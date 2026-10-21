/**
 * Approvals by MCP elicitation: ask the owner's phone(s), never the agent.
 *
 * Works with any MCP server object that can send `elicitation/create` to one
 * client session (the official SDK's low-level `Server#elicitInput`). The
 * transport tells the broker when a session's server-to-client stream (GET)
 * opens and closes, so a phone that has gone away is not waited on.
 */

/** Anything that can send one elicitation request to one client session. */
export interface Elicitor {
  elicitInput(
    params: { message: string; requestedSchema: { type: "object"; properties: Record<string, { type: "boolean"; title?: string; description?: string }>; required?: string[] } },
    options?: { signal?: AbortSignal; timeout?: number },
  ): Promise<{ action: string; content?: unknown }>;
}

export interface ApproverSession<R extends string = string> {
  session_id: string;
  role: R;
  elicitor: Elicitor;
}

export interface AskResult<R extends string = string> {
  /** true = Approve/Confirm, false = Deny, null = no answer (no approver connected, dismissed, or timed out). */
  answer: boolean | null;
  role?: R;
  session_id?: string;
  at?: number;
  why?: string;
}

export interface AskOptions<R extends string = string> {
  /** Shown on the approver's phone. Build it from your own state; mark outside text as unverified. */
  message: string;
  field: string;
  title: string;
  description: string;
  timeoutMs: number;
  /** Ties the ask to a request, for a pending list. */
  ref: string;
  kind: string;
  /** Ask only these roles (default: every approver). */
  roles?: R[];
  /** Ask only this session (for example, to show a code to the person who confirmed). */
  sessionId?: string;
}

export type ApprovalEvent = Record<string, unknown> & { event: string };

/**
 * Sends elicitation requests to approver sessions. The first explicit answer
 * wins and the other phones' requests are cancelled.
 */
export class ApprovalBroker<R extends string = string> {
  private sessions = new Map<string, ApproverSession<R>>();
  /** Sessions whose server-to-client stream is open right now. */
  private live = new Set<string>();
  /**
   * Sessions whose stream dropped less than `graceMs` ago. The SDK client reconnects on its own,
   * so a blip must not cost an approval: during the grace period the phone still counts as
   * reachable, questions for it wait for the stream to come back, and questions it already
   * received stay open (its answer arrives by POST). After the grace period it is treated as gone.
   */
  private down = new Map<string, ReturnType<typeof setTimeout>>();
  /** In-flight questions per session, cancelled if the phone is gone for good. */
  private inflight = new Map<string, Set<AbortController>>();
  /** Questions waiting for a reconnecting phone's stream. */
  private waiting = new Map<string, Set<() => void>>();
  pending = new Map<string, { ref: string; kind: string; message: string; since: number }>();

  constructor(
    private clock: { now(): number },
    private onEvent?: (e: ApprovalEvent) => void,
    private graceMs = 5000,
  ) {}

  register(s: ApproverSession<R>): void {
    this.sessions.set(s.session_id, s);
    this.onEvent?.({ event: "approver_connected", role: s.role, count: this.sessions.size });
  }

  /** The session itself ended: the phone is gone at once. */
  unregister(sessionId: string): void {
    this.gone(sessionId);
    if (this.sessions.delete(sessionId)) this.onEvent?.({ event: "approver_disconnected", count: this.sessions.size });
  }

  /** The phone's server-to-client stream is open: deliver anything that was waiting for it. */
  streamOpened(sessionId: string): void {
    this.live.add(sessionId);
    const t = this.down.get(sessionId);
    if (t) clearTimeout(t);
    this.down.delete(sessionId);
    for (const send of [...(this.waiting.get(sessionId) ?? [])]) send();
  }

  /** The stream closed. Give the phone `graceMs` to reconnect before treating it as gone. */
  streamClosed(sessionId: string): void {
    this.live.delete(sessionId);
    if (!this.sessions.has(sessionId) || this.down.has(sessionId)) return;
    const t = setTimeout(() => {
      this.down.delete(sessionId);
      if (!this.live.has(sessionId)) this.gone(sessionId);
    }, this.graceMs);
    (t as { unref?: () => void }).unref?.();
    this.down.set(sessionId, t);
  }

  private gone(sessionId: string): void {
    const t = this.down.get(sessionId);
    if (t) clearTimeout(t);
    this.down.delete(sessionId);
    this.live.delete(sessionId);
    for (const c of this.inflight.get(sessionId) ?? []) c.abort("approver went away");
    this.inflight.delete(sessionId);
    this.waiting.delete(sessionId);
  }

  /** Approvers that can be reached: registered with elicitation, with an open stream or one reconnecting. */
  connected(): ApproverSession<R>[] {
    return [...this.sessions.values()].filter((s) => this.live.has(s.session_id) || this.down.has(s.session_id));
  }

  async ask(opts: AskOptions<R>): Promise<AskResult<R>> {
    const targets = this.connected().filter(
      (s) => (!opts.roles || opts.roles.includes(s.role)) && (!opts.sessionId || s.session_id === opts.sessionId),
    );
    if (targets.length === 0) return { answer: null, why: "no approver connected" };

    const requestedSchema = {
      type: "object" as const,
      properties: { [opts.field]: { type: "boolean" as const, title: opts.title, description: opts.description } },
      required: [opts.field],
    };
    const controllers = targets.map(() => new AbortController());
    this.pending.set(opts.ref, { ref: opts.ref, kind: opts.kind, message: opts.message, since: this.clock.now() });
    this.onEvent?.({ event: "asked", ref: opts.ref, kind: opts.kind, message: opts.message, roles: targets.map((t) => t.role) });

    const result = await new Promise<AskResult<R>>((resolve) => {
      let open = targets.length;
      let done = false;
      const finish = (r: AskResult<R>) => {
        if (done) return;
        done = true;
        controllers.forEach((c) => c.abort("answered on another device"));
        resolve(r);
      };
      const settleOne = (why: string) => {
        open -= 1;
        if (open === 0) finish({ answer: null, why });
      };
      targets.forEach((t, i) => {
        const ctl = controllers[i];
        const sid = t.session_id;
        const set = this.inflight.get(sid) ?? new Set<AbortController>();
        set.add(ctl);
        this.inflight.set(sid, set);
        let sent = false;
        const send = () => {
          if (sent || ctl.signal.aborted) return;
          sent = true;
          this.waiting.get(sid)?.delete(send);
          let p: Promise<{ action: string; content?: unknown }>;
          try {
            p = t.elicitor.elicitInput({ message: opts.message, requestedSchema }, { signal: ctl.signal, timeout: opts.timeoutMs });
          } catch (err) {
            p = Promise.reject(err);
          }
          p.then((res) => {
            const v = res.action === "accept" ? (res.content as Record<string, unknown> | undefined)?.[opts.field] : undefined;
            if (typeof v === "boolean") finish({ answer: v, role: t.role, session_id: sid, at: this.clock.now() });
            else settleOne(res.action === "decline" ? "declined" : "dismissed");
          })
            .catch((err: unknown) => settleOne(err instanceof Error && /timed out|timeout/i.test(err.message) ? "timed out" : "no answer"))
            .finally(() => this.inflight.get(sid)?.delete(ctl));
        };
        ctl.signal.addEventListener(
          "abort",
          () => {
            // Never sent (the phone did not come back in time, or someone else answered): settle without asking.
            if (sent) return;
            sent = true;
            this.waiting.get(sid)?.delete(send);
            this.inflight.get(sid)?.delete(ctl);
            settleOne("phone not reachable");
          },
          { once: true },
        );
        if (this.live.has(sid)) send();
        else {
          const w = this.waiting.get(sid) ?? new Set<() => void>();
          w.add(send);
          this.waiting.set(sid, w);
        }
      });
    });

    this.pending.delete(opts.ref);
    this.onEvent?.({ event: "answered", ref: opts.ref, kind: opts.kind, answer: result.answer, role: result.role ?? null, why: result.why ?? null });
    return result;
  }
}
