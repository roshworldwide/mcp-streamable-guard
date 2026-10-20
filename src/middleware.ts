import { randomUUID } from "node:crypto";
import type { GuardInputs, GuardKey } from "./inputs.js";
import { approvalCouldHelp, decide, type PolicyResult, type ReasonMessages } from "./policy.js";

/** The shape of an MCP CallToolResult, kept local so the package has no hard SDK dependency. */
export interface ToolResult {
  [key: string]: unknown;
  content: Array<{ type: "text"; text: string }>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
}

export interface GuardContext<A = Record<string, unknown>> {
  tool: string;
  args: A;
  /** One id per request; approvals and the decision record are bound to it. */
  decision_id: string;
  /** Whatever the transport passes to tool handlers (session id, auth, ...). */
  extra?: unknown;
}

export interface Resolution {
  /** The 14 inputs, built from server-side state only. */
  inputs: GuardInputs;
  /** Optional more specific wording for a failed input, e.g. "pass revoked after 5 wrong codes". */
  messages?: ReasonMessages;
  /** Context shown to people that does not affect the decision, e.g. "voice-only request". */
  notes?: string[];
}

export interface GuardAdapter<A = Record<string, unknown>> {
  /** Build the inputs from server state. Must never read free text from `args`. */
  resolve(ctx: GuardContext<A>): Promise<Resolution> | Resolution;
  /**
   * Ask a homeowner or caregiver to approve this one request and wait for the
   * answer (or a timeout). Called only when an approval alone could allow it.
   * `resolve` is called again afterwards.
   */
  requestApproval?(ctx: GuardContext<A>, blocked: PolicyResult, resolution: Resolution): Promise<void>;
  /**
   * Atomically consume the credential that allowed the request (mark the pass
   * used, spend the approval). Return false if it was already consumed, for
   * example by a simultaneous request; the request is then blocked.
   */
  commit?(ctx: GuardContext<A>, allowed: PolicyResult): Promise<boolean> | boolean;
  /** Explanation-only extras for the dashboard (echoed outside text). Never affects the decision. */
  explain?(ctx: GuardContext<A>): Promise<{ echoed_outside_text?: string; notes?: string[] }> | { echoed_outside_text?: string; notes?: string[] };
  /** Append the decision to the audit log. */
  record?(decision: GuardDecision<A>): void | Promise<void>;
}

export interface GuardDecision<A = Record<string, unknown>> {
  decision_id: string;
  tool: string;
  args: A;
  inputs: GuardInputs;
  allow: boolean;
  path: "pass" | "owner" | null;
  reasons: string[];
  failed: GuardKey[];
  notes: string[];
  approval_requested: boolean;
  echoed_outside_text?: string;
  /** Time spent in the guard (resolve, decide, commit), excluding any wait for a human. */
  latency_ms: number;
  /** Time spent waiting for a human approver. */
  wait_ms: number;
}

export type Effect<A> = (args: A, decision: GuardDecision<A>) => Promise<Record<string, unknown> | void> | Record<string, unknown> | void;

export interface Guard<A = Record<string, unknown>> {
  /** Run the full check for one request. Use this from non-MCP callers such as a keypad. */
  check(tool: string, args: A, extra?: unknown, decisionId?: string): Promise<GuardDecision<A>>;
  /** Wrap an MCP tool handler marked physical: the effect runs only when the guard allows. */
  wrap(tool: string, effect: Effect<A>): (args: A, extra?: unknown) => Promise<ToolResult>;
}

export function createGuard<A = Record<string, unknown>>(adapter: GuardAdapter<A>): Guard<A> {
  async function check(tool: string, args: A, extra?: unknown, decisionId?: string): Promise<GuardDecision<A>> {
    const ctx: GuardContext<A> = { tool, args, decision_id: decisionId ?? "dec_" + randomUUID(), extra };
    const t0 = performance.now();
    let wait = 0;
    let approvalRequested = false;

    let res = await adapter.resolve(ctx);
    let result = decide(res.inputs, res.messages);

    if (!result.allow && adapter.requestApproval && approvalCouldHelp(res.inputs)) {
      approvalRequested = true;
      const w0 = performance.now();
      await adapter.requestApproval(ctx, result, res);
      wait += performance.now() - w0;
      res = await adapter.resolve(ctx);
      result = decide(res.inputs, res.messages);
    }

    if (result.allow && adapter.commit) {
      const committed = await adapter.commit(ctx, result);
      if (!committed) {
        // The credential was consumed between the check and the commit: treat it as used.
        const key: GuardKey = result.path === "pass" ? "pass_unused" : "owner_approved";
        const inputs = { ...res.inputs, [key]: false };
        const retry = decide(inputs, { ...res.messages, [key]: "the credential was already used by another request" });
        res = { ...res, inputs };
        result = retry.allow ? { allow: false, path: null, reasons: [{ input: key, message: "the credential was already used by another request" }] } : retry;
      }
    }

    const extras = adapter.explain ? await adapter.explain(ctx) : {};
    const latency = performance.now() - t0 - wait;

    const decision: GuardDecision<A> = {
      decision_id: ctx.decision_id,
      tool,
      args,
      inputs: res.inputs,
      allow: result.allow,
      path: result.path,
      reasons: result.reasons.map((r) => r.message),
      failed: result.reasons.map((r) => r.input),
      notes: [...(res.notes ?? []), ...(extras.notes ?? [])],
      approval_requested: approvalRequested,
      echoed_outside_text: extras.echoed_outside_text,
      latency_ms: Math.round(latency * 1000) / 1000,
      wait_ms: Math.round(wait),
    };
    await adapter.record?.(decision);
    return decision;
  }

  function wrap(tool: string, effect: Effect<A>) {
    return async (args: A, extra?: unknown): Promise<ToolResult> => {
      const d = await check(tool, args, extra);
      let effectResult: Record<string, unknown> = {};
      if (d.allow) effectResult = (await effect(args, d)) ?? {};
      const structuredContent = {
        allow: d.allow,
        verdict: d.allow ? "ALLOWED" : "BLOCKED",
        decision_id: d.decision_id,
        path: d.path,
        reasons: d.reasons,
        notes: d.notes,
        approval_requested: d.approval_requested,
        ...(d.echoed_outside_text ? { echoed_outside_text: d.echoed_outside_text } : {}),
        ...effectResult,
      };
      const text = d.allow
        ? `ALLOWED via ${d.path === "pass" ? "a signed pass" : "a fresh app approval"}. Decision ${d.decision_id}.`
        : `BLOCKED: ${d.reasons.join("; ")}. Decision ${d.decision_id}.`;
      return { content: [{ type: "text", text }], structuredContent };
    };
  }

  return { check, wrap };
}
