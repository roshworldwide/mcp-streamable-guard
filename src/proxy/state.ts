import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { chainHash, GENESIS_HASH, verifyChain, type ChainedRecord } from "../audit.js";
import { codeMatches, exportKeys, generateSigningKeys, hashCode, importKeys, newCode, newPassId, passInWindow, signObject, verifyObject, type SigningKeys } from "../passes.js";

export type ProxyRole = "agent" | "homeowner" | "caregiver";

/** A one-time pass for one door. Same shape as HomePulse's, except the door is any name the policy uses. */
export interface ProxyPassBody {
  pass_id: string;
  door: string;
  who: string;
  not_before: string;
  not_after: string;
  max_uses: 1;
  code_hash: string;
  allow_at_night: boolean;
  issued_by: "homeowner" | "caregiver";
  confirmed_via: "app";
  issued_at: string;
}
export interface ProxyPass extends ProxyPassBody {
  sig: string;
}

interface PassRow {
  pass: ProxyPass;
  uses: number;
  wrong: number;
  revoked: string | null;
}

export interface AuditRecord extends ChainedRecord {
  at: string;
  type: string;
}

/**
 * Everything the proxy's guard reads, kept by the proxy itself: passes,
 * approvals, lockdown, doorbell presence, request counts and a hash-chained
 * audit log. In memory, and in `dir` when one is given (keys, secrets,
 * passes and the audit log survive a restart).
 */
export class ProxyState {
  readonly keys: SigningKeys;
  readonly codeSecret: string;
  private passes = new Map<string, PassRow>();
  readonly approvals = new Map<string, { approved: boolean; role: string; at: number }>();
  lockdown = false;
  private presence: number[] = [];
  private calls = new Map<string, number[]>();
  readonly audit: AuditRecord[] = [];

  constructor(
    private clock: { now(): number },
    private dir: string | null = null,
  ) {
    if (dir) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const keyFile = dir ? path.join(dir, "keys.json") : null;
    if (keyFile && fs.existsSync(keyFile)) {
      const k = JSON.parse(fs.readFileSync(keyFile, "utf8")) as { privateKeyPem: string; publicKeyPem: string; codeSecret: string };
      this.keys = importKeys(k);
      this.codeSecret = k.codeSecret;
    } else {
      this.keys = generateSigningKeys();
      this.codeSecret = randomBytes(32).toString("hex");
      if (keyFile) fs.writeFileSync(keyFile, JSON.stringify({ ...exportKeys(this.keys), codeSecret: this.codeSecret }), { mode: 0o600 });
    }
    if (dir) {
      const pf = path.join(dir, "passes.json");
      if (fs.existsSync(pf)) for (const r of JSON.parse(fs.readFileSync(pf, "utf8")) as PassRow[]) this.passes.set(r.pass.pass_id, r);
      const af = path.join(dir, "audit.jsonl");
      if (fs.existsSync(af)) {
        for (const line of fs.readFileSync(af, "utf8").split("\n")) if (line.trim()) this.audit.push(JSON.parse(line) as AuditRecord);
      }
      const st = path.join(dir, "home.json");
      if (fs.existsSync(st)) this.lockdown = (JSON.parse(fs.readFileSync(st, "utf8")) as { lockdown?: boolean }).lockdown === true;
    }
  }

  private save(): void {
    if (!this.dir) return;
    fs.writeFileSync(path.join(this.dir, "passes.json"), JSON.stringify([...this.passes.values()]), { mode: 0o600 });
    fs.writeFileSync(path.join(this.dir, "home.json"), JSON.stringify({ lockdown: this.lockdown }), { mode: 0o600 });
  }

  // ---- passes ----

  /** Sign a pass after an approver asked for it in their app. Returns the code, which is never stored. */
  issuePass(p: { door: string; who: string; not_before: string; not_after: string; allow_at_night: boolean; issued_by: "homeowner" | "caregiver" }): { pass: ProxyPass; code: string } {
    const code = newCode();
    const body: ProxyPassBody = {
      pass_id: newPassId(),
      door: p.door,
      who: p.who,
      not_before: p.not_before,
      not_after: p.not_after,
      max_uses: 1,
      code_hash: hashCode(code, this.codeSecret),
      allow_at_night: p.allow_at_night,
      issued_by: p.issued_by,
      confirmed_via: "app",
      issued_at: new Date(this.clock.now()).toISOString(),
    };
    const pass: ProxyPass = { ...body, sig: signObject(body, this.keys.privateKey) };
    this.passes.set(pass.pass_id, { pass, uses: 0, wrong: 0, revoked: null });
    this.save();
    return { pass, code };
  }

  getPass(passId: string): PassRow | undefined {
    return this.passes.get(passId);
  }

  verify(pass: ProxyPass): boolean {
    if (typeof pass?.sig !== "string") return false;
    const { sig, ...body } = pass;
    return verifyObject(body, sig, this.keys.publicKey);
  }

  /** Code-only lookup, like a keypad: the active pass for this door whose code matches. */
  findByCode(door: string, code: string | undefined): PassRow | undefined {
    if (!code) return undefined;
    const now = this.clock.now();
    return [...this.passes.values()].find(
      (r) => r.pass.door === door && !r.revoked && r.uses < r.pass.max_uses && passInWindow(r.pass, now) && codeMatches(code, r.pass.code_hash, this.codeSecret),
    );
  }

  codeMatches(row: PassRow, code: string | undefined): boolean {
    return codeMatches(code, row.pass.code_hash, this.codeSecret);
  }

  /** Mark a pass used. Synchronous check-and-set, so two simultaneous requests cannot both use it. */
  consume(passId: string): boolean {
    const r = this.passes.get(passId);
    if (!r || r.revoked || r.uses >= r.pass.max_uses) return false;
    r.uses += 1;
    this.save();
    return true;
  }

  /** Count a wrong code; revoke the pass at `max`. Returns true when this call revoked it. */
  wrongCode(passId: string, max: number): boolean {
    const r = this.passes.get(passId);
    if (!r || r.revoked) return false;
    r.wrong += 1;
    if (r.wrong >= max) r.revoked = `revoked after ${max} wrong codes`;
    this.save();
    return r.revoked !== null;
  }

  activePasses(): PassRow[] {
    const now = this.clock.now();
    return [...this.passes.values()].filter((r) => !r.revoked && r.uses < r.pass.max_uses && Date.parse(r.pass.not_after) >= now);
  }

  setLockdown(on: boolean): void {
    this.lockdown = on;
    this.save();
  }

  // ---- presence and rate ----

  notePresence(at: number): void {
    this.presence.push(at);
    if (this.presence.length > 100) this.presence.shift();
  }

  someoneAtDoor(withinMs: number): boolean {
    const now = this.clock.now();
    return this.presence.some((t) => t <= now && now - t <= withinMs);
  }

  /** Record one physical request from `bucket`; returns how many came before it inside the window. */
  noteCall(bucket: string, windowMs: number): number {
    const now = this.clock.now();
    const list = (this.calls.get(bucket) ?? []).filter((t) => now - t < windowMs);
    const before = list.length;
    list.push(now);
    this.calls.set(bucket, list.slice(-1000));
    return before;
  }

  // ---- audit ----

  record(type: string, data: Record<string, unknown>): AuditRecord {
    const prev = this.audit.at(-1)?.hash ?? GENESIS_HASH;
    // The record's own id, time and type always win over fields in `data`.
    const body = { ...data, id: (this.audit.at(-1)?.id ?? 0) + 1, at: new Date(this.clock.now()).toISOString(), type };
    const rec = { ...body, prev_hash: prev, hash: chainHash(prev, body) } as AuditRecord;
    this.audit.push(rec);
    if (this.dir) fs.appendFileSync(path.join(this.dir, "audit.jsonl"), JSON.stringify(rec) + "\n", { mode: 0o600 });
    return rec;
  }

  verifyAudit() {
    return verifyChain(this.audit);
  }
}
