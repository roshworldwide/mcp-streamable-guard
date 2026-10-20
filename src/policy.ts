import type { GuardInputs, GuardKey } from "./inputs.js";

export interface Reason {
  /** The input that failed. Every reason names one. */
  input: GuardKey;
  message: string;
}

export interface PolicyResult {
  allow: boolean;
  /** Which credential path allowed the request, when it was allowed. */
  path: "pass" | "owner" | null;
  /** Empty when allowed; at least one entry when blocked. */
  reasons: Reason[];
}

export type ReasonMessages = Partial<Record<GuardKey, string>>;

export const DEFAULT_MESSAGES: Record<GuardKey, string> = {
  pass_present: "no valid pass",
  pass_signature_valid: "the pass signature does not verify",
  pass_in_window: "the pass is outside its time window",
  pass_unused: "the pass has already been used",
  pass_for_this_door: "the pass is for a different door",
  code_matches: "the code does not match",
  owner_approved: "no approval from the homeowner or caregiver",
  approval_fresh: "the approval is more than 60 seconds old",
  approver_is_owner_role: "the approval did not come from a homeowner or caregiver",
  night_mode: "night mode is on and this pass is not valid at night",
  away_lockdown: "the home is in lockdown",
  visitor_at_door: "no one has been seen at the door in the last 2 minutes",
  rate_ok: "too many door requests in the last 10 minutes",
  pass_allows_night: "night mode is on and this pass is not valid at night",
};

const PASS_CHAIN: GuardKey[] = [
  "pass_present",
  "pass_signature_valid",
  "pass_in_window",
  "pass_unused",
  "pass_for_this_door",
  "code_matches",
];
const OWNER_CHAIN: GuardKey[] = ["owner_approved", "approval_fresh", "approver_is_owner_role"];

/**
 * The guard. A pure function from 14 booleans to allow/block with reasons.
 * Browser-safe, so the console's what-if panel runs this exact code.
 *
 * Implemented as checks with reasons rather than as the formula in spec.ts,
 * so the exhaustive test compares two independent writings of the rule.
 */
export function decide(x: GuardInputs, messages: ReasonMessages = {}): PolicyResult {
  const say = (k: GuardKey): Reason => ({ input: k, message: messages[k] ?? DEFAULT_MESSAGES[k] });
  const reasons: Reason[] = [];

  // Gates that no credential can override.
  if (!x.rate_ok) reasons.push(say("rate_ok"));
  if (x.away_lockdown) reasons.push(say("away_lockdown"));
  if (!x.visitor_at_door) reasons.push(say("visitor_at_door"));

  // Credential path 1: a signed one-time pass and its code.
  let passFailure: Reason | null = null;
  for (const k of PASS_CHAIN) {
    if (!x[k]) {
      passFailure = say(k);
      break;
    }
  }
  if (passFailure === null && x.night_mode && !x.pass_allows_night) passFailure = say("night_mode");

  // Credential path 2: a fresh tap from a homeowner or caregiver session.
  let ownerFailure: Reason | null = null;
  for (const k of OWNER_CHAIN) {
    if (!x[k]) {
      ownerFailure = say(k);
      break;
    }
  }

  const passPath = passFailure === null;
  const ownerPath = ownerFailure === null;
  const credential = passPath || ownerPath;

  if (!credential) {
    reasons.push(passFailure as Reason, ownerFailure as Reason);
  }

  if (reasons.length > 0) return { allow: false, path: null, reasons };
  return { allow: true, path: passPath ? "pass" : "owner", reasons: [] };
}

/** True when an owner approval alone would turn this block into an allow. */
export function approvalCouldHelp(x: GuardInputs): boolean {
  return x.rate_ok && !x.away_lockdown && x.visitor_at_door;
}
