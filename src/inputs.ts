/**
 * The 14 yes/no inputs the guard decides on. Every one is read from
 * server-side state (passes table, approvals, clock, home mode, the event
 * log) and never from what an agent says. Browser-safe: no Node imports.
 */
export const GUARD_KEYS = [
  "pass_present",
  "pass_signature_valid",
  "pass_in_window",
  "pass_unused",
  "pass_for_this_door",
  "code_matches",
  "owner_approved",
  "approval_fresh",
  "approver_is_owner_role",
  "night_mode",
  "away_lockdown",
  "visitor_at_door",
  "rate_ok",
  "pass_allows_night",
] as const;

export type GuardKey = (typeof GUARD_KEYS)[number];
export type GuardInputs = Record<GuardKey, boolean>;

/** Short descriptions shown next to each switch in the "Why?" panel. */
export const GUARD_INPUT_LABELS: Record<GuardKey, string> = {
  pass_present: "The request names a pass that exists",
  pass_signature_valid: "The pass signature verifies",
  pass_in_window: "Now is inside the pass's time window",
  pass_unused: "The pass has not been used or revoked",
  pass_for_this_door: "The pass is for this door",
  code_matches: "The presented code matches the pass",
  owner_approved: "A homeowner or caregiver tapped Approve",
  approval_fresh: "That approval is under 60 seconds old",
  approver_is_owner_role: "The approval came from a homeowner or caregiver session",
  night_mode: "The home is in night mode",
  away_lockdown: "The home is in lockdown",
  visitor_at_door: "Someone was seen at the door in the last 120 seconds",
  rate_ok: "Fewer than 5 door requests on this channel in 10 minutes",
  pass_allows_night: "The pass was issued as valid at night",
};

/** An all-false input set: the safe default every resolver starts from. */
export function emptyInputs(): GuardInputs {
  return Object.fromEntries(GUARD_KEYS.map((k) => [k, false])) as GuardInputs;
}

/** Decode a 14-bit mask into inputs (bit i = GUARD_KEYS[i]). Used by the exhaustive test and the what-if panel. */
export function inputsFromMask(mask: number): GuardInputs {
  return Object.fromEntries(GUARD_KEYS.map((k, i) => [k, Boolean(mask & (1 << i))])) as GuardInputs;
}

/**
 * True when input `k` holds the value that works against an unlock in `x`.
 * Every reason the policy gives must name an input for which this is true.
 */
export function inputFailed(x: GuardInputs, k: GuardKey): boolean {
  switch (k) {
    case "away_lockdown":
      return x.away_lockdown;
    case "night_mode":
      return x.night_mode && !x.pass_allows_night;
    case "pass_allows_night":
      return x.night_mode && !x.pass_allows_night;
    default:
      return !x[k];
  }
}
