import type { GuardInputs } from "./inputs.js";

/**
 * The guard's rule as one plain formula. Written separately from policy.ts on
 * purpose: the exhaustive test checks that the implementation and this
 * formula agree on all 16,384 input combinations.
 *
 *   passPath  = pass_present AND pass_signature_valid AND pass_in_window AND pass_unused
 *               AND pass_for_this_door AND code_matches
 *               AND (NOT night_mode OR pass_allows_night)
 *   ownerPath = owner_approved AND approval_fresh AND approver_is_owner_role
 *   allow     = rate_ok AND NOT away_lockdown AND visitor_at_door AND (passPath OR ownerPath)
 */
export function spec(x: GuardInputs): boolean {
  const passPath =
    x.pass_present &&
    x.pass_signature_valid &&
    x.pass_in_window &&
    x.pass_unused &&
    x.pass_for_this_door &&
    x.code_matches &&
    (!x.night_mode || x.pass_allows_night);
  const ownerPath = x.owner_approved && x.approval_fresh && x.approver_is_owner_role;
  return x.rate_ok && !x.away_lockdown && x.visitor_at_door && (passPath || ownerPath);
}
