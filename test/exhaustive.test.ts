import { describe, expect, test } from "vitest";
import { GUARD_KEYS, inputFailed, inputsFromMask, type GuardInputs } from "../src/inputs.js";
import { decide } from "../src/policy.js";
import { spec } from "../src/spec.js";

const TOTAL = 1 << GUARD_KEYS.length;

describe("Axiom guard: every one of the 16,384 input combinations", () => {
  test("policy matches spec and all seven properties hold", () => {
    expect(TOTAL).toBe(16384);
    let allowed = 0;
    for (let m = 0; m < TOTAL; m++) {
      const x: GuardInputs = inputsFromMask(m);
      const d = decide(x);
      const passPath =
        x.pass_present && x.pass_signature_valid && x.pass_in_window && x.pass_unused &&
        x.pass_for_this_door && x.code_matches && (!x.night_mode || x.pass_allows_night);
      const ownerPath = x.owner_approved && x.approval_fresh && x.approver_is_owner_role;

      // 1. The implementation's answer equals the formula's answer.
      expect(d.allow).toBe(spec(x));
      // 2. Allow implies a credential.
      if (d.allow) expect(passPath || ownerPath).toBe(true);
      // 3. Lockdown wins.
      if (x.away_lockdown) expect(d.allow).toBe(false);
      // 4. No empty doorway.
      if (!x.visitor_at_door) expect(d.allow).toBe(false);
      // 5. Rate limit.
      if (!x.rate_ok) expect(d.allow).toBe(false);
      // 6. Night: night mode, a pass without allow_at_night, and no owner approval means block.
      if (x.night_mode && !x.pass_allows_night && !ownerPath) expect(d.allow).toBe(false);
      // 7. Every block lists at least one reason, and each reason names an input that failed.
      if (!d.allow) {
        expect(d.reasons.length).toBeGreaterThan(0);
        for (const r of d.reasons) expect(inputFailed(x, r.input)).toBe(true);
      } else {
        expect(d.reasons).toEqual([]);
        expect(d.path === "pass" ? passPath : ownerPath).toBe(true);
      }
      if (d.allow) allowed++;
    }
    console.log(`allowed ${allowed} of ${TOTAL}`); // quote this exact number in the README
    // Derivation: gates fix 3 inputs (1 of 8 settings). Of the other 2,048 settings,
    // passPath holds in 1*3*8 = 24, ownerPath in 1*64*4 = 256, both in 3: 24 + 256 - 3 = 277.
    expect(allowed).toBe(277);
  });

  test("a voice request alone satisfies neither path", () => {
    // Speaking sets no input: with no pass and no approval, every other setting still blocks.
    for (let m = 0; m < TOTAL; m++) {
      const x = inputsFromMask(m);
      if (x.pass_present || x.owner_approved) continue;
      expect(decide(x).allow).toBe(false);
    }
  });

  test("the blocked paramedic case reads sensibly", () => {
    const x = inputsFromMask(0);
    Object.assign(x, { visitor_at_door: true, rate_ok: true, night_mode: true });
    const d = decide(x);
    expect(d.allow).toBe(false);
    expect(d.reasons.map((r) => r.message)).toEqual([
      "no valid pass",
      "no approval from the homeowner or caregiver",
    ]);
  });
});
