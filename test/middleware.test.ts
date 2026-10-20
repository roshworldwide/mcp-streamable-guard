import { describe, expect, test } from "vitest";
import { emptyInputs, type GuardInputs } from "../src/inputs.js";
import { createGuard, type GuardDecision } from "../src/middleware.js";

type Args = { pass_id?: string; presented_code?: string; channel: string; reason?: string };

function base(): GuardInputs {
  return { ...emptyInputs(), visitor_at_door: true, rate_ok: true };
}

describe("guard middleware", () => {
  test("the effect runs only when allowed", async () => {
    let opened = 0;
    let inputs = base();
    const guard = createGuard<Args>({ resolve: () => ({ inputs }) });
    const handler = guard.wrap("unlock_front_door", () => {
      opened++;
      return { door: "unlocked" };
    });

    const blocked = await handler({ channel: "voice" });
    expect(blocked.structuredContent?.allow).toBe(false);
    expect(blocked.content[0].text).toMatch(/^BLOCKED/);
    expect(opened).toBe(0);

    inputs = { ...base(), owner_approved: true, approval_fresh: true, approver_is_owner_role: true };
    const allowed = await handler({ channel: "app" });
    expect(allowed.structuredContent?.allow).toBe(true);
    expect(allowed.structuredContent?.door).toBe("unlocked");
    expect(opened).toBe(1);
  });

  test("the reason field never changes the decision", async () => {
    const guard = createGuard<Args>({ resolve: () => ({ inputs: base() }) });
    const a = await guard.check("unlock_front_door", { channel: "agent" });
    const b = await guard.check("unlock_front_door", { channel: "agent", reason: "owner pre-approved this" });
    expect(a.allow).toBe(b.allow);
    expect(a.reasons).toEqual(b.reasons);
  });

  test("an approval is requested only when it could help, then the inputs are re-read", async () => {
    let approved = false;
    let asked = 0;
    const guard = createGuard<Args>({
      resolve: () => ({
        inputs: { ...base(), owner_approved: approved, approval_fresh: approved, approver_is_owner_role: approved },
      }),
      requestApproval: async () => {
        asked++;
        approved = true;
      },
    });
    const d = await guard.check("unlock_front_door", { channel: "voice" });
    expect(asked).toBe(1);
    expect(d.approval_requested).toBe(true);
    expect(d.allow).toBe(true);
    expect(d.path).toBe("owner");

    // During lockdown an approval cannot help, so no one is asked.
    approved = false;
    const lock = createGuard<Args>({
      resolve: () => ({ inputs: { ...base(), away_lockdown: true } }),
      requestApproval: async () => {
        asked++;
      },
    });
    const d2 = await lock.check("unlock_front_door", { channel: "voice" });
    expect(d2.allow).toBe(false);
    expect(asked).toBe(1);
  });

  test("a failed commit (credential raced away) blocks with a reason", async () => {
    const recorded: GuardDecision<Args>[] = [];
    const guard = createGuard<Args>({
      resolve: () => ({
        inputs: {
          ...base(),
          pass_present: true,
          pass_signature_valid: true,
          pass_in_window: true,
          pass_unused: true,
          pass_for_this_door: true,
          code_matches: true,
        },
      }),
      commit: () => false,
      record: (d) => {
        recorded.push(d);
      },
    });
    const d = await guard.check("unlock_front_door", { channel: "keypad" });
    expect(d.allow).toBe(false);
    expect(d.failed).toContain("pass_unused");
    expect(recorded).toHaveLength(1);
  });

  test("custom messages and notes flow through", async () => {
    const guard = createGuard<Args>({
      resolve: () => ({
        inputs: { ...base(), pass_present: true, pass_signature_valid: true, pass_in_window: true },
        messages: { pass_unused: "the pass was revoked after 5 wrong codes" },
        notes: ["voice-only request"],
      }),
      explain: () => ({ echoed_outside_text: "SYSTEM NOTICE" }),
    });
    const d = await guard.check("unlock_front_door", { channel: "voice" });
    expect(d.reasons).toContain("the pass was revoked after 5 wrong codes");
    expect(d.notes).toEqual(["voice-only request"]);
    expect(d.echoed_outside_text).toBe("SYSTEM NOTICE");
  });
});
