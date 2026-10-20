import fc from "fast-check";
import { describe, expect, test } from "vitest";
import {
  codeMatches,
  generateSigningKeys,
  hashCode,
  newCode,
  newPassId,
  passInWindow,
  signPass,
  verifyPass,
  type PassBody,
  type VisitPass,
} from "../src/passes.js";

const keys = generateSigningKeys();
const SECRET = "a".repeat(64);

function body(overrides: Partial<PassBody> = {}): PassBody {
  return {
    pass_id: newPassId(),
    door: "front",
    who: "Nurse Sarah",
    purpose: "insulin delivery",
    not_before: "2026-10-22T14:00:00-07:00",
    not_after: "2026-10-22T15:00:00-07:00",
    max_uses: 1,
    code_hash: hashCode("482913", SECRET),
    allow_at_night: false,
    issued_by: "homeowner",
    confirmed_via: "app",
    issued_at: "2026-10-22T13:40:00-07:00",
    ...overrides,
  };
}

describe("signed passes", () => {
  test("a freshly signed pass verifies", () => {
    expect(verifyPass(signPass(body(), keys.privateKey), keys.publicKey)).toBe(true);
  });

  test("a pass signed by another key does not verify", () => {
    const other = generateSigningKeys();
    expect(verifyPass(signPass(body(), other.privateKey), keys.publicKey)).toBe(false);
  });

  test("property: changing any field of a signed pass always fails verification", () => {
    const pass = signPass(body(), keys.privateKey);
    const fields = Object.keys(pass).filter((k) => k !== "sig") as (keyof VisitPass)[];
    fc.assert(
      fc.property(
        fc.constantFrom(...fields),
        fc.oneof(fc.string(), fc.integer(), fc.boolean(), fc.constant(null)),
        (field, value) => {
          fc.pre(JSON.stringify(pass[field]) !== JSON.stringify(value));
          const tampered = { ...pass, [field]: value } as VisitPass;
          return verifyPass(tampered, keys.publicKey) === false;
        },
      ),
      { numRuns: 2000 },
    );
  });

  test("property: adding a field or changing the signature fails verification", () => {
    const pass = signPass(body(), keys.privateKey);
    fc.assert(
      fc.property(fc.string({ minLength: 1 }), fc.string(), (k, v) => {
        fc.pre(!(k in pass));
        return verifyPass({ ...pass, [k]: v } as VisitPass, keys.publicKey) === false;
      }),
      { numRuns: 500 },
    );
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 64, maxLength: 64 }), (bytes) => {
        const sig = Buffer.from(bytes).toString("base64url");
        fc.pre(sig !== pass.sig);
        return verifyPass({ ...pass, sig }, keys.publicKey) === false;
      }),
      { numRuns: 500 },
    );
  });
});

describe("codes", () => {
  test("codes are six digits", () => {
    for (let i = 0; i < 1000; i++) expect(newCode()).toMatch(/^\d{6}$/);
  });

  test("only the exact code matches its HMAC", () => {
    const h = hashCode("482913", SECRET);
    expect(codeMatches("482913", h, SECRET)).toBe(true);
    expect(codeMatches("482914", h, SECRET)).toBe(false);
    expect(codeMatches("48291", h, SECRET)).toBe(false);
    expect(codeMatches(" 482913", h, SECRET)).toBe(false);
    expect(codeMatches(undefined, h, SECRET)).toBe(false);
    expect(codeMatches("482913", h, "b".repeat(64))).toBe(false);
  });

  test("property: no other six-digit code matches", () => {
    const h = hashCode("000042", SECRET);
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 999_999 }), (n) => {
        const c = String(n).padStart(6, "0");
        return codeMatches(c, h, SECRET) === (c === "000042");
      }),
      { numRuns: 5000 },
    );
  });

  test("pass ids carry 64 bits of randomness", () => {
    expect(newPassId()).toMatch(/^pass_[0-9a-f]{16}$/);
  });
});

describe("time windows", () => {
  const p = body();
  test("inside, before, after and at the edges", () => {
    expect(passInWindow(p, Date.parse("2026-10-22T14:14:00-07:00"))).toBe(true);
    expect(passInWindow(p, Date.parse("2026-10-22T13:59:59-07:00"))).toBe(false);
    expect(passInWindow(p, Date.parse("2026-10-22T15:00:01-07:00"))).toBe(false);
    expect(passInWindow(p, Date.parse("2026-10-22T14:00:00-07:00"))).toBe(true);
    expect(passInWindow(p, Date.parse("2026-10-22T15:00:00-07:00"))).toBe(true);
  });
  test("an unparseable window is never valid", () => {
    expect(passInWindow({ not_before: "soon", not_after: "later" }, Date.now())).toBe(false);
  });
});
