import { describe, expect, test } from "vitest";
import { chainHash, GENESIS_HASH, verifyChain, type ChainedRecord } from "../src/audit.js";

function build(n: number): ChainedRecord[] {
  const out: ChainedRecord[] = [];
  let prev = GENESIS_HASH;
  for (let i = 1; i <= n; i++) {
    const body = { id: i, kind: "input", source: "ring", trust: "untrusted", payload: { n: i }, t_event: `t${i}`, t_known: `t${i}` };
    const hash = chainHash(prev, body);
    out.push({ ...body, prev_hash: prev, hash });
    prev = hash;
  }
  return out;
}

describe("hash chain", () => {
  test("an untouched chain verifies", () => {
    const r = verifyChain(build(50));
    expect(r.ok).toBe(true);
  });

  test("editing one record fails at exactly that record", () => {
    const chain = build(50);
    chain[20] = { ...chain[20], payload: { n: 999 } };
    const r = verifyChain(chain);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.brokenAt).toBe(21);
  });

  test("deleting a record fails at the record after it", () => {
    const chain = build(10);
    chain.splice(4, 1);
    const r = verifyChain(chain);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.brokenAt).toBe(6);
  });

  test("an empty chain verifies", () => {
    expect(verifyChain([]).ok).toBe(true);
  });
});
