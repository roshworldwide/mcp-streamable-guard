import { createHash } from "node:crypto";
import { canonicalJson } from "./canonical.js";

/** The first record's prev_hash. */
export const GENESIS_HASH = "0".repeat(64);

export interface ChainedRecord {
  id: number;
  prev_hash: string;
  hash: string;
  [field: string]: unknown;
}

/** The part of a record that its hash covers: every field except prev_hash and hash. */
export function recordBody(r: ChainedRecord): Record<string, unknown> {
  const { prev_hash: _p, hash: _h, ...body } = r;
  return body;
}

/** sha256(prev_hash + canonical record). Editing any record breaks the link to the next one. */
export function chainHash(prevHash: string, body: object): string {
  return createHash("sha256").update(prevHash + canonicalJson(body), "utf8").digest("hex");
}

export type ChainCheck =
  | { ok: true; count: number; head: string }
  | { ok: false; count: number; brokenAt: number; index: number; why: string };

/** Walk the chain in id order and report the first broken link. */
export function verifyChain(records: ChainedRecord[]): ChainCheck {
  let prev = GENESIS_HASH;
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    if (r.prev_hash !== prev) {
      return { ok: false, count: records.length, brokenAt: r.id, index: i, why: "prev_hash does not match the previous record's hash" };
    }
    const expected = chainHash(r.prev_hash, recordBody(r));
    if (expected !== r.hash) {
      return { ok: false, count: records.length, brokenAt: r.id, index: i, why: "record contents do not match its hash" };
    }
    prev = r.hash;
  }
  return { ok: true, count: records.length, head: prev };
}
