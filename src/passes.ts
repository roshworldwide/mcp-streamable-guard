import {
  createHmac,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  randomInt,
  sign,
  timingSafeEqual,
  verify,
  type KeyObject,
} from "node:crypto";
import { canonicalJson } from "./canonical.js";

export type Door = "front" | "parcel_box";
export const DOORS: readonly Door[] = ["front", "parcel_box"] as const;

/** Everything in a pass except its signature. The signature covers every field here. */
export interface PassBody {
  pass_id: string;
  door: Door;
  /** Shown to people only, never used to decide. */
  who: string;
  /** Shown to people only, never used to decide. */
  purpose?: string;
  /** ISO 8601 with offset. */
  not_before: string;
  not_after: string;
  max_uses: 1;
  /** HMAC-SHA256(code, server secret), hex. The code itself goes only to the approver and then the visitor. */
  code_hash: string;
  allow_at_night: boolean;
  issued_by: "homeowner" | "caregiver";
  /** A pass is only ever signed after a tap in the app, never from voice alone. */
  confirmed_via: "app";
  issued_at: string;
}

export interface VisitPass extends PassBody {
  /** Ed25519 over canonical JSON of every other field, base64url. */
  sig: string;
}

export interface SigningKeys {
  privateKey: KeyObject;
  publicKey: KeyObject;
}

export function generateSigningKeys(): SigningKeys {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { privateKey, publicKey };
}

export function exportKeys(keys: SigningKeys): { privateKeyPem: string; publicKeyPem: string } {
  return {
    privateKeyPem: keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: keys.publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

export function importKeys(pem: { privateKeyPem: string; publicKeyPem: string }): SigningKeys {
  return { privateKey: createPrivateKey(pem.privateKeyPem), publicKey: createPublicKey(pem.publicKeyPem) };
}

/** Sign any JSON object: Ed25519 over its canonical JSON. */
export function signObject(body: object, privateKey: KeyObject): string {
  return sign(null, Buffer.from(canonicalJson(body), "utf8"), privateKey).toString("base64url");
}

export function verifyObject(body: object, sig: string, publicKey: KeyObject): boolean {
  try {
    return verify(null, Buffer.from(canonicalJson(body), "utf8"), publicKey, Buffer.from(sig, "base64url"));
  } catch {
    return false;
  }
}

export function signPass(body: PassBody, privateKey: KeyObject): VisitPass {
  return { ...body, sig: signObject(body, privateKey) };
}

export function verifyPass(pass: VisitPass, publicKey: KeyObject): boolean {
  if (typeof pass?.sig !== "string") return false;
  const { sig, ...body } = pass;
  return verifyObject(body, sig, publicKey);
}

/** 64 bits of randomness, so a pass id cannot be guessed and targeted. */
export function newPassId(): string {
  return "pass_" + randomBytes(8).toString("hex");
}

/** Six random digits from a CSPRNG. Shown once, then only its HMAC is kept. */
export function newCode(): string {
  return String(randomInt(0, 1_000_000)).padStart(6, "0");
}

export function hashCode(code: string, secret: string | Buffer): string {
  return createHmac("sha256", secret).update(code, "utf8").digest("hex");
}

/** Constant-time comparison of HMAC(presented) with the stored hash. */
export function codeMatches(presented: string | undefined | null, codeHash: string, secret: string | Buffer): boolean {
  if (typeof presented !== "string" || !/^\d{6}$/.test(presented)) return false;
  const a = Buffer.from(hashCode(presented, secret), "hex");
  const b = Buffer.from(codeHash, "hex");
  if (a.length !== b.length || a.length === 0) return false;
  return timingSafeEqual(a, b);
}

export function passInWindow(pass: Pick<PassBody, "not_before" | "not_after">, nowMs: number): boolean {
  const start = Date.parse(pass.not_before);
  const end = Date.parse(pass.not_after);
  if (Number.isNaN(start) || Number.isNaN(end)) return false;
  return nowMs >= start && nowMs <= end;
}
