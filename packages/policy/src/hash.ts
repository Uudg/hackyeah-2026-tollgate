// Content identities. Policy: hash of the canonical parsed policy (stable under comments and key order).
// Feed: hash of the raw file bytes (SPEC §6.1).
import { createHash } from "node:crypto";

export function sortKeysDeep(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeysDeep);
  if (v && typeof v === "object") {
    return Object.fromEntries(Object.keys(v as object).sort().map((k) => [k, sortKeysDeep((v as Record<string, unknown>)[k])]));
  }
  return v;
}

export const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
export const canonicalJson = (v: unknown) => JSON.stringify(sortKeysDeep(v));
export const policyHash = (policy: unknown) => `p-${sha256(canonicalJson(policy)).slice(0, 12)}`;
export const feedHash = (raw: string) => `f-${sha256(raw).slice(0, 12)}`;
