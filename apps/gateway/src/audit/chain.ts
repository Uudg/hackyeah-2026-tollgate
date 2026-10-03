// Audit line format and hashing (SPEC §9): hash = sha256(prev_hash + "\n" + canonicalJson(record)).
import { existsSync, readdirSync } from "node:fs";
import { canonicalJson, sha256 } from "@tollgate/policy/loader";

export const GENESIS = "0".repeat(64);

export interface AuditLine { seq: number; prev_hash: string; hash: string; record: Record<string, unknown> }

export const lineHash = (prevHash: string, record: unknown) => sha256(`${prevHash}\n${canonicalJson(record)}`);

/** File-name-safe timestamp; sorts in time order. */
export const fileStamp = () => new Date().toISOString().replace(/[:.]/g, "-");

/** Rotated chain files: audit-<seq padded to 12>-<stamp>.jsonl. Sequence first, so name order is chain order even if
 * the clock goes backwards. */
export const rotatedName = (seq: number) => `audit-${String(seq).padStart(12, "0")}-${fileStamp()}.jsonl`;

/** A file the writer could not resume from; kept for inspection, never part of the chain. */
export const brokenName = () => `audit-${fileStamp()}.broken.jsonl`;

const isBroken = (f: string) => f.endsWith(".broken.jsonl");

/** Rotated chain files in `dir`, oldest first (names only). */
export function rotatedFiles(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((f) => /^audit-.+\.jsonl$/.test(f) && !isBroken(f)).sort();
}

/** Files set aside by the writer because their last line was not an audit record. */
export function brokenFiles(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((f) => /^audit-.+\.jsonl$/.test(f) && isBroken(f)).sort();
}

export type ParsedHead = { ok: true; seq: number; prev_hash: string; hash: string } | { ok: false; reason: string };

/** Parse one line just far enough to continue or check a chain. A typed failure, never a throw. */
export function parseHead(line: string): ParsedHead {
  let v: unknown;
  try { v = JSON.parse(line); }
  catch (err) { return { ok: false, reason: `not valid JSON: ${(err as Error).message}` }; }
  const l = v as Partial<AuditLine> | null;
  if (!l || typeof l !== "object" || !Number.isInteger(l.seq) || (l.seq as number) < 1) return { ok: false, reason: "no positive integer seq" };
  if (typeof l.hash !== "string" || !/^[a-f0-9]{64}$/.test(l.hash)) return { ok: false, reason: "no 64-hex hash" };
  if (typeof l.prev_hash !== "string" || !/^[a-f0-9]{64}$/.test(l.prev_hash)) return { ok: false, reason: "no 64-hex prev_hash" };
  return { ok: true, seq: l.seq as number, prev_hash: l.prev_hash, hash: l.hash };
}
