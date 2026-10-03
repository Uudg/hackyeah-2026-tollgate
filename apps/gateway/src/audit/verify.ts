// Chain verification (SPEC §9). CLI: bun apps/gateway/src/audit/verify.ts ./data/audit.jsonl
// The chain spans the rotated files (audit-<ts>-<seq>.jsonl, oldest first) and then audit.jsonl.
import { existsSync, readFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { brokenFiles, GENESIS, lineHash, parseHead, rotatedFiles, type AuditLine } from "./chain.ts";

export interface VerifyResult {
  ok: boolean;
  /** Lines checked across every file of the chain. */
  lines: number;
  /** Line number inside `file` (1-based). */
  firstBadLine: number | null;
  headHash: string;
  headSeq: number | null;
  reason: string | null;
  /** File the first bad line is in (name only), null when ok. */
  file: string | null;
  /** Files checked, oldest first (names only). */
  files: string[];
  /** Files the writer set aside because it could not resume from them; not part of the chain, listed for review. */
  brokenFiles: string[];
}

/**
 * Verify one file's lines. `startPrev`/`startSeq` continue a chain from the previous file; a file whose first line is
 * a genesis line (seq 1, prev_hash all zeros) starts a new chain, which is what the writer does after moving a
 * broken file aside.
 */
export function verifyText(text: string, startPrev = GENESIS, startSeq: number | null = null): VerifyResult {
  const lines = text.split("\n").filter((l) => l.length > 0);
  let prev = startPrev;
  let expectedSeq: number | null = startSeq === null ? null : startSeq + 1;
  let headSeq: number | null = startSeq;
  const first = lines[0] ? parseHead(lines[0]) : null;
  if (first?.ok && first.seq === 1 && first.prev_hash === GENESIS) { prev = GENESIS; expectedSeq = null; }
  for (let i = 0; i < lines.length; i++) {
    const bad = (reason: string): VerifyResult => ({ ok: false, lines: lines.length, firstBadLine: i + 1, headHash: prev, headSeq, reason, file: null, files: [], brokenFiles: [] });
    let line: AuditLine;
    try { line = JSON.parse(lines[i]!) as AuditLine; }
    catch { return bad("not valid JSON"); }
    if (line === null || typeof line !== "object") return bad("not an audit record");
    if (expectedSeq !== null && line.seq !== expectedSeq) return bad(`seq ${line.seq}, expected ${expectedSeq}`);
    if (line.prev_hash !== prev) return bad("prev_hash does not match the previous line");
    if (lineHash(line.prev_hash, line.record) !== line.hash) return bad("hash mismatch: the record was modified");
    prev = line.hash;
    headSeq = line.seq;
    expectedSeq = line.seq + 1;
  }
  return { ok: true, lines: lines.length, firstBadLine: null, headHash: prev, headSeq, reason: null, file: null, files: [], brokenFiles: [] };
}

export function verifyFile(path: string): VerifyResult {
  const dir = dirname(path);
  const files = [...rotatedFiles(dir), ...(existsSync(path) ? [basename(path)] : [])];
  const broken = brokenFiles(dir);
  let prev = GENESIS;
  let seq: number | null = null;
  let total = 0;
  for (const f of files) {
    const r = verifyText(readFileSync(join(dir, f), "utf8"), prev, seq);
    total += r.lines;
    if (!r.ok) return { ...r, lines: total, file: f, files, brokenFiles: broken };
    prev = r.headHash;
    seq = r.headSeq;
  }
  return { ok: true, lines: total, firstBadLine: null, headHash: prev, headSeq: seq, reason: null, file: null, files, brokenFiles: broken };
}

if (import.meta.main) {
  const path = process.argv[2] ?? "./data/audit.jsonl";
  const r = verifyFile(path);
  for (const b of r.brokenFiles) console.log(`WARN ${b} was set aside by the writer (unreadable last line); it is not part of the chain`);
  // SPEC §9 output format; the file is named only when the chain spans rotated files.
  const where = r.files.length > 1 ? ` (${r.files.length} files)` : "";
  if (r.ok) { console.log(`OK ${r.lines} lines, head ${r.headHash}${where}`); process.exit(0); }
  console.log(`BROKEN at line ${r.firstBadLine}: ${r.reason}${r.files.length > 1 ? ` (in ${r.file})` : ""}`);
  process.exit(1);
}
