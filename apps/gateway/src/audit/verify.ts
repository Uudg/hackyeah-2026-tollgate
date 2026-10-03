// Chain verification (SPEC §9). CLI: bun apps/gateway/src/audit/verify.ts ./data/audit.jsonl
import { existsSync, readFileSync } from "node:fs";
import { GENESIS, lineHash, type AuditLine } from "./chain.ts";

export interface VerifyResult { ok: boolean; lines: number; firstBadLine: number | null; headHash: string; reason: string | null }

export function verifyText(text: string, startPrev = GENESIS): VerifyResult {
  const lines = text.split("\n").filter((l) => l.length > 0);
  let prev = startPrev;
  let expectedSeq: number | null = null;
  for (let i = 0; i < lines.length; i++) {
    const bad = (reason: string): VerifyResult => ({ ok: false, lines: lines.length, firstBadLine: i + 1, headHash: prev, reason });
    let line: AuditLine;
    try { line = JSON.parse(lines[i]!) as AuditLine; }
    catch { return bad("not valid JSON"); }
    if (expectedSeq !== null && line.seq !== expectedSeq) return bad(`seq ${line.seq}, expected ${expectedSeq}`);
    if (line.prev_hash !== prev) return bad("prev_hash does not match the previous line");
    if (lineHash(line.prev_hash, line.record) !== line.hash) return bad("hash mismatch: the record was modified");
    prev = line.hash;
    expectedSeq = line.seq + 1;
  }
  return { ok: true, lines: lines.length, firstBadLine: null, headHash: prev, reason: null };
}

export function verifyFile(path: string): VerifyResult {
  if (!existsSync(path)) return { ok: true, lines: 0, firstBadLine: null, headHash: GENESIS, reason: null };
  return verifyText(readFileSync(path, "utf8"));
}

if (import.meta.main) {
  const path = process.argv[2] ?? "./data/audit.jsonl";
  const r = verifyFile(path);
  if (r.ok) { console.log(`OK ${r.lines} lines, head ${r.headHash}`); process.exit(0); }
  console.log(`BROKEN at line ${r.firstBadLine}: ${r.reason}`);
  process.exit(1);
}
