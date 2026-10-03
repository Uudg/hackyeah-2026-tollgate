// System-prompt leakage (SPEC §7.4): word n-gram overlap between the system prompt and the response.
import { makeHit, type Action, type Hit } from "./types.ts";

interface Word { w: string; start: number; end: number }
const words = (s: string): Word[] => [...s.matchAll(/[\p{L}\p{N}]+/gu)].map((m) => ({ w: m[0].toLowerCase(), start: m.index!, end: m.index! + m[0].length }));

export interface SyspromptOptions { action: Action; ngram: number; overlapThreshold: number; minRun: number; field: string }

export function scanSysprompt(system: string, response: string, o: SyspromptOptions): Hit[] {
  const sw = words(system);
  if (sw.length < 20) return [];
  const n = o.ngram;
  const gram = (ws: Word[], i: number) => ws.slice(i, i + n).map((x) => x.w).join(" ");
  const sGrams = new Set<string>();
  for (let i = 0; i + n <= sw.length; i++) sGrams.add(gram(sw, i));
  const rw = words(response);
  const shared = new Set<string>();
  const runs: Array<[number, number]> = []; // [first gram start, last gram start] in response words
  for (let i = 0; i + n <= rw.length; i++) {
    const g = gram(rw, i);
    if (!sGrams.has(g)) continue;
    shared.add(g);
    const last = runs[runs.length - 1];
    if (last && last[1] === i - 1) last[1] = i; else runs.push([i, i]);
  }
  if (runs.length === 0) return [];
  const overlap = shared.size / sGrams.size;
  const longestRun = Math.max(...runs.map(([a, b]) => b - a + n));
  if (overlap < o.overlapThreshold && longestRun < o.minRun) return [];
  // One hit per maximal run; each redacts its run to [REDACTED:system_prompt].
  return runs.map(([a, b]) => makeHit({
    controlId: "sysprompt", ruleId: "sysprompt.leak", action: o.action, owasp: ["LLM07"], field: o.field, text: response,
    start: rw[a]!.start, end: rw[b + n - 1]!.end, label: "system_prompt",
    details: { overlap: Number(overlap.toFixed(3)), longestRun },
  }));
}
