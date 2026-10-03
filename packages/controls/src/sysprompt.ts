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
  if (runs.length === 0) return lettersPass(system, response, o);
  const overlap = shared.size / sGrams.size;
  const longestRun = Math.max(...runs.map(([a, b]) => b - a + n));
  if (overlap < o.overlapThreshold && longestRun < o.minRun) return lettersPass(system, response, o);
  // One hit per maximal run; each redacts its run to [REDACTED:system_prompt].
  return runs.map(([a, b]) => makeHit({
    controlId: "sysprompt", ruleId: "sysprompt.leak", action: o.action, owasp: ["LLM07"], field: o.field, text: response,
    start: rw[a]!.start, end: rw[b + n - 1]!.end, label: "system_prompt",
    details: { overlap: Number(overlap.toFixed(3)), longestRun },
  }));
}

/**
 * Letters and digits only, lowercased. `start[i]` / `end[i]` give the span in the original string of the character
 * that produced text[i] (one entry per UTF-16 unit, so lowercasing that changes length cannot shift them).
 */
export function squashText(s: string): { text: string; start: number[]; end: number[] } {
  let text = "";
  const start: number[] = [];
  const end: number[] = [];
  for (const m of s.matchAll(/[\p{L}\p{N}]/gu)) {
    const low = m[0].toLowerCase();
    text += low;
    for (let k = 0; k < low.length; k++) { start.push(m.index!); end.push(m.index! + m[0].length); }
  }
  return { text, start, end };
}

const SHINGLE = 24;

/**
 * Second pass for reformatted leaks the word pass cannot see: "Y-o-u a-r-e ...", one letter per line, CamelCase,
 * words glued with symbols. Both texts are reduced to letters and digits; a shared run of at least min_run * 6
 * characters (≈ 15 words, longer than the word pass needs, so it never fires before it) is a leak.
 */
function lettersPass(system: string, response: string, o: SyspromptOptions): Hit[] {
  const minChars = o.minRun * 6;
  const s = squashText(system).text;
  const r = squashText(response);
  if (s.length < minChars || r.text.length < minChars) return [];
  const sh = new Set<string>();
  for (let i = 0; i + SHINGLE <= s.length; i++) sh.add(s.slice(i, i + SHINGLE));
  const runs: Array<[number, number]> = [];
  for (let i = 0; i + SHINGLE <= r.text.length; i++) {
    if (!sh.has(r.text.slice(i, i + SHINGLE))) continue;
    const last = runs[runs.length - 1];
    if (last && last[1] === i - 1) last[1] = i; else runs.push([i, i]);
  }
  const long = runs.filter(([a, b]) => b - a + SHINGLE >= minChars);
  return long.map(([a, b]) => makeHit({
    controlId: "sysprompt", ruleId: "sysprompt.leak", action: o.action, owasp: ["LLM07"], field: o.field, text: response,
    start: r.start[a]!, end: r.end[b + SHINGLE - 1]!, label: "system_prompt",
    details: { pass: "letters", longestRunChars: Math.max(...long.map(([x, y]) => y - x + SHINGLE)) },
  }));
}
