// Fixed injection phrases (SPEC §2.2 step 3b). Run on normalized text only; tier 1 still runs on clean text.
// Rule id inject.heuristic.<n> (1-based, stable: append new phrases at the end).
import { makeHit, type Action, type Hit } from "../types.ts";

export const HEURISTICS: RegExp[] = [
  /ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above)\s+(?:instructions|rules|prompts)/i,
  /disregard\s+(?:your|the)\s+(?:system\s+prompt|instructions)/i,
  /you\s+are\s+(?:now\s+)?(?:DAN\b|in\s+developer\s+mode|unrestricted)/i,
  /reveal\s+(?:your|the)\s+(?:system\s+prompt|instructions|configuration)/i,
  /print\s+(?:your|the)\s+(?:system\s+prompt|initial\s+prompt)/i,
  /(?:begin|start)\s+your\s+(?:answer|response)\s+with/i,
  /do\s+not\s+(?:tell|inform|mention)\s+(?:the\s+)?user/i,
  /\bsudo\s+mode\b/i,
  /new\s+instructions?:/i,
  /###\s*(?:system|instruction)/i,
  /<\|im_start\|>\s*system/i,
];

export function scanInjection(text: string, o: { action: Action; field: string }): Hit[] {
  const hits: Hit[] = [];
  HEURISTICS.forEach((re, i) => {
    const m = re.exec(text);
    if (!m) return;
    hits.push(makeHit({
      controlId: "prompt_injection", ruleId: `inject.heuristic.${i + 1}`, action: o.action, owasp: ["LLM01", "ASI01"],
      field: o.field, text, start: m.index, end: m.index + m[0].length, label: "injection", details: { phrase: i + 1 },
    }));
  });
  return hits;
}
