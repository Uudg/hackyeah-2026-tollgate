// Fixed injection phrases (SPEC §2.2 step 3b). Run on normalized text only; tier 1 still runs on clean text.
// Rule id inject.heuristic.<n> (1-based, stable: append new phrases at the end).
import { makeHit, type Action, type Hit } from "../types.ts";

// Word gap for heuristic 1: whitespace, punctuation or underscores ("ignore_all_previous", "ignore, all previous").
const G = String.raw`[\s\W_]+`;
// "all of the previous", "any and all prior", "your earlier", ...
const PRIOR = String.raw`(?:(?:all|any|and|every|each)${G})*(?:of${G})?(?:(?:the|your|these|those)${G})?(?:previous|prior|above|earlier|preceding|foregoing)${G}`;
// "ignore the previous instructions I gave you" is a user retracting their own instruction, not an attack.
// Only a relative clause counts ("instructions (that) I gave"): spaces only, so "...instructions. I wrote new ones:" is
// still an attack.
const NOT_MINE = String.raw`(?![ \t]+(?:that[ \t]+)?(?:I|we)[ \t]+(?:just[ \t]+)?(?:gave|sent|wrote|shared|provided)\b)`;

export const HEURISTICS: RegExp[] = [
  // 1. Override phrase. rules/guidelines only after ignore/disregard: "forget the earlier guidelines from 2023" is ordinary.
  new RegExp(
    String.raw`\b(?:ignore|disregard|forget|override)${G}${PRIOR}(?:instructions?|prompts?|directives|commands)\b${NOT_MINE}` +
    String.raw`|\b(?:ignore|disregard)${G}${PRIOR}(?:rules|guidelines)\b${NOT_MINE}` +
    String.raw`|\b(?:ignore|disregard|forget|override)${G}(?:all${G})?(?:of${G})?(?:the|your)${G}(?:instructions?|rules|prompts?|directives|guidelines)${G}(?:above|given${G}(?:above|earlier|before))\b`,
    "i",
  ),
  // 2. "disregard the instructions in my last message" is a user correcting themselves.
  /disregard\s+(?:your|the)\s+(?:system\s+prompt|instructions(?!\s+(?:in|from|about)\s+(?:my|our)\b))/i,
  /you\s+are\s+(?:now\s+)?(?:DAN\b|in\s+developer\s+mode|unrestricted)/i,
  /reveal\s+(?:your|the)\s+(?:system\s+prompt|instructions|configuration)/i,
  /print\s+(?:your|the)\s+(?:system\s+prompt|initial\s+prompt)/i,
  // 6. Affirmative primer ("Sure, here is"); "start your response with a summary" is an ordinary request.
  /(?:begin|start)\s+your\s+(?:answer|response|reply)\s+with\s*["'“‘]\s*(?:sure|certainly|of\s+course|absolutely|yes|here\s+is)/i,
  // 7. Not "the user's manager" or "the users".
  /do\s+not\s+(?:tell|inform|mention)\s+(?:the\s+)?user\b(?!['’]s)/i,
  /\bsudo\s+mode\b/i,
  /new\s+instructions?:/i,
  // 10. Prompt-template headers ("### System:", "### Instruction:"), not markdown headings like "### System requirements".
  /###\s*(?:system|instructions?)\s*(?:prompt\s*)?:/i,
  /<\|im_start\|>\s*system/i,
  // 12. Chat-template control tokens (Llama 2 [INST]/<<SYS>>, sequence reset </s><s>, Llama 3 headers, Zephyr/Phi <|system|>).
  /\[\/?INST\]|<<\/?SYS>>|<\/s>\s*<s>|<\|(?:system|start_header_id|end_header_id|eot_id)\|>/i,
  // 13. The override phrase in Polish, German and Russian: needs both the verb and "previous instructions".
  /\bignoruj\s+(?:wszystkie\s+)?(?:poprzednie|wcześniejsze|powyższe)\s+(?:instrukcje|polecenia|zasady)|\bignorier(?:e|en)?\s+(?:alle\s+)?(?:vorherigen|bisherigen|früheren|obigen)\s+(?:Anweisungen|Instruktionen|Regeln|Befehle)|(?:игнорируй|проигнорируй|забудь)\s+(?:все\s+)?(?:предыдущие|прошлые|прежние|вышеуказанные)\s+(?:инструкции|указания|правила|команды)/i,
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
