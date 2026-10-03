// Secret detection (SPEC §7.1): rule ids secrets.<name>, OWASP LLM02.
import { makeHit, overlaps, type Action, type Hit } from "../types.ts";
import { SECRET_PATTERNS, customPatterns } from "./patterns.ts";
import { judgeToken, tokenRegex } from "./entropy.ts";

export { SECRET_PATTERNS } from "./patterns.ts";
export { shannon } from "./entropy.ts";

export interface SecretsOptions {
  action: Action;
  entropyMin: number;
  entropyMinLen: number;
  patterns: readonly string[];
  field: string;
  /** Strings that are never reported: the calling agent's own gateway key and the canary tokens. */
  ignore: readonly string[];
  owasp?: string[];
}

export function scanSecrets(text: string, o: SecretsOptions): Hit[] {
  const hits: Hit[] = [];
  const taken: Array<[number, number]> = [];
  const ignored = (s: string) => o.ignore.some((t) => t.length > 0 && (s.includes(t) || t.includes(s)));
  const add = (name: string, start: number, end: number, action: Action, details?: Record<string, unknown>) => {
    taken.push([start, end]);
    hits.push(makeHit({
      controlId: "secrets", ruleId: `secrets.${name}`, action, owasp: o.owasp ?? ["LLM02"],
      field: o.field, text, start, end, label: name.replace(/^custom\./, ""), details: { name, ...details },
    }));
  };
  for (const { name, re } of [...SECRET_PATTERNS, ...customPatterns(o.patterns)]) {
    for (const m of text.matchAll(re)) {
      const start = m.index!, end = start + m[0].length;
      if (m[0].length === 0 || overlaps(taken, start, end) || ignored(m[0])) continue;
      add(name, start, end, o.action);
    }
  }
  for (const m of text.matchAll(tokenRegex(o.entropyMinLen))) {
    const start = m.index!, end = start + m[0].length;
    if (overlaps(taken, start, end) || ignored(m[0])) continue;
    const v = judgeToken(m[0], text.slice(Math.max(0, start - 300), start), o.entropyMin);
    if (!v.secret) continue;
    add("high_entropy", start, end, o.action, { entropy: Number(v.entropy.toFixed(2)) });
  }
  return hits;
}
