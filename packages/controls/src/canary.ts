// Canary tokens (SPEC §13): fake secrets whose appearance outside the system prompt proves a leak.
import { makeHit, type Action, type CanaryToken, type Hit } from "./types.ts";
import { squashText } from "./sysprompt.ts";

export type CanaryRule = "canaries.in_input" | "canaries.in_output" | "canaries.in_tool_call";

/** A squashed token shorter than this is only matched exactly (a short custom token could occur by chance). */
const MIN_SQUASHED = 12;

/**
 * Exact substring match on normalized text (homoglyphed tokens are folded back before this runs), then a squashed
 * match: letters and digits only, case-insensitive, so "t g c _ S t a t i c…", "TGC-STATIC…" and a token split
 * across joined argument values still match. Canaries are 20+ random characters, so this cannot fire by chance.
 */
export function scanCanaries(text: string, tokens: readonly CanaryToken[], o: { rule: CanaryRule; action: Action; field: string; extraOwasp?: string[] }): Hit[] {
  const hits: Hit[] = [];
  let sq: ReturnType<typeof squashText> | null = null;
  for (const c of tokens) {
    let start = text.indexOf(c.token);
    let end = start + c.token.length;
    let match = "exact";
    if (start < 0) {
      const tok = squashText(c.token).text;
      if (tok.length < MIN_SQUASHED) continue;
      sq ??= squashText(text);
      const at = sq.text.indexOf(tok);
      if (at < 0) continue;
      start = sq.start[at]!;
      end = sq.end[at + tok.length - 1]!;
      match = "squashed";
    }
    hits.push(makeHit({
      controlId: "canaries", ruleId: o.rule, action: o.action, owasp: [...new Set(["LLM02", "LLM07", "ASI06", ...(o.extraOwasp ?? [])])],
      field: o.field, text, start, end, label: "canary",
      details: { canary: { id: c.id, kind: c.kind, label: c.label }, match },
    }));
  }
  return hits;
}

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const B62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const pick = (alphabet: string, n: number) => {
  const bytes = crypto.getRandomValues(new Uint8Array(n));
  return [...bytes].map((b) => alphabet[b % alphabet.length]).join("");
};

/** Small checksum of the canary id, so a canary AKIA key can be told apart from a real one in the log. */
function idChecksum(id: string, n: number): string {
  let h = 0;
  for (const ch of id) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  let out = "";
  for (let i = 0; i < n; i++) { out += B32[h % 32]; h = Math.floor(h / 32); }
  return out;
}

function ibanChecksum(country: string, bban: string): string {
  let rem = 0;
  for (const ch of bban + country + "00") {
    const v = ch >= "A" && ch <= "Z" ? String(ch.charCodeAt(0) - 55) : ch;
    for (const d of v) rem = (rem * 10 + Number(d)) % 97;
  }
  return String(98 - rem).padStart(2, "0");
}

export type CanaryKind = "aws_key" | "api_key" | "iban" | "record";

export function generateCanary(kind: CanaryKind, id: string): string {
  switch (kind) {
    case "aws_key": return `AKIA${pick(B32, 12)}${idChecksum(id, 4)}`;
    case "api_key": return `tgc_${pick(B62, 24)}`;
    case "iban": {
      const bban = `9999${pick("0123456789", 20)}`;
      return `PL${ibanChecksum("PL", bban)}${bban}`;
    }
    case "record": return `CANARY-RECORD-${[...crypto.getRandomValues(new Uint8Array(4))].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
  }
}
