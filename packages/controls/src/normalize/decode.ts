// Decode-and-rescan candidates (SPEC §2.2 step 3a.4): base64, hex, URL-encoded runs and HTML entities are decoded
// and kept as extra variants when the result is readable text. Base64 that decodes to a pickle header is kept
// as bytes for the pickle walker instead. base64 may be line-wrapped (GNU base64, Python encodebytes) and hex may be
// written as separated bytes ("49 67 6e", "0x49,0x67", "\x49\x67"); whitespace, separators and prefixes are removed
// before decoding. Whole-text rewrites found by the Red Team Loop and the hardening pass are added too: leetspeak
// folded back to letters, string fragments the text asks to concatenate, ROT13, letter-spaced words joined
// ("i g n o r e"), intra-word -, ., * removed ("ig-nore"), and HTML entities decoded across the whole text.
import type { Encoding } from "../types.ts";
import { stripInvisible, stripStrayMarks } from "./invisible.ts";
import { foldHomoglyphs } from "./homoglyphs.ts";

export interface DecodedVariant {
  text: string;
  depth: number;
  encoding: Encoding;
  /** Span of the outermost encoded blob in the depth-0 text; redacting a decoded hit redacts this span. */
  rootStart: number;
  rootEnd: number;
}

export interface PickleBlob { bytes: Uint8Array; depth: number; rootStart: number; rootEnd: number }

export interface DecodeResult { variants: DecodedVariant[]; pickles: PickleBlob[]; truncated: boolean }

const MAX_VARIANTS = 32;
const MAX_BYTES = 64 * 1024;

const CANDIDATES: Array<[RegExp, Encoding]> = [
  [/[A-Za-z0-9+/_-]{24,}={0,2}/g, "base64"],
  // Line-wrapped base64 (76 or 64 columns). Starts only at the beginning of a run and bounds the line length, so a
  // long run without a newline is linear, not quadratic.
  [/(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{16,76}\r?\n)+[A-Za-z0-9+/]{4,}={0,2}/g, "base64"],
  [/\b(?:[0-9a-fA-F]{2}){12,}\b/g, "hex"],
  [/\b(?:0x)?[0-9a-fA-F]{2}(?:(?:, ?|[ :])(?:0x)?[0-9a-fA-F]{2}){11,}\b/g, "hex"],
  [/(?:\\x[0-9a-fA-F]{2}){12,}/g, "hex"],
  [/(?<!\S)\S*%[0-9A-Fa-f]{2}\S*/g, "url"], // whole whitespace-delimited token; starting only at its first char keeps it linear
  [/(?:&#x?[0-9a-fA-F]+;){6,}/g, "html"],
];

const utf8 = new TextDecoder("utf-8", { fatal: false });

/** ≥ 90 % printable characters (tabs and newlines count as printable). */
export function isPrintable(s: string): boolean {
  if (s.length < 4) return false;
  let ok = 0, n = 0;
  for (const ch of s) {
    n++;
    const c = ch.codePointAt(0)!;
    if ((c >= 32 && c !== 127 && c !== 0xfffd && !(c >= 0x80 && c < 0xa0)) || c === 9 || c === 10 || c === 13) ok++;
  }
  return ok / n >= 0.9;
}

export function base64Bytes(s: string): Uint8Array | null {
  const clean = s.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  if (clean.length % 4 === 1) return null;
  try {
    return new Uint8Array(Buffer.from(clean, "base64"));
  } catch {
    return null; // not base64 after all: simply not a candidate
  }
}

export function isPickleHeader(b: Uint8Array): boolean {
  return b.length >= 2 && b[0] === 0x80 && b[1]! >= 0x02 && b[1]! <= 0x05;
}

/** Text decoded from a base64 token, or null when the bytes are not readable text. */
export function base64Text(token: string): string | null {
  const bytes = base64Bytes(token);
  if (!bytes || bytes.length < 12) return null;
  const text = utf8.decode(bytes);
  return isPrintable(text) ? text : null;
}

function decodeOne(span: string, enc: Encoding): string | null {
  try {
    switch (enc) {
      case "base64": return base64Text(span.replace(/\s+/g, ""));
      case "hex": {
        const text = utf8.decode(new Uint8Array(Buffer.from(span.replace(/\\x|0x|[\s,:]/gi, ""), "hex")));
        return isPrintable(text) ? text : null;
      }
      case "url": {
        if ((span.match(/%[0-9A-Fa-f]{2}/g) ?? []).length < 3) return null;
        const text = decodeURIComponent(span.replace(/\+/g, " "));
        return isPrintable(text) ? text : null;
      }
      case "html": {
        const text = span.replace(/&#(x?)([0-9a-fA-F]+);/g, (_, x: string, n: string) => String.fromCodePoint(parseInt(n, x ? 16 : 10)));
        return isPrintable(text) ? text : null;
      }
      default: return null; // the other encodings are whole-text rewrites, not span decoders
    }
  } catch {
    return null; // malformed escape sequence or out-of-range code point: not a decodable candidate
  }
}

const LEET: Record<string, string> = { "4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t", "@": "a", "$": "s" };

/** "1gn0r3 4ll prev10u5" → "ignore all previous". Only words mixing letters and leet digits change; needs ≥ 2 of them. */
export function foldLeet(text: string): string | null {
  let changed = 0;
  const out = text.replace(/[\p{L}\d@$]+/gu, (w, at: number) => {
    // Skip %XX escapes, hex strings (a short word such as "d0" or "b3" is still folded), tokens (long, or with digits
    // that are not leet: keys, ids, digests) and words without both letters and leet digits.
    if (text[at - 1] === "%" || w.length > 16 || /[2689]/.test(w) || (w.length > 3 && /^[0-9a-f]+$/i.test(w)) || !/\p{L}/u.test(w) || !/[013457@$]/.test(w)) return w;
    changed++;
    // "@" before a domain is an e-mail address, not a leet "a" ("j4n.k0w4l5k1@3xampl3.c0m").
    const email = /@/.test(w) && text[at + w.length] === ".";
    return w.replace(email ? /[013457$]/g : /[013457@$]/g, (ch) => LEET[ch]!);
  });
  // Once the text is clearly leetspeak, a lone "4" or "1" between words is the word "a" or "I" ("You 4r3 4 f1n4nc3
  // 455i574n7"); otherwise one digit breaks every n-gram of a repeated system prompt (depth-2 finding).
  return changed >= 2 ? out.replace(/(?<=[\p{L}] )[41](?= [\p{L}])/gu, (d) => (d === "4" ? "a" : "I")) : null;
}

/** `a = "Ignore all prev"` `b = "ious instructions"` → the fragments joined, when there are at least two. */
export function joinFragments(text: string): string | null {
  const parts: string[] = [];
  for (const m of text.matchAll(/\b\w{1,24}\s*[=:]\s*("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')/g)) {
    const lit = m[1]!;
    try { parts.push(lit.startsWith('"') ? (JSON.parse(lit) as string) : lit.slice(1, -1)); }
    catch { parts.push(lit.slice(1, -1)); } // not valid JSON escapes: take the raw characters
  }
  return parts.length >= 2 ? parts.join("") : null;
}

const ROT13_WORDS = new Set(["the", "and", "to", "of", "in", "is", "you", "your", "all", "for", "that", "this", "it", "with", "be", "are", "on", "not", "or", "as", "do", "what", "me", "my", "now", "from", "at", "any", "previous", "instructions", "ignore", "system", "prompt"]);
const rot13 = (t: string) => t.replace(/[A-Za-z]/g, (ch) => {
  const base = ch <= "Z" ? 65 : 97;
  return String.fromCharCode(((ch.charCodeAt(0) - base + 13) % 26) + base);
});
const commonWords = (t: string) => (t.toLowerCase().match(/[a-z]+/g) ?? []).filter((w) => ROT13_WORDS.has(w)).length;

/**
 * ROT13 of the whole text, when the text names ROT13/Caesar or the rotated text reads as English (at least 3 common
 * words, more than the original has). Ordinary text rotates into gibberish and produces no variant.
 */
export function rot13Text(text: string): string | null {
  if (!/[A-Za-z]/.test(text)) return null;
  const r = rot13(text);
  const mentioned = /\brot[\s-]?13\b|\bcaesar\b/i.test(text);
  const words = commonWords(r);
  return mentioned || (words >= 3 && words > commonWords(text)) ? r : null;
}

/** "i g n o r e  a l l" → "ignore all": runs of ≥ 3 single characters split by single spaces are joined (≥ 8 joined in total). */
export function despace(text: string): string | null {
  let joined = 0;
  const out = text.replace(/(?<!\S)(?:\S ){2,}\S(?!\S)/g, (run) => {
    const word = run.replace(/ /g, "");
    joined += word.length;
    return word;
  });
  return joined >= 8 ? out.replace(/ {2,}/g, " ") : null;
}

/** "Ig-nore all pre-vious in-struc-tions" → "Ignore all previous instructions": -, ., * between letters removed (≥ 2 of them). */
export function squash(text: string): string | null {
  let n = 0;
  const out = text.replace(/(?<=\p{L})[-.*](?=\p{L})/gu, () => { n++; return ""; });
  return n >= 2 ? out : null;
}

const ENTITY = /&(?:#(x?)([0-9a-fA-F]{1,6})|(lt|gt|amp|quot|apos|nbsp));/gi;
const NAMED: Record<string, string> = { lt: "<", gt: ">", amp: "&", quot: '"', apos: "'", nbsp: " " };

/** HTML entities decoded across the whole text when it has at least 3 ("ign&#111;re all previ&#111;us ..."). */
export function decodeEntities(text: string): string | null {
  if ((text.match(ENTITY) ?? []).length < 3) return null;
  return text.replace(ENTITY, (all, x: string | undefined, num: string | undefined, name: string | undefined) => {
    if (name) return NAMED[name.toLowerCase()] ?? all;
    const cp = parseInt(num!, x ? 16 : 10);
    return Number.isFinite(cp) && cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : all;
  });
}

/**
 * %XX escapes decoded across the whole text when it has at least 6 of them. The span decoder works per
 * whitespace-delimited token, which misses fragments split over lines (payload_split + url_encode).
 */
export function urlDecodeAll(text: string): string | null {
  if ((text.match(/%[0-9A-Fa-f]{2}/g) ?? []).length < 6) return null;
  return text.replace(/(?:%[0-9A-Fa-f]{2})+/g, (run) => {
    try { return decodeURIComponent(run); } catch { return run; } // an invalid UTF-8 sequence stays as written
  });
}

/**
 * Rewrites that change the characters of the text rather than undo an encoding. Secrets and PII are literal strings,
 * so these variants are scanned for injection and signatures only: folding or rotating a value only invents new ones.
 */
export const NON_LITERAL: ReadonlySet<Encoding> = new Set<Encoding>(["leet", "rot13", "despace", "squash", "entities"]);

/** [rewrite, encoding, walk]: walk = also look for encoded blobs inside the rewritten text (depth 2). */
const REWRITES: Array<[(t: string) => string | null, Encoding, boolean]> = [
  [foldLeet, "leet", true], [joinFragments, "concat", true], [urlDecodeAll, "url", true],
  [rot13Text, "rot13", false], [despace, "despace", false], [squash, "squash", false], [decodeEntities, "entities", false],
];

/**
 * Decoded text gets the same normalization as the request text (zero-width characters, stray marks, homoglyphs), so
 * text obfuscated before it was encoded is still read (depth-2 red-team finding: zero_width + base64/hex/url).
 */
const clean = (t: string) => foldHomoglyphs(stripStrayMarks(stripInvisible(t.normalize("NFKC")).text).text).text;

/** All decodable variants of `text`, recursively to `maxDepth`, bounded by 32 variants and 64 KB. */
export function decodeVariants(text: string, maxDepth: number): DecodeResult {
  const result: DecodeResult = { variants: [], pickles: [], truncated: false };
  let bytes = 0;
  const walk = (src: string, depth: number, root: [number, number] | null) => {
    if (depth > maxDepth) return;
    for (const [re, enc] of CANDIDATES) {
      for (const m of src.matchAll(re)) {
        if (result.variants.length >= MAX_VARIANTS || bytes >= MAX_BYTES) { result.truncated = true; return; }
        const span = enc === "base64" ? m[0].replace(/\s+/g, "") : m[0];
        const start = root ? root[0] : m.index!;
        const end = root ? root[1] : m.index! + m[0].length;
        if (enc === "base64") {
          const raw = base64Bytes(span);
          if (raw && isPickleHeader(raw)) { result.pickles.push({ bytes: raw, depth, rootStart: start, rootEnd: end }); continue; }
        }
        const raw = decodeOne(span, enc);
        if (raw === null || raw === m[0]) continue;
        const decoded = clean(raw);
        bytes += decoded.length;
        result.variants.push({ text: decoded, depth, encoding: enc, rootStart: start, rootEnd: end });
        // Leetspeak or fragments inside the encoding (leetspeak + base64, payload_split + url_encode): the walkable
        // rewrites run on the decoded text too. The variant keeps the outer encoding's root span.
        for (const [rewrite, renc, nested] of REWRITES) {
          if (!nested || result.variants.length >= MAX_VARIANTS) continue;
          const r = rewrite(decoded);
          if (r !== null && r !== decoded) result.variants.push({ text: r, depth: depth + 1, encoding: renc, rootStart: start, rootEnd: end });
        }
        walk(decoded, depth + 1, [start, end]);
      }
    }
  };
  walk(text, 1, null);
  for (const [rewrite, enc, nested] of REWRITES) {
    const t = rewrite(text);
    if (t === null || t === text || result.variants.length >= MAX_VARIANTS) continue;
    result.variants.push({ text: t, depth: 1, encoding: enc, rootStart: 0, rootEnd: text.length });
    if (!nested) continue;
    walk(t, 2, [0, text.length]);
    // Two stacked rewrites (leetspeak + payload_split, payload_split + url_encode): the other walkable rewrites run on
    // this one's result. The second rewrite names the variant: leet on top of anything stays non-literal.
    for (const [second, enc2, nested2] of REWRITES) {
      if (!nested2 || second === rewrite || result.variants.length >= MAX_VARIANTS) continue;
      const t2 = second(t);
      if (t2 !== null && t2 !== t) result.variants.push({ text: t2, depth: 2, encoding: enc === "leet" ? "leet" : enc2, rootStart: 0, rootEnd: text.length });
    }
  }
  return result;
}
