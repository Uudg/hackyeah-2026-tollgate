// Decode-and-rescan candidates (SPEC §2.2 step 3a.4): base64, hex, URL-encoded runs and HTML entities are decoded
// and kept as extra variants when the result is readable text. Base64 that decodes to a pickle header is kept
// as bytes for the pickle walker instead.
import type { Encoding } from "../types.ts";

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
  [/\b(?:[0-9a-fA-F]{2}){12,}\b/g, "hex"],
  [/\S*%[0-9A-Fa-f]{2}\S*/g, "url"],
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
      case "base64": return base64Text(span);
      case "hex": {
        const text = utf8.decode(new Uint8Array(Buffer.from(span, "hex")));
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
    }
  } catch {
    return null; // malformed escape sequence or out-of-range code point: not a decodable candidate
  }
}

/** All decodable variants of `text`, recursively to `maxDepth`, bounded by 32 variants and 64 KB. */
export function decodeVariants(text: string, maxDepth: number): DecodeResult {
  const result: DecodeResult = { variants: [], pickles: [], truncated: false };
  let bytes = 0;
  const walk = (src: string, depth: number, root: [number, number] | null) => {
    if (depth > maxDepth) return;
    for (const [re, enc] of CANDIDATES) {
      for (const m of src.matchAll(re)) {
        if (result.variants.length >= MAX_VARIANTS || bytes >= MAX_BYTES) { result.truncated = true; return; }
        const span = m[0];
        const start = root ? root[0] : m.index!;
        const end = root ? root[1] : m.index! + span.length;
        if (enc === "base64") {
          const raw = base64Bytes(span);
          if (raw && isPickleHeader(raw)) { result.pickles.push({ bytes: raw, depth, rootStart: start, rootEnd: end }); continue; }
        }
        const decoded = decodeOne(span, enc);
        if (decoded === null || decoded === span) continue;
        bytes += decoded.length;
        result.variants.push({ text: decoded, depth, encoding: enc, rootStart: start, rootEnd: end });
        walk(decoded, depth + 1, [start, end]);
      }
    }
  };
  walk(text, 1, null);
  return result;
}
