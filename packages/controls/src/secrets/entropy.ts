// Generic high-entropy token rule (SPEC §7.1).
import { base64Bytes, base64Text, isPickleHeader } from "../normalize/index.ts";

export function shannon(s: string): number {
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

export const tokenRegex = (minLen: number) => new RegExp(`(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{${minLen},}(?![A-Za-z0-9+/=_-])`, "g");

export type EntropyVerdict = { secret: false } | { secret: true; entropy: number };

/**
 * `before` is the text right before the token, used to skip tokens inside URLs.
 * Skipped on purpose: URLs and paths, tokens with fewer than 3 character classes, base64 that decodes to
 * readable text (decode-and-rescan scans it) or to a pickle stream (the pickle signatures scan it), UUIDs, code
 * identifiers and paths made of words, and SSH public keys. Those are identifiers or public material, not secrets.
 */
export function judgeToken(token: string, before: string, minBits: number): EntropyVerdict {
  if (/[a-z][a-z0-9+.-]*:\/\/\S*$/i.test(before) || /(?:^|\s)(?:~|\.{1,2})?$/.test(before) && token.startsWith("/")) return { secret: false };
  // md5 / sha1 / sha256 digests (commit ids, manifest digests) are public identifiers, not secrets.
  if (/^[a-f0-9]+$/i.test(token) && [32, 40, 64].includes(token.length)) return { secret: false };
  // UUIDs (request ids, trace ids) are identifiers, like the digests above.
  if (/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(token)) return { secret: false };
  if (isSshPublicKey(token, before)) return { secret: false };
  if (looksLikeIdentifier(token)) return { secret: false };
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[+/=_-]/].filter((r) => r.test(token)).length;
  if (classes < 3) return { secret: false };
  if (base64Text(token) !== null) return { secret: false };
  const bytes = base64Bytes(token);
  if (bytes && isPickleHeader(bytes)) return { secret: false };
  const entropy = shannon(token);
  return entropy >= minBits ? { secret: true, entropy } : { secret: false };
}

/**
 * Code identifiers and paths ("getRevenueByRegionV2Async_withRetry", "src/services/RevenueChart2026") are mostly
 * word segments: a capital or nothing, then 3+ lower-case letters. Random keys almost never are (measured: 5 in 20,000
 * random 40-character base62 tokens reach 70 %; real keys in the fixtures score 0–10 %).
 */
export function looksLikeIdentifier(token: string): boolean {
  const words = token.match(/[A-Z]?[a-z]{3,}/g) ?? [];
  return words.join("").length >= 0.7 * token.length;
}

/**
 * The body after "ssh-ed25519 " / "ssh-rsa " / "ecdsa-sha2-nistp256 " is a public key when it decodes to the SSH wire
 * format: a 4-byte length, then the same algorithm name. A random secret placed after "ssh-rsa " does not.
 */
function isSshPublicKey(token: string, before: string): boolean {
  const algo = before.match(/(?:^|\s)((?:ssh|ecdsa|sk)-[a-z0-9@.-]+)\s+$/)?.[1];
  const bytes = algo ? base64Bytes(token) : null;
  if (!algo || !bytes || bytes.length < 4 + algo.length) return false;
  const len = ((bytes[0]! << 24) | (bytes[1]! << 16) | (bytes[2]! << 8) | bytes[3]!) >>> 0;
  return len === algo.length && new TextDecoder().decode(bytes.slice(4, 4 + len)) === algo;
}

/** Spans of PEM public keys and certificates: their base64 bodies are public material, not secrets. */
export function publicBlockSpans(text: string): Array<[number, number]> {
  const spans: Array<[number, number]> = [];
  for (const m of text.matchAll(/-----BEGIN ((?:[A-Z0-9]+ )*PUBLIC KEY|CERTIFICATE)-----[A-Za-z0-9+/=\s]*?-----END \1-----/g)) {
    spans.push([m.index!, m.index! + m[0].length]);
  }
  return spans;
}
