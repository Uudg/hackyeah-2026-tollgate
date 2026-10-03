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
 * readable text (decode-and-rescan scans it) or to a pickle stream (the pickle signatures scan it).
 */
export function judgeToken(token: string, before: string, minBits: number): EntropyVerdict {
  if (/[a-z][a-z0-9+.-]*:\/\/\S*$/i.test(before) || /(?:^|\s)(?:~|\.{1,2})?$/.test(before) && token.startsWith("/")) return { secret: false };
  // md5 / sha1 / sha256 digests (commit ids, manifest digests) are public identifiers, not secrets.
  if (/^[a-f0-9]+$/i.test(token) && [32, 40, 64].includes(token.length)) return { secret: false };
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[+/=_-]/].filter((r) => r.test(token)).length;
  if (classes < 3) return { secret: false };
  if (base64Text(token) !== null) return { secret: false };
  const bytes = base64Bytes(token);
  if (bytes && isPickleHeader(bytes)) return { secret: false };
  const entropy = shannon(token);
  return entropy >= minBits ? { secret: true, entropy } : { secret: false };
}
