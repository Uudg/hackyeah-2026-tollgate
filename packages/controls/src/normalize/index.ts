// Normalization: NFKC, strip invisible code points, fold homoglyphs. Every later control scans the result.
import { stripInvisible } from "./invisible.ts";
import { foldHomoglyphs } from "./homoglyphs.ts";

export { stripInvisible, hasInvisible, INVISIBLE } from "./invisible.ts";
export { foldHomoglyphs } from "./homoglyphs.ts";
export { decodeVariants, base64Text, base64Bytes, isPickleHeader, isPrintable } from "./decode.ts";
export type { DecodedVariant, PickleBlob, DecodeResult } from "./decode.ts";

export interface Normalized { text: string; invisible: number; homoglyphs: number }

export function normalize(input: string): Normalized {
  const nfkc = input.normalize("NFKC");
  const stripped = stripInvisible(nfkc);
  const folded = foldHomoglyphs(stripped.text);
  return { text: folded.text, invisible: stripped.count, homoglyphs: folded.count };
}
