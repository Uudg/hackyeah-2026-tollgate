// Normalization: NFKC, strip invisible code points and stray combining marks, fold homoglyphs. Every later control
// scans the result.
import { stripInvisible, stripStrayMarks } from "./invisible.ts";
import { foldHomoglyphs } from "./homoglyphs.ts";

export { stripInvisible, stripStrayMarks, hasInvisible, INVISIBLE } from "./invisible.ts";
export { foldHomoglyphs } from "./homoglyphs.ts";
export { decodeVariants, base64Text, base64Bytes, isPickleHeader, isPrintable, foldLeet, joinFragments, rot13Text, despace, squash, decodeEntities, NON_LITERAL } from "./decode.ts";
export type { DecodedVariant, PickleBlob, DecodeResult } from "./decode.ts";

export interface Normalized { text: string; invisible: number; homoglyphs: number }

export function normalize(input: string): Normalized {
  const nfkc = input.normalize("NFKC");
  const stripped = stripInvisible(nfkc);
  // Stray combining marks count as invisible characters: they hide text the same way.
  const unmarked = stripStrayMarks(stripped.text);
  const folded = foldHomoglyphs(unmarked.text);
  return { text: folded.text, invisible: stripped.count + unmarked.count, homoglyphs: folded.count };
}
