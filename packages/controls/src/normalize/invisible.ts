// Invisible code points stripped before scanning (SPEC §2.2 step 3a.2): every Unicode Default_Ignorable_Code_Point
// (zero-width, bidi controls, word joiners, soft hyphen, variation selectors, tag characters, Hangul fillers,
// Mongolian variation selectors, shorthand format controls, musical-symbol format characters) plus the line/paragraph
// separators and narrow no-break space (U+2028–U+202F) and the interlinear annotation marks (U+FFF9–U+FFFB).
export const INVISIBLE = /[\p{Default_Ignorable_Code_Point}\u2028-\u202F\uFFF9-\uFFFB]/gu;

/** Emoji presentation selectors are stripped but not counted, so three emoji in a row are not an attack. */
const UNCOUNTED = new Set(["\uFE0E", "\uFE0F"]);

export function stripInvisible(text: string): { text: string; count: number } {
  let count = 0;
  const out = text.replace(INVISIBLE, (ch) => {
    if (!UNCOUNTED.has(ch)) count++;
    return "";
  });
  return { text: out, count };
}

export function hasInvisible(text: string): boolean {
  INVISIBLE.lastIndex = 0;
  const found = INVISIBLE.test(text);
  INVISIBLE.lastIndex = 0;
  return found;
}

/**
 * Combining marks left on an ASCII letter or digit after NFKC ("A̶K̶I̶A̶", Zalgo text). NFKC composes every mark that
 * has a precomposed letter (ą, é, ż stay intact), so what is left on a Latin base is decoration that only hides the
 * text from regexes. Marks on other scripts (Arabic harakat, Devanagari signs) are untouched.
 */
const MARK = /\p{Mn}/u;
const LATIN_BASE = /[A-Za-z0-9]/;

/**
 * One linear pass (a lookbehind version was quadratic on a long run of marks). `count` is the number of stacked marks
 * (a second or later mark on the same base, as in Zalgo text): a single mark such as x̄ or p̂ in statistics, or t͡s in
 * IPA, is stripped for scanning but is not counted as hidden text.
 */
export function stripStrayMarks(text: string): { text: string; count: number } {
  let count = 0;
  let onLatin = false;
  let marks = 0;
  let out = "";
  for (const ch of text) {
    if (MARK.test(ch)) {
      if (onLatin) { if (++marks > 1) count++; continue; }
      out += ch;
      continue;
    }
    onLatin = LATIN_BASE.test(ch);
    marks = 0;
    out += ch;
  }
  return { text: out, count };
}
