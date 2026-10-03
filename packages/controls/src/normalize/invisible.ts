// Invisible code points stripped before scanning (SPEC §2.2 step 3a.2): zero-width, bidi controls, word joiners,
// soft hyphen, variation selectors, tag characters, musical-symbol format characters.
export const INVISIBLE = /[\u200B-\u200F\u2028-\u202F\u2060-\u206F\uFEFF\u00AD\u034F\u061C\u180E\uFE00-\uFE0F\u{E0000}-\u{E007F}\u{1D173}-\u{1D17A}]/gu;

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
