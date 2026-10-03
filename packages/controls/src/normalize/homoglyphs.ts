// Homoglyph folding (SPEC §2.2 step 3a.3). NFKC already maps fullwidth forms and mathematical alphanumerics
// to ASCII; this table covers the Cyrillic and Greek letters NFKC leaves alone.
// Only words that mix Latin with these letters are folded: plain Russian or Greek text stays untouched.
const MAP: Record<string, string> = {
  "\u0430": "a", "\u0432": "b", "\u0435": "e", "\u043A": "k", "\u043C": "m", "\u043D": "h", "\u043E": "o", "\u0440": "p", "\u0441": "c", "\u0442": "t", "\u0443": "y", "\u0445": "x",
  "\u0456": "i", "\u0458": "j", "\u0455": "s", "\u0501": "d", "\u051B": "q", "\u051D": "w", "\u04BB": "h", "\u04CF": "l", "\u0261": "g",
  "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041A": "K", "\u041C": "M", "\u041D": "H", "\u041E": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T", "\u0425": "X", "\u0423": "Y",
  "\u0406": "I", "\u0408": "J", "\u0405": "S", "\u0500": "D",
  "\u03B1": "a", "\u03BF": "o", "\u03BD": "v", "\u03B9": "i", "\u03C1": "p", "\u03C4": "t", "\u03C5": "u", "\u03BA": "k", "\u03B5": "e",
  "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z", "\u0397": "H", "\u0399": "I", "\u039A": "K", "\u039C": "M", "\u039D": "N", "\u039F": "O", "\u03A1": "P", "\u03A4": "T", "\u03A5": "Y", "\u03A7": "X",
};
const LATIN = /[A-Za-z]/;
const CONFUSABLE = /[\u0370-\u03FF\u0400-\u052F\u0261]/;

export function foldHomoglyphs(text: string): { text: string; count: number } {
  let count = 0;
  const out = text.replace(/[\p{L}\p{M}\p{N}_]+/gu, (word) => {
    if (!LATIN.test(word) || !CONFUSABLE.test(word)) return word;
    let folded = "";
    for (const ch of word) {
      const ascii = MAP[ch];
      if (ascii) { count++; folded += ascii; } else folded += ch;
    }
    return folded;
  });
  return { text: out, count };
}
