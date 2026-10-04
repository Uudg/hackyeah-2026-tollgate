// Payment cards: 13–19 digits, Luhn, issuer prefix 3/4/5/6 or Mastercard's 2221–2720 range (SPEC §7.1).
// Digit groups may be split by spaces, dashes or dots ("4111.1111.1111.1111").
export const CARD_RE = /\b(?:\d[ .-]?){12,18}\d\b/g;

export function luhnValid(digits: string): boolean {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
  }
  return sum % 10 === 0;
}

export function cardValid(m: string): boolean {
  const d = m.replace(/\D/g, "");
  return d.length >= 13 && d.length <= 19 && /^(?:[3-6]|2[2-7])/.test(d) && luhnValid(d);
}

/**
 * [offset, length] of a valid card inside a match, or null. The regex is greedy, so a number written right before the
 * card ("number 15 4111 1111 1111 1111") is pulled into the match; each later digit group is tried as the start too.
 */
export function cardSpan(m: string): [number, number] | null {
  if (cardValid(m)) return [0, m.length];
  for (const g of m.matchAll(/[ .-](?=\d)/g)) {
    const off = g.index + 1;
    if (cardValid(m.slice(off))) return [off, m.length - off];
  }
  return null;
}
