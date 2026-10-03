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
