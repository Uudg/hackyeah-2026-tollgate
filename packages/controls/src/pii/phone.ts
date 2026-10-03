// Phone numbers (SPEC §7.1): 9–15 digits, not glued to other digits or letters, and shaped like a phone
// (a leading + or at least two separators), so order numbers and amounts are not flagged. A compact international
// number ("+48601234567") is accepted on its leading +. A match never starts after "1." or "1,", and digit groups
// followed by a currency ("4 111 111 111 PLN") are an amount, not a phone. "call 1 601 234 567" is still a phone.
const CURRENCY = String.raw`\s?(?:PLN|EUR|USD|GBP|CHF|JPY|zł|zl|€|\$|£)`;
export const PHONE_RE = new RegExp(String.raw`(?<![\w+]|\d[.,])(?:\+\d{9,15}(?!\d)|(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?|\d{2,4}[ .-])\d{3}[ .-]?\d{2,4}(?:[ .-]?\d{2,3})?)(?!\w)(?!${CURRENCY}(?![A-Za-z]))`, "g");

export function phoneValid(m: string): boolean {
  const digits = m.replace(/\D/g, "").length;
  const seps = (m.match(/[ .()-]/g) ?? []).length;
  return digits >= 9 && digits <= 15 && (m.startsWith("+") || seps >= 2);
}

export const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
export const ipValid = (m: string) => m.split(".").every((o) => Number(o) <= 255);
