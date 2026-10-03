// PESEL (Polish national id): weighted checksum, month with century offset, day 1–31 (SPEC §7.1).
export const PESEL_RE = /\b\d{11}\b/g;

export function peselValid(p: string): boolean {
  if (!/^\d{11}$/.test(p)) return false;
  const w = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
  const sum = w.reduce((s, wi, i) => s + wi * Number(p[i]), 0);
  if ((10 - (sum % 10)) % 10 !== Number(p[10])) return false;
  const month = Number(p.slice(2, 4)) % 20, day = Number(p.slice(4, 6));
  return month >= 1 && month <= 12 && day >= 1 && day <= 31;
}
