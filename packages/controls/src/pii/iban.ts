// IBAN: mod-97 checksum plus a country length table (SPEC §7.1).
const LENGTHS: Record<string, number> = {
  PL: 28, DE: 22, GB: 22, FR: 27, LT: 20, LV: 21, EE: 20, ES: 24, IT: 27, NL: 18, BE: 16, AT: 20, CH: 21, CZ: 24, SK: 24, IE: 22, PT: 25, SE: 24, NO: 15, DK: 18, FI: 18,
};

// Case-insensitive: "pl61 1090 ..." is the same account (the red team's case_shuffle beat the upper-case-only form).
// Groups may be split by spaces or dashes ("PL61-1090-1014-...").
export const IBAN_RE = /\b[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]){11,30}\b/gi;

/**
 * Polish domestic account number (NRB): the PL IBAN without "PL", 26 digits written "61 1090 1014 0000 0712 1981 2874"
 * or run together. Reported as pii.iban when "PL" + the digits passes the IBAN checksum.
 */
export const NRB_RE = /(?<![\w-])\d{2}(?:[ ]?\d{4}){6}(?![\w-])/g;

export function nrbMatchLength(m: string): number {
  return ibanValid("PL" + m.replace(/ /g, "")) ? m.length : 0;
}

export function ibanValid(compact: string): boolean {
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(compact)) return false;
  const want = LENGTHS[compact.slice(0, 2)];
  if (want !== undefined ? compact.length !== want : compact.length < 15 || compact.length > 34) return false;
  let rem = 0;
  for (const ch of compact.slice(4) + compact.slice(0, 4)) {
    const v = ch >= "A" && ch <= "Z" ? String(ch.charCodeAt(0) - 55) : ch;
    for (const d of v) rem = (rem * 10 + Number(d)) % 97;
  }
  return rem === 1;
}

/**
 * The regex can swallow a following token ("... 2874 PLN"), so try shorter prefixes until one validates.
 * Returns the length of the valid IBAN inside the match, or 0.
 */
export function ibanMatchLength(m: string): number {
  const pos: number[] = [];
  let compact = "";
  for (let i = 0; i < m.length; i++) if (m[i] !== " " && m[i] !== "-") { compact += m[i]!.toUpperCase(); pos.push(i); }
  for (let len = Math.min(34, compact.length); len >= 15; len--) {
    if (ibanValid(compact.slice(0, len))) return pos[len - 1]! + 1;
  }
  return 0;
}
