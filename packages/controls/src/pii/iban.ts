// IBAN: mod-97 checksum plus a country length table (SPEC §7.1).
const LENGTHS: Record<string, number> = {
  PL: 28, DE: 22, GB: 22, FR: 27, LT: 20, LV: 21, EE: 20, ES: 24, IT: 27, NL: 18, BE: 16, AT: 20, CH: 21, CZ: 24, SK: 24, IE: 22, PT: 25, SE: 24, NO: 15, DK: 18, FI: 18,
};

export const IBAN_RE = /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b/g;

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
  for (let i = 0; i < m.length; i++) if (m[i] !== " ") { compact += m[i]; pos.push(i); }
  for (let len = Math.min(34, compact.length); len >= 15; len--) {
    if (ibanValid(compact.slice(0, len))) return pos[len - 1]! + 1;
  }
  return 0;
}
