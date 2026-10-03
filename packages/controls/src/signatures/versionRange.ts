// `version-range` entries (SPEC §6.3): compared against GET /api/version at startup and on reload.
// Reporting only; never blocks chat traffic.

/** Numeric compare of dotted versions ("0.1.34" vs "0.6.2"); pre-release suffixes are ignored. */
export function compareVersions(a: string, b: string): number {
  const pa = a.replace(/^v/, "").split(/[.-]/).map((x) => parseInt(x, 10) || 0);
  const pb = b.replace(/^v/, "").split(/[.-]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return Math.sign(d);
  }
  return 0;
}

export function versionInRange(v: string, r: { lt?: string; lte?: string; gte?: string }): boolean {
  if (r.lt !== undefined && !(compareVersions(v, r.lt) < 0)) return false;
  if (r.lte !== undefined && !(compareVersions(v, r.lte) <= 0)) return false;
  if (r.gte !== undefined && !(compareVersions(v, r.gte) >= 0)) return false;
  return true;
}
