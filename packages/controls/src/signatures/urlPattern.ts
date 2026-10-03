// `url-pattern` entries (SPEC §6.3): every specified field must match the extracted URL.
import type { SignatureEntry } from "@tollgate/policy";
import { hostTrusted, type FoundUrl } from "../urls.ts";

type UrlEntry = Extract<SignatureEntry, { type: "url-pattern" }>;

export function urlMatches(e: UrlEntry, pathRe: RegExp | null, u: FoundUrl, allowDomains: readonly string[]): boolean {
  const p = e.pattern;
  // Exfiltration-shaped entries respect the link_exfil allowlist; infrastructure entries (ShadowRay) do not.
  if ((p.query_min_len !== undefined || p.markdown_image !== undefined) && hostTrusted(u.host, allowDomains)) return false;
  if (p.host !== undefined && !(u.host === p.host.toLowerCase() || u.host.endsWith(`.${p.host.toLowerCase()}`))) return false;
  if (p.port !== undefined && u.port !== p.port) return false;
  if (pathRe && !pathRe.test(u.path)) return false;
  if (p.scheme && !p.scheme.includes(u.scheme)) return false;
  if (p.query_min_len !== undefined && u.query.length < p.query_min_len) return false;
  if (p.markdown_image === true && !u.isImage) return false;
  return true;
}
