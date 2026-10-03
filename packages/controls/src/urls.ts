// URL extraction shared by link_exfil and url-pattern signatures (SPEC §6.3): markdown links and images,
// HTML <img src> / <a href>, and bare http(s) URLs.

export interface FoundUrl {
  url: string;
  scheme: string;
  host: string;
  port: number | null;
  path: string;
  /** Query string without the leading "?". */
  query: string;
  isImage: boolean;
  /** Span of the URL itself. */
  start: number;
  end: number;
  /** Span to remove when the whole construct must go (markdown images); equals the URL span otherwise. */
  spanStart: number;
  spanEnd: number;
}

const MD = /(!?)\[([^\]\n]{0,500})\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)/g;
const HTML = /<(img|a)\b[^>]*?\b(?:src|href)\s*=\s*["']([^"']+)["'][^>]*>/gi;
const BARE = /\b(?:https?|ftp):\/\/[^\s<>"'`)\]]+/gi;
const DEFAULT_PORT: Record<string, number> = { http: 80, https: 443, ftp: 21 };

function parts(raw: string): Pick<FoundUrl, "scheme" | "host" | "port" | "path" | "query"> | null {
  if (/^data:/i.test(raw)) return { scheme: "data", host: "", port: null, path: raw.slice(5), query: "" };
  try {
    const u = new URL(raw);
    const scheme = u.protocol.replace(/:$/, "").toLowerCase();
    return {
      scheme,
      host: u.hostname.toLowerCase().replace(/^\[|\]$/g, ""),
      port: u.port ? Number(u.port) : (DEFAULT_PORT[scheme] ?? null),
      path: u.pathname,
      query: u.search.replace(/^\?/, ""),
    };
  } catch {
    return null; // not a parseable absolute URL: ignored
  }
}

export function extractUrls(text: string): FoundUrl[] {
  const out: FoundUrl[] = [];
  const taken: Array<[number, number]> = [];
  const push = (raw: string, urlStart: number, isImage: boolean, spanStart: number, spanEnd: number) => {
    const p = parts(raw);
    if (!p) return;
    out.push({ url: raw, ...p, isImage, start: urlStart, end: urlStart + raw.length, spanStart, spanEnd });
    taken.push([spanStart, spanEnd]);
  };
  const free = (s: number, e: number) => !taken.some(([a, b]) => s < b && e > a);
  for (const m of text.matchAll(MD)) {
    const s = m.index!, raw = m[3]!, urlStart = s + m[0].lastIndexOf(raw);
    const image = m[1] === "!";
    push(raw, urlStart, image, image ? s : urlStart, image ? s + m[0].length : urlStart + raw.length);
  }
  for (const m of text.matchAll(HTML)) {
    const s = m.index!, e = s + m[0].length, raw = m[2]!;
    if (!free(s, e)) continue;
    const image = m[1]!.toLowerCase() === "img";
    const urlStart = s + m[0].indexOf(raw);
    push(raw, urlStart, image, image ? s : urlStart, image ? e : urlStart + raw.length);
  }
  for (const m of text.matchAll(BARE)) {
    const raw = m[0].replace(/[.,;:!?]+$/, "");
    const s = m.index!;
    if (!free(s, s + raw.length)) continue;
    push(raw, s, false, s, s + raw.length);
  }
  return out.sort((a, b) => a.start - b.start);
}

/** Suffix match: "example.com" trusts "docs.example.com" but not "evilexample.com". */
export function hostTrusted(host: string, allow: readonly string[]): boolean {
  const h = host.toLowerCase();
  return h !== "" && allow.some((d) => {
    const x = d.toLowerCase().replace(/^\*?\./, "");
    return h === x || h.endsWith(`.${x}`);
  });
}

/** Mask a URL for logs: keep scheme, host and path, cut the query to its first 8 chars. */
export function maskUrl(u: FoundUrl): string {
  if (u.scheme === "data") return `data:${u.path.slice(0, 24)}…`;
  const q = u.query ? `?${u.query.slice(0, 8)}…` : "";
  return `${u.scheme}://${u.host}${u.port && u.port !== DEFAULT_PORT[u.scheme] ? `:${u.port}` : ""}${u.path}${q}`;
}
