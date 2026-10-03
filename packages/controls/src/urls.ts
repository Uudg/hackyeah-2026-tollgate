// URL extraction shared by link_exfil and url-pattern signatures (SPEC §6.3): markdown links and images (inline and
// reference-style), HTML src/href/poster attributes (quoted or not), and bare http(s) URLs. Protocol-relative URLs
// (//host/path) inside markdown or HTML are resolved as https, because a browser fetches them.
import { foldHomoglyphs } from "./normalize/homoglyphs.ts";

export interface FoundUrl {
  url: string;
  scheme: string;
  host: string;
  port: number | null;
  path: string;
  /** Query string without the leading "?". */
  query: string;
  /** Fragment without the leading "#". Never sent to the server, but readable by the target page's script. */
  fragment: string;
  isImage: boolean;
  /** Span of the URL itself. */
  start: number;
  end: number;
  /** Span to remove when the whole construct must go (markdown images); equals the URL span otherwise. */
  spanStart: number;
  spanEnd: number;
}

// The URL part excludes [ and ] (not valid unescaped in a URL), so "![a](![a](..." cannot rescan to the end of the text.
const MD = /(!?)\[([^\]\n]{0,500})\]\(\s*<?([^)\s>\[\]]+)>?(?:\s+"[^"]*")?\s*\)/g;
// Every tag here except <a> is fetched by the client without a click.
const HTML = /<(img|image|a|iframe|video|audio|source|embed)\b[^<>]*?\b(?:src|href|poster)\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s"'>]+))[^<>]*>/gi; // [^<>]: an unclosed tag stops at the next <
// Reference-style markdown: `[label]: url "title"` on its own line, used by `![alt][label]`, `![label][]` or `![label]`.
const REF_DEF = /^[ \t]{0,3}\[([^\]\n]{1,200})\]:[ \t]*<?([^\s>]+)>?(?:[ \t]+(?:"[^"\n]*"|'[^'\n]*'|\([^)\n]*\)))?[ \t]*$/gm;
const REF_IMG = /!\[([^\]\n]{0,500})\](?:\[([^\]\n]*)\])?/g;
const refLabel = (l: string) => l.trim().replace(/\s+/g, " ").toLowerCase();
const BARE = /\b(?:https?|ftp):\/\/[^\s<>"'`)\]]+/gi;
const DEFAULT_PORT: Record<string, number> = { http: 80, https: 443, ftp: 21 };

function parts(raw: string): Pick<FoundUrl, "scheme" | "host" | "port" | "path" | "query" | "fragment"> | null {
  if (/^data:/i.test(raw)) return { scheme: "data", host: "", port: null, path: raw.slice(5), query: "", fragment: "" };
  const abs = raw.startsWith("//") ? `https:${raw}` : raw;
  if (!URL.canParse(abs)) return null; // not a parseable absolute URL (a relative path): ignored
  const u = new URL(abs);
  const scheme = u.protocol.replace(/:$/, "").toLowerCase();
  return {
    scheme,
    host: u.hostname.toLowerCase().replace(/^\[|\]$/g, ""),
    port: u.port ? Number(u.port) : (DEFAULT_PORT[scheme] ?? null),
    path: u.pathname,
    query: u.search.replace(/^\?/, ""),
    fragment: u.hash.replace(/^#/, ""),
  };
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
    const s = m.index!, e = s + m[0].length, raw = m[2] ?? m[3] ?? m[4]!;
    if (!free(s, e)) continue;
    const image = m[1]!.toLowerCase() !== "a";
    const urlStart = s + m[0].indexOf(raw);
    push(raw, urlStart, image, image ? s : urlStart, image ? e : urlStart + raw.length);
  }
  const imageLabels = new Set<string>();
  for (const m of text.matchAll(REF_IMG)) imageLabels.add(refLabel(m[2] || m[1]!));
  for (const m of text.matchAll(REF_DEF)) {
    const s = m.index!, e = s + m[0].length, raw = m[2]!;
    if (!free(s, e)) continue;
    const image = imageLabels.has(refLabel(m[1]!));
    const urlStart = s + m[0].indexOf(raw, m[0].indexOf("]:"));
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

const RAW_HOST = /^(?:[a-z][a-z0-9+.-]*:)?\/\/(?:[^@/?#\s]*@)?([^/:?#\s]+)/i;

/**
 * Hosts that only look like ASCII after homoglyph folding. Pass the field text BEFORE the fold (NFKC + invisible
 * stripped is fine): "docs.exаmple.com" (Cyrillic а) is returned as "docs.example.com", the form the folded text
 * shows. A browser would fetch docs.xn--exmple-cua.com, so scanLinks must not trust it.
 */
export function spoofedHosts(textBeforeFold: string): Set<string> {
  const out = new Set<string>();
  for (const u of extractUrls(textBeforeFold)) {
    const raw = RAW_HOST.exec(u.url)?.[1];
    if (!raw || /^[\x00-\x7f]*$/.test(raw)) continue;
    const folded = foldHomoglyphs(raw).text.toLowerCase();
    if (folded !== raw.toLowerCase()) out.add(folded);
  }
  return out;
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
