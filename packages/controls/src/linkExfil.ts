// Link exfiltration (SPEC §7.3): URLs in model output or tool-call arguments that would carry data out.
// Rule order per URL: data_uri, image_untrusted, payload_untrusted. One hit per URL.
import { makeHit, type Action, type Hit } from "./types.ts";
import { extractUrls, hostTrusted, maskUrl } from "./urls.ts";

export interface LinkExfilOptions {
  action: Action;
  allowDomains: readonly string[];
  minQueryLen: number;
  blockImages: boolean;
  field: string;
  /** Spans already flagged as PII / secret / canary: a URL containing one is a payload. */
  sensitive: ReadonlyArray<{ start: number; end: number }>;
  extraOwasp?: string[];
  /** From spoofedHosts(text before the homoglyph fold): hosts that read as ASCII only after folding. Never trusted. */
  spoofedHosts?: ReadonlySet<string>;
}

const BASE64ISH = /[A-Za-z0-9+_=-]{16,}/;
/** A segment that looks like encoded data: 16+ base64-ish chars mixing digits, lower and upper case. */
const encoded = (s: string) => BASE64ISH.test(s) && /\d/.test(s) && /[a-z]/.test(s) && /[A-Z]/.test(s);

export function scanLinks(text: string, o: LinkExfilOptions): Hit[] {
  const hits: Hit[] = [];
  for (const u of extractUrls(text)) {
    const trusted = hostTrusted(u.host, o.allowDomains) && !o.spoofedHosts?.has(u.host);
    let rule: string | null = null;
    if (u.scheme === "data") rule = u.url.length > 256 ? "link_exfil.data_uri" : null;
    else if (u.isImage && !trusted && o.blockImages) rule = "link_exfil.image_untrusted";
    else if (!trusted) {
      // The #fragment never reaches the server, but the page behind one click reads it: an encoded fragment, or a
      // key=value fragment as long as a payload query, counts like the path and the query. Heading anchors
      // (#setup-in-three-commands) are neither.
      // A fragment made of words joined by - or _ ("Getting-Started-With-Python3") is a heading anchor.
      const headingAnchor = /^[A-Za-z][a-z0-9]*(?:[-_][A-Za-z][a-z0-9]*)+$/.test(u.fragment);
      const encodedSegment = [...u.path.split("/"), ...(headingAnchor ? [] : u.fragment.split(/[/&]/))].some(encoded);
      const queryLike = u.query.length + (u.fragment.includes("=") ? u.fragment.length : 0);
      const carriesSecret = o.sensitive.some((s) => s.start < u.end && s.end > u.start);
      if (queryLike >= o.minQueryLen || encodedSegment || carriesSecret) rule = "link_exfil.payload_untrusted";
    }
    if (!rule) continue;
    hits.push(makeHit({
      controlId: "link_exfil", ruleId: rule, action: o.action, owasp: [...new Set(["LLM05", "LLM02", "ASI01", ...(o.extraOwasp ?? [])])],
      field: o.field, text, start: u.spanStart, end: u.spanEnd, label: "link", details: { url: maskUrl(u), host: u.host, image: u.isImage },
    }));
  }
  return hits;
}
