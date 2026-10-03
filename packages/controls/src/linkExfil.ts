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
}

const BASE64ISH = /[A-Za-z0-9+_=-]{16,}/;

export function scanLinks(text: string, o: LinkExfilOptions): Hit[] {
  const hits: Hit[] = [];
  for (const u of extractUrls(text)) {
    const trusted = hostTrusted(u.host, o.allowDomains);
    let rule: string | null = null;
    if (u.scheme === "data") rule = u.url.length > 256 ? "link_exfil.data_uri" : null;
    else if (u.isImage && !trusted && o.blockImages) rule = "link_exfil.image_untrusted";
    else if (!trusted) {
      const encodedSegment = u.path.split("/").some((s) => BASE64ISH.test(s) && /\d/.test(s) && /[a-z]/.test(s) && /[A-Z]/.test(s));
      const carriesSecret = o.sensitive.some((s) => s.start < u.end && s.end > u.start);
      if (u.query.length >= o.minQueryLen || encodedSegment || carriesSecret) rule = "link_exfil.payload_untrusted";
    }
    if (!rule) continue;
    hits.push(makeHit({
      controlId: "link_exfil", ruleId: rule, action: o.action, owasp: [...new Set(["LLM05", "LLM02", "ASI01", ...(o.extraOwasp ?? [])])],
      field: o.field, text, start: u.spanStart, end: u.spanEnd, label: "link", details: { url: maskUrl(u), host: u.host, image: u.isImage },
    }));
  }
  return hits;
}
