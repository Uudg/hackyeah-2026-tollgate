// Historical-attack signatures (SPEC §6). Rule id sig.<entry id>, control id "signatures".
// The feed is compiled once per load; evaluation is pure.
import type { Feed, FeedScope, SignatureEntry } from "@tollgate/policy";
import { makeHit, type Action, type Hit } from "../types.ts";
import { extractUrls, maskUrl } from "../urls.ts";
import { compileRegex } from "./regex.ts";
import { urlMatches } from "./urlPattern.ts";
import { walkPickle } from "./pickle.ts";
import { describeMatch, toolTexts } from "./toolDescription.ts";

export { walkPickle } from "./pickle.ts";
export { compareVersions, versionInRange } from "./versionRange.ts";
export { toolTexts } from "./toolDescription.ts";

export interface CompiledEntry { entry: SignatureEntry; regex: RegExp | null; pathRegex: RegExp | null }
export interface CompiledFeed { entries: CompiledEntry[] }

const cache = new WeakMap<Feed, CompiledFeed>();

export function compileFeed(feed: Feed): CompiledFeed {
  const hit = cache.get(feed);
  if (hit) return hit;
  const entries = feed.entries.filter((e) => e.enabled).map((entry): CompiledEntry => {
    if (entry.type === "regex" || entry.type === "tool-description") return { entry, regex: compileRegex(entry.pattern.regex, entry.pattern.flags), pathRegex: null };
    if (entry.type === "url-pattern") return { entry, regex: null, pathRegex: entry.pattern.path_regex ? new RegExp(entry.pattern.path_regex) : null };
    return { entry, regex: null, pathRegex: null };
  });
  const compiled = { entries };
  cache.set(feed, compiled);
  return compiled;
}

export interface SigOptions {
  scope: FeedScope;
  /** policy.controls.signatures.action: used for entries without their own action. */
  defaultAction: Action;
  field: string;
  allowDomains: readonly string[];
  extraOwasp?: string[];
}

function sigHit(c: CompiledEntry, o: SigOptions, text: string, start: number, end: number, label: string, details: Record<string, unknown>): Hit {
  const e = c.entry;
  return makeHit({
    controlId: "signatures", ruleId: `sig.${e.id}`, action: e.action ?? o.defaultAction,
    owasp: [...new Set([...e.owasp, ...(o.extraOwasp ?? [])])], field: o.field, text, start, end, label,
    details: { entryId: e.id, cve: e.cve, severity: e.severity, type: e.type, ...details },
  });
}

/** regex and url-pattern entries on one text. */
export function scanSignatures(text: string, feed: CompiledFeed, o: SigOptions): Hit[] {
  const hits: Hit[] = [];
  let urls: ReturnType<typeof extractUrls> | null = null;
  for (const c of feed.entries) {
    if (!c.entry.scope.includes(o.scope)) continue;
    if (c.entry.type === "regex" && c.regex) {
      const m = c.regex.exec(text);
      if (m) hits.push(sigHit(c, o, text, m.index, m.index + m[0].length, "signature", {}));
    } else if (c.entry.type === "url-pattern") {
      urls ??= extractUrls(text);
      const u = urls.find((x) => urlMatches(c.entry as Extract<SignatureEntry, { type: "url-pattern" }>, c.pathRegex, x, o.allowDomains));
      if (u) hits.push(sigHit(c, o, text, u.spanStart, u.spanEnd, "link", { url: maskUrl(u) }));
    }
  }
  return hits;
}

/** pickle-opcode entries on bytes that start with a pickle header. Span is the encoded blob in `text`. */
export function scanPickle(bytes: Uint8Array, feed: CompiledFeed, o: SigOptions & { text: string; start: number; end: number }): Hit[] {
  const pickles = feed.entries.filter((c) => c.entry.type === "pickle-opcode" && c.entry.scope.includes(o.scope));
  if (pickles.length === 0) return [];
  const walk = walkPickle(bytes);
  const hits: Hit[] = [];
  for (const c of pickles) {
    const p = (c.entry as Extract<SignatureEntry, { type: "pickle-opcode" }>).pattern;
    const bad = walk.globals.find((g) => p.dangerous_globals.includes(g) && (!p.require_reduce || walk.called.has(g)));
    if (bad) hits.push(sigHit(c, o, o.text, o.start, o.end, "pickle", { global: bad, globals: walk.globals.slice(0, 10) }));
    else if (walk.parseError && p.on_parse_error === "block") hits.push(sigHit(c, o, o.text, o.start, o.end, "pickle", { parseError: walk.parseError, globals: walk.globals.slice(0, 10) }));
  }
  return hits;
}

/** tool-description entries on a request's tools[]. Direction request. */
export function scanToolDefinitions(tools: readonly unknown[], feed: CompiledFeed, defaultAction: Action): Hit[] {
  const hits: Hit[] = [];
  const entries = feed.entries.filter((c) => c.entry.type === "tool-description" && c.entry.scope.includes("tool_definition"));
  tools.forEach((tool, i) => {
    const { toolName, texts } = toolTexts(tool, i);
    for (const c of entries) {
      const p = (c.entry as Extract<SignatureEntry, { type: "tool-description" }>).pattern;
      for (const t of texts) {
        const m = describeMatch(t.text, { regex: c.regex!, maxLength: p.max_length, invisible: p.invisible_chars, htmlComments: p.html_comments });
        if (!m) continue;
        hits.push(sigHit(c, { scope: "tool_definition", defaultAction, field: t.field, allowDomains: [] }, t.text, m.start, m.end, "tool_description", { toolName, reason: m.reason }));
        break;
      }
    }
  });
  return hits;
}
