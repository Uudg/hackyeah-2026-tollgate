// Per-field scanning used by the gateway's tier 0 and output path. Pure: the caller passes the policy snapshot,
// the compiled feed and the canary list; nothing here touches the network, disk or a clock.
import { SEVERITY, type Action, type Hit, type Policy } from "@tollgate/policy";
import { applyRedactions, excerpt, remaskExcerpts, type CanaryToken } from "./types.ts";
import { normalize, decodeVariants } from "./normalize/index.ts";
import { scanPii } from "./pii/index.ts";
import { scanSecrets } from "./secrets/index.ts";
import { scanInjection } from "./inject/heuristics.ts";
import { scanPickle, scanSignatures, type CompiledFeed } from "./signatures/index.ts";
import { scanCanaries } from "./canary.ts";
import { scanLinks } from "./linkExfil.ts";
import { scanSysprompt } from "./sysprompt.ts";

export interface ScanEnv {
  policy: Policy;
  feed: CompiledFeed | null;
  canaries: readonly CanaryToken[];
  /** Never reported as secrets: the calling agent's own gateway key. Canary tokens are added automatically. */
  ignore: readonly string[];
}

export type Role = "system" | "user" | "assistant" | "tool";

export interface FieldResult {
  hits: Hit[];
  /** The field after applying every redact-action hit; null when nothing needs redacting. */
  redacted: string | null;
  /** false when spans could not be mapped back to the original text and the normalized text was used instead. */
  remapped: boolean;
  decodeTruncated: boolean;
}

const union = (a: string[], b: string[]) => [...new Set([...a, ...b])];

function redactField(original: string, normalized: string, hits: Hit[], forceNormalized: boolean): Pick<FieldResult, "redacted" | "remapped"> {
  const spans = hits
    .filter((h) => h.action === "redact" && h.span && h.span.end > h.span.start)
    .map((h) => ({ start: h.span!.start, end: h.span!.end, label: String(h.details?.mask ?? h.controlId) }));
  if (spans.length === 0 && !forceNormalized) return { redacted: null, remapped: true };
  const same = original === normalized && !forceNormalized;
  return { redacted: applyRedactions(same ? original : normalized, spans), remapped: same };
}

/** Tier 0 on one request field (SPEC §2.2 step 3): normalize, decode, then every deterministic control per variant. */
export function scanRequestField(text: string, role: Role, field: string, env: ScanEnv): FieldResult {
  const c = env.policy.controls;
  const hits: Hit[] = [];
  const n = normalize(text);
  if (c.unicode.enabled) {
    const whole = { start: 0, end: n.text.length, field };
    if (n.invisible > 0 && n.invisible >= c.unicode.max_invisible) {
      hits.push({ controlId: "unicode", ruleId: "unicode.invisible", action: c.unicode.action, owasp: ["LLM01"], span: whole, details: { count: n.invisible, mask: "unicode" } });
    }
    if (n.homoglyphs > 0 && n.homoglyphs >= c.unicode.max_homoglyphs) {
      hits.push({ controlId: "unicode", ruleId: "unicode.homoglyph", action: c.unicode.action, owasp: ["LLM01"], span: whole, details: { count: n.homoglyphs, mask: "unicode" } });
    }
  }
  const ignore = [...env.ignore, ...env.canaries.map((k) => k.token)];
  const untrusted = role !== "system";
  const scanVariant = (t: string): Hit[] => {
    const out: Hit[] = [];
    if (c.secrets.enabled) out.push(...scanSecrets(t, { action: c.secrets.action, entropyMin: c.secrets.entropy_min, entropyMinLen: c.secrets.entropy_min_len, patterns: c.secrets.patterns, field, ignore }));
    if (c.pii.enabled && (untrusted || c.pii.scan_system_prompt)) out.push(...scanPii(t, { entities: c.pii.entities, action: c.pii.action, field }));
    if (!untrusted) return out;
    if (c.prompt_injection.enabled && c.prompt_injection.heuristics) out.push(...scanInjection(t, { action: c.prompt_injection.action, field }));
    if (c.signatures.enabled && env.feed) out.push(...scanSignatures(t, env.feed, { scope: "request", defaultAction: c.signatures.action, field, allowDomains: c.link_exfil.allow_domains }));
    if (c.canaries.enabled) out.push(...scanCanaries(t, env.canaries, { rule: "canaries.in_input", action: c.canaries.action, field }));
    return out;
  };
  hits.push(...scanVariant(n.text));

  let decodeTruncated = false;
  if (c.decode.enabled && c.decode.max_depth > 0) {
    const d = decodeVariants(n.text, c.decode.max_depth);
    decodeTruncated = d.truncated;
    for (const v of d.variants) {
      for (const inner of scanVariant(v.text)) {
        // A hit hidden inside an encoding is reported as decode.rescan, with the inner rule's action.
        hits.push({
          controlId: "decode", ruleId: "decode.rescan", action: inner.action, owasp: union(inner.owasp, ["LLM01"]),
          span: { start: v.rootStart, end: v.rootEnd, field },
          excerptRedacted: excerpt(n.text, v.rootStart, v.rootEnd, "encoded"),
          details: { innerRuleId: inner.ruleId, innerControlId: inner.controlId, encoding: v.encoding, depth: v.depth, mask: "encoded" },
        });
      }
    }
    if (c.signatures.enabled && env.feed && untrusted) {
      for (const p of d.pickles) {
        hits.push(...scanPickle(p.bytes, env.feed, { scope: "request", defaultAction: c.signatures.action, field, allowDomains: [], text: n.text, start: p.rootStart, end: p.rootEnd }));
      }
    }
  }
  const unicodeRedact = hits.some((h) => h.controlId === "unicode" && h.action === "redact");
  return { hits: remaskExcerpts(n.text, hits), ...redactField(text, n.text, hits, unicodeRedact), decodeTruncated };
}

export interface OutputFieldOptions {
  surface: "response" | "tool_call";
  /** Concatenated system messages of the request, for the sysprompt control (response content only). */
  system: string;
  /** For tool calls: every string value of the parsed arguments, scanned in addition to the raw JSON. */
  argumentStrings?: string;
}

/** Output path on one completion field (SPEC §2.2 step 7): secrets → pii → canaries → link_exfil → sysprompt → signatures. */
export function scanOutputField(text: string, field: string, env: ScanEnv, o: OutputFieldOptions): FieldResult {
  const c = env.policy.controls;
  const n = normalize(text);
  const t = n.text;
  const extraOwasp = o.surface === "tool_call" ? ["ASI02"] : [];
  const ignore = [...env.ignore, ...env.canaries.map((k) => k.token)];
  const hits: Hit[] = [];
  // Responses are never blocked for a secret, only redacted (unless the control is set to allow).
  const secretAction: Action = c.secrets.action === "allow" ? "allow" : "redact";
  if (c.secrets.enabled) hits.push(...scanSecrets(t, { action: secretAction, entropyMin: c.secrets.entropy_min, entropyMinLen: c.secrets.entropy_min_len, patterns: c.secrets.patterns, field, ignore, owasp: union(["LLM02"], extraOwasp) }));
  if (c.pii.enabled) hits.push(...scanPii(t, { entities: c.pii.entities, action: c.pii.action, field, owasp: union(["LLM02"], extraOwasp) }));
  const canaryRule = o.surface === "tool_call" ? "canaries.in_tool_call" : "canaries.in_output";
  if (c.canaries.enabled) hits.push(...scanCanaries(t, env.canaries, { rule: canaryRule, action: c.canaries.action, field, extraOwasp }));
  if (c.link_exfil.enabled) {
    const sensitive = hits.filter((h) => h.span).map((h) => h.span!);
    hits.push(...scanLinks(t, { action: c.link_exfil.action, allowDomains: c.link_exfil.allow_domains, minQueryLen: c.link_exfil.min_query_len, blockImages: c.link_exfil.block_images, field, sensitive, extraOwasp }));
  }
  if (o.surface === "response" && c.sysprompt.enabled && o.system) {
    hits.push(...scanSysprompt(o.system, t, { action: c.sysprompt.action, ngram: c.sysprompt.ngram, overlapThreshold: c.sysprompt.overlap_threshold, minRun: c.sysprompt.min_run, field }));
  }
  if (c.signatures.enabled && env.feed) {
    hits.push(...scanSignatures(t, env.feed, { scope: o.surface, defaultAction: c.signatures.action, field, allowDomains: c.link_exfil.allow_domains, extraOwasp }));
    if (o.surface === "tool_call") {
      for (const p of decodeVariants(t, 1).pickles) {
        hits.push(...scanPickle(p.bytes, env.feed, { scope: "tool_call", defaultAction: c.signatures.action, field, allowDomains: [], extraOwasp, text: t, start: p.rootStart, end: p.rootEnd }));
      }
    }
  }
  // JSON escapes can hide a payload from regexes ("os.system(\"bash", "AKIA\u0049..."); scan the unescaped values too.
  let wholeField = false;
  if (o.argumentStrings && o.argumentStrings !== t) {
    const flat = normalize(o.argumentStrings).text;
    const seen = new Set(hits.map((h) => h.ruleId));
    const extra: Hit[] = [];
    if (c.secrets.enabled) extra.push(...scanSecrets(flat, { action: secretAction, entropyMin: c.secrets.entropy_min, entropyMinLen: c.secrets.entropy_min_len, patterns: c.secrets.patterns, field, ignore, owasp: union(["LLM02"], extraOwasp) }));
    if (c.pii.enabled) extra.push(...scanPii(flat, { entities: c.pii.entities, action: c.pii.action, field, owasp: union(["LLM02"], extraOwasp) }));
    if (c.canaries.enabled) extra.push(...scanCanaries(flat, env.canaries, { rule: "canaries.in_tool_call", action: c.canaries.action, field, extraOwasp }));
    if (c.signatures.enabled && env.feed) extra.push(...scanSignatures(flat, env.feed, { scope: "tool_call", defaultAction: c.signatures.action, field, allowDomains: c.link_exfil.allow_domains, extraOwasp }));
    for (const h of extra) {
      if (seen.has(h.ruleId)) continue;
      // The span points into the unescaped text, not the raw JSON: a redact replaces the whole argument string.
      if (h.action === "redact") wholeField = true;
      hits.push({ ...h, span: undefined, details: { ...h.details, scannedAs: "argument_values" } });
    }
  }
  if (wholeField) return { hits: remaskExcerpts(t, hits), redacted: JSON.stringify({ redacted: "[REDACTED:tool_arguments]" }), remapped: false, decodeTruncated: false };
  return { hits: remaskExcerpts(t, hits), ...redactField(text, t, hits, false), decodeTruncated: false };
}

/** Highest-severity hit (first one wins a tie) and the collapsed decision. No hits → allow. */
export function collapse(hits: readonly Hit[]): { decision: Action; deciding: Hit | null } {
  let deciding: Hit | null = null;
  for (const h of hits) if (!deciding || SEVERITY[h.action] > SEVERITY[deciding.action]) deciding = h;
  return { decision: deciding?.action ?? "allow", deciding };
}
