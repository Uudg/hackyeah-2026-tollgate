// Shared types for the pure controls. No I/O, no network, no globals: strings and policy slices in, Hit[] out.
import type { Action, Hit } from "@tollgate/policy";

export type { Action, Hit };

export type Encoding = "base64" | "hex" | "url" | "html" | "leet" | "concat";
export type Surface = "request" | "response" | "tool_call";

/** A canary token as the gateway loads it from SQLite and policy.canaries.tokens. */
export interface CanaryToken { id: string; token: string; kind: string; label: string | null }

/** Placeholder written over a redacted span. */
export const mask = (label: string) => `[REDACTED:${label}]`;

/** ≤ 120 chars around [start, end) with the match itself masked. Never contains the matched text. */
export function excerpt(text: string, start: number, end: number, label: string): string {
  const before = text.slice(Math.max(0, start - 40), start);
  const after = text.slice(end, end + 40);
  return `${start > 40 ? "…" : ""}${before}${mask(label)}${after}${end + 40 < text.length ? "…" : ""}`.slice(0, 120);
}

export interface HitInput {
  controlId: string;
  ruleId: string;
  action: Action;
  owasp: string[];
  field: string;
  text: string;
  start: number;
  end: number;
  /** Replacement label: the hit redacts [start, end) to [REDACTED:<label>]. */
  label: string;
  details?: Record<string, unknown>;
}

/** Builds a Hit with span, masked excerpt and the redaction label kept in details.mask. */
export function makeHit(h: HitInput): Hit {
  return {
    controlId: h.controlId,
    ruleId: h.ruleId,
    action: h.action,
    owasp: h.owasp,
    span: { start: h.start, end: h.end, field: h.field },
    excerptRedacted: excerpt(h.text, h.start, h.end, h.label),
    details: { ...h.details, mask: h.label },
  };
}

/** Non-overlapping regex matches; `taken` collects spans already claimed by earlier rules. */
export function overlaps(taken: Array<[number, number]>, start: number, end: number): boolean {
  return taken.some(([a, b]) => start < b && end > a);
}

/** Case-insensitive glob where `*` matches any run of characters (tool names, model names, registries). */
export function globMatch(pattern: string, value: string): boolean {
  const re = new RegExp(`^${pattern.split("*").map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`, "i");
  return re.test(value);
}

/**
 * Rebuild every hit's excerpt with all masked spans of the same field applied, so the 40 characters of
 * context around one match never carry a neighbouring secret, canary or PII value in clear text.
 * `text` is the text the spans index into.
 */
export function remaskExcerpts(text: string, hits: Hit[]): Hit[] {
  const spans = hits.flatMap((h) => (h.span && typeof h.details?.mask === "string" ? [{ ...h.span, label: h.details.mask as string }] : []));
  if (spans.length < 2) return hits;
  return hits.map((h) => {
    if (!h.span || typeof h.details?.mask !== "string") return h;
    const ws = Math.max(0, h.span.start - 40), we = Math.min(text.length, h.span.end + 40);
    const inWindow = spans.filter((s) => s.field === h.span!.field && s.start < we && s.end > ws)
      .map((s) => ({ start: Math.max(s.start, ws) - ws, end: Math.min(s.end, we) - ws, label: s.label }));
    const body = applyRedactions(text.slice(ws, we), inWindow);
    return { ...h, excerptRedacted: `${ws > 0 ? "…" : ""}${body}${we < text.length ? "…" : ""}`.slice(0, 120) };
  });
}

/**
 * Apply redactions. Overlapping spans merge into one, labelled by the longest span.
 * Spans index into `text`.
 */
export function applyRedactions(text: string, spans: Array<{ start: number; end: number; label: string }>): string {
  if (spans.length === 0) return text;
  const sorted = [...spans].sort((a, b) => a.start - b.start || b.end - a.end);
  const merged: Array<{ start: number; end: number; label: string; len: number }> = [];
  for (const s of sorted) {
    const last = merged[merged.length - 1];
    if (last && s.start < last.end) {
      if (s.end - s.start > last.len) { last.label = s.label; last.len = s.end - s.start; }
      last.end = Math.max(last.end, s.end);
    } else merged.push({ ...s, len: s.end - s.start });
  }
  let out = "";
  let pos = 0;
  for (const m of merged) { out += text.slice(pos, m.start) + mask(m.label); pos = m.end; }
  return out + text.slice(pos);
}
