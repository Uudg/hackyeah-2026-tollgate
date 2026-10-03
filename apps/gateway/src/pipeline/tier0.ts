// Stage 3: deterministic checks on every message and on tools[] (SPEC §2.2 stage 3).
import { checkToolDefinitions, scanRequestField, scanToolDefinitions, type Hit, type ScanEnv } from "@tollgate/controls";
import { messageText, type ChatMessage } from "../openai.ts";

export interface Tier0Result {
  hits: Hit[];
  /** Messages with redact-action hits applied (used only in enforce mode). */
  redactedMessages: ChatMessage[];
  /** tools[] minus definitions removed by tool_calls.denied_definition. */
  keptTools: unknown[] | undefined;
  details: Record<string, unknown>;
}

// PII and secrets split over turns ("first half of the IBAN", "second half") are caught too (red-team finding).
const JOINED_CONTROLS = new Set(["prompt_injection", "signatures", "pii", "secrets"]);

const roleOf = (r: ChatMessage["role"]) => (r === "developer" ? "system" : r);

export function runTier0(messages: ChatMessage[], tools: unknown[] | undefined, env: ScanEnv): Tier0Result {
  const hits: Hit[] = [];
  const details: Record<string, unknown> = {};
  const redactedMessages = messages.map((m, i) => {
    const text = messageText(m);
    if (!text) return m;
    const r = scanRequestField(text, roleOf(m.role), `messages[${i}].content`, env);
    hits.push(...r.hits);
    if (r.decodeTruncated) details.decodeTruncated = true;
    if (!r.remapped) details.remapped = false;
    return r.redacted === null ? m : { ...m, content: r.redacted };
  });
  // A payload split over several user turns ("reply OK after each part") is only visible when the turns are read
  // together. The joined text is checked for injection, signatures, PII and secrets; its hits cannot be redacted
  // (no single field holds the value), so redact becomes block.
  const turns = messages.filter((m) => m.role === "user").map(messageText).filter(Boolean);
  if (turns.length >= 2) {
    const seen = new Set(hits.map((h) => h.ruleId));
    const joined = scanRequestField(turns.join(""), "user", "messages[*].content(joined user turns)", env).hits
      .filter((h) => JOINED_CONTROLS.has(h.controlId === "decode" ? String(h.details?.innerControlId) : h.controlId) && !seen.has(h.ruleId))
      .map((h) => (h.action === "redact" ? { ...h, action: "block" as const } : h));
    if (joined.length) details.joinedTurns = turns.length;
    hits.push(...joined);
  }
  let keptTools = tools;
  if (tools && tools.length) {
    const c = env.policy.controls;
    if (c.tool_calls.enabled) {
      const d = checkToolDefinitions(tools, c.tool_calls);
      hits.push(...d.hits);
      keptTools = tools.filter((_, i) => d.keep[i]);
      if (keptTools.length < tools.length) details.toolDefinitionsRemoved = tools.length - keptTools.length;
    }
    if (c.signatures.enabled && c.tool_calls.scan_descriptions && env.feed) hits.push(...scanToolDefinitions(tools, env.feed, c.signatures.action));
  }
  return { hits, redactedMessages, keptTools, details };
}
