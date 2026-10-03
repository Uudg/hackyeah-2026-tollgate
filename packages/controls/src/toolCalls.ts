// Tool-call gating (SPEC §7.5). Request side: tool definitions. Response side: each tool call the model made.
import { globMatch, type Action, type Hit } from "./types.ts";
import { foldHomoglyphs } from "./normalize/homoglyphs.ts";
import { stripInvisible } from "./normalize/invisible.ts";

export interface ToolCallsConfig {
  action: Action;
  allow: readonly string[];
  deny: readonly string[];
  require_approval: readonly string[];
  max_arguments_bytes: number;
}

const hit = (ruleId: string, action: Action, owasp: string[], field: string, details: Record<string, unknown>): Hit => ({
  controlId: "tool_calls", ruleId, action, owasp, span: { start: 0, end: 0, field }, details,
});

/** OpenAI's own rule for function names. Anything else ("shell ", "ѕhell" with a Cyrillic ѕ) is a policy-evasion attempt. */
export const TOOL_NAME = /^[A-Za-z0-9_-]{1,64}$/;

/** The name the deny / allow / approval globs see: NFKC, invisible characters removed, homoglyphs folded, trimmed. */
export function canonicalToolName(name: string): string {
  return foldHomoglyphs(stripInvisible(name.normalize("NFKC")).text).text.trim();
}

const matchesAny = (globs: readonly string[], name: string) => globs.some((p) => globMatch(p, name));

export interface DefinitionCheck { hits: Hit[]; keep: boolean[] }

/**
 * definition_invalid (block) and denied_definition (removed from the forwarded request). The deny globs see the
 * canonical name first, so a lookalike of a denied tool is removed (redact); any other name outside TOOL_NAME blocks.
 */
export function checkToolDefinitions(tools: readonly unknown[], cfg: ToolCallsConfig): DefinitionCheck {
  const hits: Hit[] = [];
  const keep = tools.map((t, i) => {
    const def = t as { type?: unknown; function?: { name?: unknown; parameters?: unknown } } | null;
    const fn = def?.function;
    const params = fn?.parameters;
    if (def?.type !== "function" || typeof fn?.name !== "string" || fn.name === "" || (params !== undefined && (typeof params !== "object" || params === null || Array.isArray(params)))) {
      hits.push(hit("tool_calls.definition_invalid", "block", ["LLM06"], `tools[${i}]`, { type: def?.type ?? null }));
      return false;
    }
    if (matchesAny(cfg.deny, canonicalToolName(fn.name))) {
      hits.push(hit("tool_calls.denied_definition", "redact", ["LLM06", "ASI02"], `tools[${i}]`, { toolName: fn.name }));
      return false;
    }
    if (!TOOL_NAME.test(fn.name)) {
      hits.push(hit("tool_calls.definition_invalid", "block", ["LLM06"], `tools[${i}]`, { toolName: fn.name, reason: "name outside [A-Za-z0-9_-]{1,64}" }));
      return false;
    }
    return true;
  });
  return { hits, keep };
}

export interface ToolCall { id?: string; type?: string; function?: { name?: string; arguments?: string } }

/** Names and required keys of the tools the request declared. */
export function declaredTools(tools: readonly unknown[]): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const t of tools) {
    const fn = (t as { function?: { name?: unknown; parameters?: { required?: unknown } } } | null)?.function;
    if (typeof fn?.name !== "string") continue;
    const req = Array.isArray(fn.parameters?.required) ? fn.parameters.required.filter((x): x is string => typeof x === "string") : [];
    out.set(fn.name, req);
  }
  return out;
}

/** schema and denied checks for one call. Returns the parsed arguments when they are a JSON object. */
export function checkToolCall(call: ToolCall, index: number, declared: Map<string, string[]>, cfg: ToolCallsConfig): { hits: Hit[]; args: Record<string, unknown> | null; needsApproval: boolean } {
  const field = `tool_calls[${index}]`;
  const name = call.function?.name ?? "";
  const raw = call.function?.arguments ?? "";
  const schemaOwasp = ["LLM05", "LLM06", "ASI02"];
  let args: Record<string, unknown> | null = null;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) args = parsed as Record<string, unknown>;
  } catch {
    args = null; // not JSON: reported as tool_calls.schema below
  }
  const fail = (reason: string) => ({ hits: [hit("tool_calls.schema", cfg.action, schemaOwasp, field, { toolName: name, reason })], args, needsApproval: false });
  // A lookalike name ("send_email ", "ѕhell") is refused before anything else; the globs below see the canonical name.
  if (!TOOL_NAME.test(name)) return fail("tool name outside [A-Za-z0-9_-]{1,64}");
  const canonical = canonicalToolName(name);
  const required = declared.get(name);
  if (required === undefined) return fail("tool not declared in the request");
  if (args === null) return fail("arguments are not a JSON object");
  if (new TextEncoder().encode(raw).length > cfg.max_arguments_bytes) return fail(`arguments larger than ${cfg.max_arguments_bytes} bytes`);
  const missing = required.filter((k) => !(k in args!));
  if (missing.length) return fail(`missing required argument(s): ${missing.join(", ")}`);
  if (matchesAny(cfg.deny, canonical) || !matchesAny(cfg.allow, canonical)) {
    return { hits: [hit("tool_calls.denied", cfg.action, ["LLM06", "ASI02"], field, { toolName: name })], args, needsApproval: false };
  }
  return { hits: [], args, needsApproval: matchesAny(cfg.require_approval, canonical) };
}

/** A string that is itself a JSON object or array, parsed; undefined for any other string. */
function nestedJson(s: string): object | undefined {
  if (!/^\s*[[{]/.test(s)) return undefined;
  try {
    const v: unknown = JSON.parse(s);
    return v && typeof v === "object" ? v : undefined;
  } catch {
    return undefined; // looks like JSON but is not: the string itself was already collected
  }
}

/**
 * Every string value inside parsed arguments, joined: scanned in addition to the raw JSON (escapes removed).
 * A value that is itself JSON ('{"note":"\\u0074gc_..."}') is parsed and walked too, up to 3 levels deep.
 */
export function argumentStrings(args: unknown): string {
  const out: string[] = [];
  const walk = (v: unknown, depth: number) => {
    if (typeof v === "string") {
      out.push(v);
      const inner = depth < 3 ? nestedJson(v) : undefined;
      if (inner) walk(inner, depth + 1);
    } else if (Array.isArray(v)) v.forEach((x) => walk(x, depth));
    else if (v && typeof v === "object") Object.values(v).forEach((x) => walk(x, depth));
  };
  walk(args, 0);
  return out.join("\n");
}
