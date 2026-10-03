// Tool-call gating (SPEC §7.5). Request side: tool definitions. Response side: each tool call the model made.
import { globMatch, type Action, type Hit } from "./types.ts";

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

export interface DefinitionCheck { hits: Hit[]; keep: boolean[] }

/** definition_invalid (block) and denied_definition (removed from the forwarded request). */
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
    if (cfg.deny.some((p) => globMatch(p, fn.name as string))) {
      hits.push(hit("tool_calls.denied_definition", "redact", ["LLM06", "ASI02"], `tools[${i}]`, { toolName: fn.name }));
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
  const required = declared.get(name);
  if (required === undefined) return fail("tool not declared in the request");
  if (args === null) return fail("arguments are not a JSON object");
  if (new TextEncoder().encode(raw).length > cfg.max_arguments_bytes) return fail(`arguments larger than ${cfg.max_arguments_bytes} bytes`);
  const missing = required.filter((k) => !(k in args!));
  if (missing.length) return fail(`missing required argument(s): ${missing.join(", ")}`);
  if (cfg.deny.some((p) => globMatch(p, name)) || !cfg.allow.some((p) => globMatch(p, name))) {
    return { hits: [hit("tool_calls.denied", cfg.action, ["LLM06", "ASI02"], field, { toolName: name })], args, needsApproval: false };
  }
  return { hits: [], args, needsApproval: cfg.require_approval.some((p) => globMatch(p, name)) };
}

/** Every string value inside parsed arguments, joined: scanned in addition to the raw JSON (escapes removed). */
export function argumentStrings(args: unknown): string {
  const out: string[] = [];
  const walk = (v: unknown) => {
    if (typeof v === "string") out.push(v);
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === "object") Object.values(v).forEach(walk);
  };
  walk(args);
  return out.join("\n");
}
