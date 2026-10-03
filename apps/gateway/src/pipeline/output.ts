// Stage 7: response-path controls on choices[].message.content and choices[].message.tool_calls[] (SPEC §2.2 stage 7).
// Order: every choice's content and every tool call gets its deterministic checks first; approvals are asked only
// when nothing in the whole completion blocks, so a human is never asked about a call that is refused anyway.
import { argumentStrings, checkToolCall, declaredTools, scanOutputField, type Hit, type ScanEnv } from "@tollgate/controls";
import { SEVERITY, type Direction } from "@tollgate/policy";
import type { ChatCompletion } from "../openai.ts";

export interface OutputHit { hit: Hit; direction: Direction }

export interface OutputResult {
  hits: OutputHit[];
  /** The completion with redactions applied (used only in enforce mode). */
  redacted: ChatCompletion;
  details: Record<string, unknown>;
}

export interface ApprovalGate {
  /** Resolves with the approval outcome; only called in enforce mode when no output hit blocks. */
  wait(toolName: string, args: unknown, timeoutMs: number): Promise<{ id: string; status: "approved" | "denied" | "expired" }>;
}

/** The only message fields forwarded. Anything else (reasoning_content, refusal, audio, legacy function_call) is removed. */
const KEEP = new Set(["role", "content", "tool_calls"]);
const APPROVAL_OWASP = ["LLM06", "ASI02", "ASI05"];

interface PendingApproval { toolName: string; args: unknown; field: string }

export async function runOutput(completion: ChatCompletion, requestTools: unknown[], system: string, env: ScanEnv, enforce: boolean, gate: ApprovalGate): Promise<OutputResult> {
  const hits: OutputHit[] = [];
  const details: Record<string, unknown> = {};
  const redacted: ChatCompletion = structuredClone(completion);
  const cfg = env.policy.controls.tool_calls;
  const declared = declaredTools(requestTools);
  const pending: PendingApproval[] = [];
  const dropped: string[] = [];
  for (const [ci, choice] of completion.choices.entries()) {
    const out = redacted.choices[ci]!;
    const content = choice.message.content;
    if (typeof content === "string" && content) {
      const r = scanOutputField(content, `choices[${ci}].message.content`, env, { surface: "response", system });
      hits.push(...r.hits.map((hit) => ({ hit, direction: "response" as const })));
      if (r.redacted !== null) out.message.content = r.redacted;
    }

    // Extra message fields: text ones are scanned like content (a canary in reasoning_content is still a leak), then
    // every extra field is removed. A legacy function_call would skip tool-call gating entirely: it is a block.
    const outMsg = out.message as Record<string, unknown>;
    for (const [key, value] of Object.entries(choice.message as Record<string, unknown>)) {
      if (KEEP.has(key)) continue;
      const fieldName = `choices[${ci}].message.${key}`;
      if (key === "function_call" && value !== null && value !== undefined && cfg.enabled) {
        const toolName = (value as { name?: unknown }).name;
        hits.push({ hit: { controlId: "tool_calls", ruleId: "tool_calls.schema", action: "block", owasp: ["LLM05", "LLM06", "ASI02"], span: { start: 0, end: 0, field: fieldName }, details: { toolName: typeof toolName === "string" ? toolName : null, reason: "legacy function_call is not supported; use tool_calls" } }, direction: "tool_call" });
      } else if (typeof value === "string" && value) {
        const r = scanOutputField(value, fieldName, env, { surface: "response", system });
        hits.push(...r.hits.map((hit) => ({ hit, direction: "response" as const })));
      }
      delete outMsg[key];
      dropped.push(fieldName);
    }

    for (const [ti, call] of (choice.message.tool_calls ?? []).entries()) {
      const callHits: Hit[] = [];
      let args: Record<string, unknown> | null = null;
      let needsApproval = false;
      if (cfg.enabled) {
        const g = checkToolCall(call, ti, declared, cfg);
        callHits.push(...g.hits);
        args = g.args;
        needsApproval = g.needsApproval;
      }
      const raw = call.function.arguments;
      const scan = scanOutputField(raw, `choices[${ci}].message.tool_calls[${ti}].function.arguments`, env, {
        surface: "tool_call", system, argumentStrings: args ? argumentStrings(args) : undefined,
      });
      callHits.push(...scan.hits);
      if (scan.redacted !== null) out.message.tool_calls![ti]!.function.arguments = scan.redacted;
      if (needsApproval) pending.push({ toolName: call.function.name, args, field: `tool_calls[${ti}]` });
      hits.push(...callHits.map((hit) => ({ hit, direction: "tool_call" as const })));
    }
  }
  if (dropped.length) details.droppedFields = dropped;

  const blocking = hits.some((h) => SEVERITY[h.hit.action] >= SEVERITY.block);
  if (pending.length && !blocking) {
    const approvalHit = (ruleId: string, p: PendingApproval, approvalId?: string): OutputHit => ({
      hit: { controlId: "tool_calls", ruleId, action: "block", owasp: APPROVAL_OWASP, span: { start: 0, end: 0, field: p.field }, details: { toolName: p.toolName, ...(approvalId ? { approvalId } : {}) } },
      direction: "tool_call",
    });
    if (!enforce) {
      // Monitor mode never waits for a human: record what would have been asked.
      for (const p of pending) hits.push(approvalHit("tool_calls.approval_required", p));
    } else {
      // Parallel calls are asked for together, so the wait is one timeout, not one per call.
      const results = await Promise.all(pending.map((p) => gate.wait(p.toolName, p.args, cfg.approval_timeout_ms)));
      details.approvalId = results[0]!.id;
      if (results.length > 1) details.approvalIds = results.map((a) => a.id);
      for (const [i, a] of results.entries()) {
        if (a.status === "denied") hits.push(approvalHit("tool_calls.approval_denied", pending[i]!, a.id));
        if (a.status === "expired") hits.push(approvalHit("tool_calls.approval_timeout", pending[i]!, a.id));
      }
    }
  }

  // logprobs repeat every generated token in clear text: once anything was redacted they would undo it.
  if (hits.some((h) => SEVERITY[h.hit.action] >= SEVERITY.redact)) {
    for (const c of redacted.choices) {
      const rec = c as Record<string, unknown>;
      if ("logprobs" in rec) { delete rec.logprobs; details.logprobsDropped = true; }
    }
  }
  return { hits, redacted, details };
}
