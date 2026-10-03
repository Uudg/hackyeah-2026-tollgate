// Stage 7: response-path controls on choices[].message.content and choices[].message.tool_calls[] (SPEC §2.2 stage 7).
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
  /** Resolves with the approval outcome; only called in enforce mode for calls with no other blocking hit. */
  wait(toolName: string, args: unknown, timeoutMs: number): Promise<{ id: string; status: "approved" | "denied" | "expired" }>;
}

export async function runOutput(completion: ChatCompletion, requestTools: unknown[], system: string, env: ScanEnv, enforce: boolean, gate: ApprovalGate): Promise<OutputResult> {
  const hits: OutputHit[] = [];
  const details: Record<string, unknown> = {};
  const redacted: ChatCompletion = structuredClone(completion);
  const cfg = env.policy.controls.tool_calls;
  const declared = declaredTools(requestTools);
  for (const [ci, choice] of completion.choices.entries()) {
    const out = redacted.choices[ci]!;
    const content = choice.message.content;
    if (typeof content === "string" && content) {
      const r = scanOutputField(content, `choices[${ci}].message.content`, env, { surface: "response", system });
      hits.push(...r.hits.map((hit) => ({ hit, direction: "response" as const })));
      if (r.redacted !== null) out.message.content = r.redacted;
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
      const blocking = callHits.some((h) => SEVERITY[h.action] >= SEVERITY.block);
      if (needsApproval && !blocking) {
        const owasp = ["LLM06", "ASI02", "ASI05"];
        const field = `tool_calls[${ti}]`;
        if (!enforce) {
          // Monitor mode never waits for a human: record what would have been asked.
          callHits.push({ controlId: "tool_calls", ruleId: "tool_calls.approval_required", action: "block", owasp, span: { start: 0, end: 0, field }, details: { toolName: call.function.name } });
        } else {
          const a = await gate.wait(call.function.name, args, cfg.approval_timeout_ms);
          details.approvalId = a.id;
          if (a.status === "denied") callHits.push({ controlId: "tool_calls", ruleId: "tool_calls.approval_denied", action: "block", owasp, span: { start: 0, end: 0, field }, details: { toolName: call.function.name, approvalId: a.id } });
          if (a.status === "expired") callHits.push({ controlId: "tool_calls", ruleId: "tool_calls.approval_timeout", action: "block", owasp, span: { start: 0, end: 0, field }, details: { toolName: call.function.name, approvalId: a.id } });
        }
      }
      hits.push(...callHits.map((hit) => ({ hit, direction: "tool_call" as const })));
    }
  }
  return { hits, redacted, details };
}
