// Built-in upstream that needs no model (SPEC §2.1). Replies "OK: <last user message>", or whatever the
// X-Tollgate-Echo header asks for: { content?, tool_calls?, status?, delay_ms? } as JSON.
import { z } from "zod";
import { estimateTokens, messageText, ToolCallSchema, type ChatCompletion } from "../openai.ts";
import { sleep } from "../semantic/provider.ts";
import type { Upstream } from "./types.ts";

export const EchoSchema = z.object({
  content: z.string().optional(),
  tool_calls: z.array(ToolCallSchema).optional(),
  status: z.number().int().min(100).max(599).optional(),
  delay_ms: z.number().int().min(0).max(60_000).optional(),
});
export type EchoSpec = z.infer<typeof EchoSchema>;

/** Invalid header JSON is ignored and the default echo reply is used. */
export function parseEchoHeader(header: string | null): EchoSpec | null {
  if (!header) return null;
  try {
    const parsed = EchoSchema.safeParse(JSON.parse(header));
    return parsed.success ? parsed.data : null;
  } catch {
    return null; // not JSON: documented fallback to the default reply
  }
}

export function createEchoUpstream(): Upstream {
  return {
    name: "echo",
    host: () => "echo",
    async chat(req, ctx) {
      const spec = parseEchoHeader(ctx.echo);
      if (spec?.delay_ms) await sleep(spec.delay_ms, ctx.signal);
      if (spec?.status && spec.status >= 400) return { ok: false, status: spec.status, message: `echo upstream returned ${spec.status}` };
      const lastUser = [...req.messages].reverse().find((m) => m.role === "user");
      const toolCalls = spec?.tool_calls;
      const content = spec?.content ?? (toolCalls ? null : `OK: ${lastUser ? messageText(lastUser) : ""}`);
      const promptChars = req.messages.reduce((n, m) => n + messageText(m).length, 0);
      const outChars = (content ?? "").length + (toolCalls ? JSON.stringify(toolCalls).length : 0);
      const body: ChatCompletion = {
        id: `chatcmpl-echo-${crypto.randomUUID().slice(0, 8)}`,
        object: "chat.completion",
        created: Math.floor(Date.now() / 1000),
        model: req.model,
        choices: [{
          index: 0,
          message: { role: "assistant", content, ...(toolCalls ? { tool_calls: toolCalls } : {}) },
          finish_reason: toolCalls ? "tool_calls" : "stop",
        }],
        usage: { prompt_tokens: estimateTokens(promptChars), completion_tokens: estimateTokens(outChars), total_tokens: estimateTokens(promptChars) + estimateTokens(outChars) },
      };
      return { ok: true, body };
    },
  };
}
