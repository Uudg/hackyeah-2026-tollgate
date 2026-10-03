// OpenAI-compatible upstream (Ollama's /v1 by default). The gateway always asks for a non-streamed completion;
// streaming to the caller is done by the gateway after the output path ran (SPEC §2.2 stage 6, buffered mode).
import { ChatCompletionSchema } from "../openai.ts";
import type { Upstream } from "./types.ts";

export function createHttpUpstream(): Upstream {
  return {
    name: "ollama",
    host: (policy) => {
      try { return new URL(policy.upstream.base_url).host; }
      catch { return policy.upstream.base_url; } // schema guarantees a URL; this is only for the type checker
    },
    async chat(req, ctx) {
      const u = ctx.policy.upstream;
      const headers: Record<string, string> = { "content-type": "application/json", "x-tollgate-agent": ctx.agentId };
      if (u.api_key) headers.authorization = `Bearer ${u.api_key}`;
      const signal = AbortSignal.any([ctx.signal, AbortSignal.timeout(u.timeout_ms)]);
      let res: Response;
      try {
        res = await fetch(`${u.base_url.replace(/\/$/, "")}/chat/completions`, { method: "POST", headers, signal, body: JSON.stringify({ ...req, stream: false }) });
      } catch (err) {
        return { ok: false, status: 504, message: `upstream unreachable: ${(err as Error).message}` };
      }
      if (!res.ok) return { ok: false, status: res.status, message: (await res.text()).slice(0, 300) };
      const parsed = ChatCompletionSchema.safeParse(await res.json());
      if (!parsed.success) return { ok: false, status: 502, message: "upstream returned a body that is not a chat completion" };
      return { ok: true, body: parsed.data };
    },
  };
}
