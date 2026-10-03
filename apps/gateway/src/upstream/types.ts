// Where clean traffic goes (SPEC §2.1): the configured OpenAI-compatible upstream, or the built-in echo.
import type { Policy } from "@tollgate/policy";
import type { ChatCompletion, ChatRequest } from "../openai.ts";

export interface UpstreamContext {
  policy: Policy;
  agentId: string;
  /** X-Tollgate-Echo header value; only the echo upstream reads it. */
  echo: string | null;
  signal: AbortSignal;
}

export type UpstreamResult =
  | { ok: true; body: ChatCompletion }
  | { ok: false; status: number; message: string };

export interface Upstream {
  readonly name: "ollama" | "echo";
  /** Host key for the circuit breaker. */
  host(policy: Policy): string;
  chat(req: ChatRequest, ctx: UpstreamContext): Promise<UpstreamResult>;
}
