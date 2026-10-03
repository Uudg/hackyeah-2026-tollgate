// POST /v1/chat/completions and GET /v1/models (SPEC §8).
import { Hono } from "hono";
import { globMatch } from "@tollgate/controls";
import type { Ctx } from "../context.ts";
import { runChat, type ChatResponseOut } from "../pipeline/run.ts";
import { authenticate } from "../pipeline/identity.ts";

export function toResponse(out: ChatResponseOut): Response {
  if (out.stream) return new Response(out.stream, { status: out.status, headers: out.headers });
  return new Response(JSON.stringify(out.body), { status: out.status, headers: { ...out.headers, "content-type": "application/json" } });
}

export function chatRoutes(ctx: Ctx) {
  const app = new Hono();
  app.post("/v1/chat/completions", async (c) => {
    let body: unknown;
    try { body = await c.req.json(); }
    catch { return c.json({ error: { type: "invalid_request", message: "body is not valid JSON" } }, 400); }
    return toResponse(await runChat(ctx, { body, header: (n) => c.req.header(n) }));
  });
  app.get("/v1/models", async (c) => {
    const policy = ctx.policy().value;
    const auth = authenticate(c.req.header("authorization"), policy);
    if (!auth.ok) return c.json({ error: { type: "unauthorized", code: auth.ruleId, message: "missing or unknown agent key" } }, 401);
    const allowedFor = (m: string) => policy.models.allow.some((p) => globMatch(p, m)) && (!auth.id.agent.models || auth.id.agent.models.some((p) => globMatch(p, m)));
    let names = policy.models.allow.filter((m) => !m.includes("*"));
    if (ctx.upstream.name === "ollama") {
      try {
        const res = await fetch(`${ctx.opts.ollamaUrl}/api/tags`, { signal: AbortSignal.timeout(1000) });
        const tags = (await res.json()) as { models?: Array<{ name: string }> };
        names = [...new Set([...(tags.models ?? []).map((m) => m.name)])];
      } catch {
        // Upstream unreachable: fall back to the exact names in the allowlist.
      }
    }
    return c.json({ object: "list", data: names.filter(allowedFor).map((id) => ({ id, object: "model", owned_by: "tollgate", allowed: true })) });
  });
  return app;
}
