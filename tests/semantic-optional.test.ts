// The optional jailbreak model (semantic.jailbreak_model) must never take the gateway down: with policy.strict.yaml
// (fail_mode: closed) and granite3-guardian:2b not pulled, requests are still classified by Llama Guard alone.
// A stub Ollama answers for Llama Guard and the judge and returns 404 for the jailbreak model, like a real Ollama
// does for a model that was never pulled.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { join } from "node:path";
import { chat, getRecord, ROOT, startGateway, type TestGateway } from "./harness/gateway.ts";

let stub: ReturnType<typeof Bun.serve>;
let tg: TestGateway;
const calls: string[] = [];

beforeAll(() => {
  stub = Bun.serve({
    port: 0,
    async fetch(req) {
      const url = new URL(req.url);
      if (url.pathname === "/api/tags") return Response.json({ models: [{ name: "llama-guard3:1b" }, { name: "llama3.2:3b" }] });
      if (url.pathname === "/api/chat") {
        const body = (await req.json()) as { model: string };
        calls.push(body.model);
        if (body.model === "llama-guard3:1b") return Response.json({ message: { content: "safe" } });
        if (body.model === "llama3.2:3b") return Response.json({ message: { content: JSON.stringify({ verdict: "allow", confidence: 0.9, category: "none", reason: "ok" }) } });
        return Response.json({ error: `model "${body.model}" not found, try pulling it first` }, { status: 404 });
      }
      return new Response("not found", { status: 404 });
    },
  });
  tg = startGateway({ policyPath: join(ROOT, "policy.strict.yaml"), ollamaUrl: `http://localhost:${stub.port}` });
});
afterAll(() => { tg.stop(); stub.stop(true); });

describe("deterministic · optional jailbreak model missing", () => {
  test("strict preset still classifies with Llama Guard and lets a clean request through", async () => {
    const p = tg.gw.getPolicy().value;
    expect(p.semantic.fail_mode).toBe("closed");
    expect(p.semantic.jailbreak_model).toBe("granite3-guardian:2b");
    const r = await chat(tg, "What is the settlement date for the March supplier batch?");
    expect(r.status).toBe(200);
    expect(r.headers.get("x-tollgate-decision")).toBe("allow");
    const rec = await getRecord(tg, r.headers.get("x-tollgate-event"));
    expect(rec.hits.some((h) => h.ruleId === "semantic.unavailable")).toBe(false);
    expect(JSON.stringify(rec.details)).toContain("jailbreak:unavailable");
    expect(calls).toContain("granite3-guardian:2b");
  });

  test("/healthz reports the missing optional model as WARN", async () => {
    const h = (await (await fetch(`${tg.url}/healthz`)).json()) as { models: { classifier: boolean; jailbreak: boolean | null }; warnings: string[] };
    expect(h.models.classifier).toBe(true);
    expect(h.models.jailbreak).toBe(false);
    expect(h.warnings.some((w) => w.startsWith("WARN") && w.includes("granite3-guardian:2b"))).toBe(true);
  });

  test("the classifier itself failing still triggers fail_mode closed", async () => {
    const down = startGateway({ policyPath: join(ROOT, "policy.strict.yaml"), ollamaUrl: "http://127.0.0.1:9" });
    try {
      const r = await chat(down, "What is the settlement date for the March supplier batch?");
      expect(r.status).toBe(403);
      expect(r.headers.get("x-tollgate-rule")).toBe("semantic.unavailable");
    } finally { down.stop(); }
  });
});
