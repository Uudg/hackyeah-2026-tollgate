// Gateway overhead (SPEC §11.2, §14). `bun test tests/latency.test.ts` asserts the tier-0 budget;
// `bun run bench` (this file with --bench) prints the numbers for the README with more requests and a throughput run.
import { createEchoUpstream } from "../apps/gateway/src/upstream/echo.ts";
import { chat, deepSet, getRecord, startGateway, type TestGateway } from "./harness/gateway.ts";
import { missingModels, skipMessage } from "./harness/ollama.ts";

const BENCH = process.argv.includes("--bench");
const PROMPT = "Summarise our Q3 treasury notes in three bullet points, keep it short and plain.";

/** The same prompt is sent many times; the loop breaker and the rpm limit would stop it after a few. */
const NO_LIMITS = { "budgets.loop_breaker.enabled": false, "budgets.default.requests_per_minute": 1_000_000, "budgets.default.tokens_per_hour": 1_000_000_000 };

interface Stats { p50: number; p95: number; p99: number; mean: number }
const stats = (xs: number[]): Stats => {
  const s = [...xs].sort((a, b) => a - b);
  const q = (p: number) => s[Math.min(s.length - 1, Math.floor(p * s.length))]!;
  return { p50: q(0.5), p95: q(0.95), p99: q(0.99), mean: xs.reduce((a, b) => a + b, 0) / xs.length };
};
const fmt = (s: Stats) => `p50 ${s.p50.toFixed(2)}  p95 ${s.p95.toFixed(2)}  p99 ${s.p99.toFixed(2)}  mean ${s.mean.toFixed(2)} ms`;

/** A bare HTTP server that answers like the echo upstream: the baseline with no controls at all. */
function directEcho() {
  const echo = createEchoUpstream();
  return Bun.serve({
    port: 0,
    fetch: async (req) => {
      const body = (await req.json()) as Parameters<typeof echo.chat>[0];
      const r = await echo.chat(body, { echo: null, agentId: "bench", signal: AbortSignal.timeout(5000) } as Parameters<typeof echo.chat>[1]);
      return Response.json(r.ok ? r.body : { error: r.message });
    },
  });
}

async function timeRequests(n: number, send: () => Promise<unknown>): Promise<number[]> {
  for (let i = 0; i < 10; i++) await send(); // warm-up: JIT, regex compilation, SQLite statement cache
  const out: number[] = [];
  for (let i = 0; i < n; i++) {
    const t = performance.now();
    await send();
    out.push(performance.now() - t);
  }
  return out;
}

/** Overhead run: n tier-0-only requests through the gateway vs n direct to the echo server. */
export async function measureOverhead(tg: TestGateway, n: number) {
  const direct = directEcho();
  const key = tg.keyFor("demo-agent");
  const body = JSON.stringify({ model: "llama3.2:3b", messages: [{ role: "user", content: PROMPT }] });
  const directMs = await timeRequests(n, () => fetch(`http://127.0.0.1:${direct.port}/v1/chat/completions`, { method: "POST", body }).then((r) => r.text()));
  const tier0: number[] = [];
  const gatewayMs = await timeRequests(n, async () => {
    const res = await fetch(`${tg.url}/v1/chat/completions`, { method: "POST", headers: { authorization: `Bearer ${key}`, "content-type": "application/json" }, body });
    await res.text();
    const lat = res.headers.get("x-tollgate-latency") ?? "";
    const m = /tier0=([\d.]+)/.exec(lat);
    if (m) tier0.push(Number(m[1]));
  });
  direct.stop(true);
  const d = stats(directMs);
  const g = stats(gatewayMs);
  return { direct: d, gateway: g, overhead: { p50: g.p50 - d.p50, p95: g.p95 - d.p95 }, tier0: stats(tier0.slice(10)) };
}

/** Throughput: `concurrency` clients sending for `seconds`. */
async function throughput(tg: TestGateway, concurrency: number, seconds: number) {
  const key = tg.keyFor("research-bot");
  const end = performance.now() + seconds * 1000;
  let done = 0;
  let non200 = 0;
  const worker = async (w: number) => {
    let i = 0;
    while (performance.now() < end) {
      // Distinct bodies so the loop breaker never fires.
      const body = JSON.stringify({ model: "llama3.2:3b", messages: [{ role: "user", content: `${PROMPT} worker ${w} request ${i++}` }] });
      const res = await fetch(`${tg.url}/v1/chat/completions`, { method: "POST", headers: { authorization: `Bearer ${key}`, "content-type": "application/json" }, body });
      await res.text();
      if (res.status !== 200) non200++;
      done++;
    }
  };
  await Promise.all(Array.from({ length: concurrency }, (_, w) => worker(w)));
  return { rps: done / seconds, non200 };
}

if (BENCH) {
  // Limits raised for the bench: rpm and token budgets would turn the throughput run into a 429 test.
  const tg = startGateway();
  tg.gw.setPolicy(deepSet(tg.basePolicy, { ...NO_LIMITS, "budgets.agents.research-bot.requests_per_minute": 1_000_000, "budgets.agents.research-bot.tokens_per_hour": 1_000_000_000 }));
  const r = await measureOverhead(tg, 1000);
  console.log(`Tollgate bench (${process.platform} ${process.arch}, bun ${Bun.version}), 1000 sequential requests, echo upstream, semantic tiers off`);
  console.log(`  direct echo      ${fmt(r.direct)}`);
  console.log(`  through gateway  ${fmt(r.gateway)}`);
  console.log(`  overhead         p50 ${r.overhead.p50.toFixed(2)}  p95 ${r.overhead.p95.toFixed(2)} ms`);
  console.log(`  tier-0 stage     ${fmt(r.tier0)}`);
  for (const c of [1, 8, 32]) {
    const t = await throughput(tg, c, 3);
    console.log(`  throughput c=${String(c).padEnd(3)} ${t.rps.toFixed(0)} req/s (${t.non200} non-200)`);
  }
  tg.stop();
  process.exit(0);
} else {
  const { afterAll, beforeAll, expect, test } = await import("bun:test");
  let tg: TestGateway;
  beforeAll(() => {
    tg = startGateway();
    tg.gw.setPolicy(deepSet(tg.basePolicy, NO_LIMITS));
  });
  afterAll(() => tg.stop());

  test("deterministic: tier-0 p95 < 5 ms over 100 requests, overhead printed", async () => {
    const r = await measureOverhead(tg, 100);
    console.log(`direct ${fmt(r.direct)}\ngateway ${fmt(r.gateway)}\noverhead p50 ${r.overhead.p50.toFixed(2)} ms, p95 ${r.overhead.p95.toFixed(2)} ms\ntier0 ${fmt(r.tier0)}`);
    expect(r.tier0.p95).toBeLessThan(5);
  }, 30_000);

  test("deterministic: every stage is recorded in the decision record", async () => {
    const res = await chat(tg, PROMPT);
    const rec = await getRecord(tg, res.headers.get("x-tollgate-event"));
    for (const k of ["auth", "budget", "tier0", "tier1", "tier2", "upstream", "output", "total"] as const) expect(typeof rec.latencyMs[k]).toBe("number");
    expect(rec.latencyMs.total).toBeGreaterThanOrEqual(rec.latencyMs.tier0);
  });

  const missing = await missingModels(["llama-guard3:1b"]);
  if (missing.length) test.skip(`[model] tier-1 latency — ${skipMessage(missing)}`, () => {});
  else test("[model] tier-1 latency with llama-guard3:1b", async () => {
    tg.gw.setPolicy(deepSet(tg.basePolicy, { ...NO_LIMITS, "semantic.enabled": true }));
    const t1: number[] = [];
    for (let i = 0; i < 10; i++) {
      const res = await chat(tg, `${PROMPT} (${i})`);
      t1.push((await getRecord(tg, res.headers.get("x-tollgate-event"))).latencyMs.tier1);
    }
    console.log(`tier1 (llama-guard3:1b, warm after the first call) ${fmt(stats(t1.slice(1)))}`);
    expect(stats(t1.slice(1)).p50).toBeGreaterThan(0);
  }, 120_000);
}
