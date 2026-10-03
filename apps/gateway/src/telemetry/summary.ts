// JSON summary for GET /admin/metrics and the metrics.tick SSE event (SPEC §8).
import { limitsFor } from "@tollgate/policy";
import type { Ctx } from "../context.ts";
import { posture } from "./posture.ts";

export function metricsSummary(ctx: Ctx) {
  const t = ctx.telemetry;
  const policy = ctx.policy().value;
  const dayStart = Math.floor(Date.now() / 86_400_000) * 86400;
  const spendRows = ctx.db.query("SELECT agent_id, tokens_in, tokens_out, usd, compute_ms FROM usage_windows WHERE kind = 'day' AND window_start = ?").all(dayStart) as Array<{ agent_id: string; tokens_in: number; tokens_out: number; usd: number; compute_ms: number }>;
  const spend = Object.fromEntries(spendRows.map((r) => [r.agent_id, { usd: Math.round(r.usd * 1e6) / 1e6, tokensIn: r.tokens_in, tokensOut: r.tokens_out, computeSeconds: r.compute_ms / 1000 }]));
  const oh = t.overhead.quantiles();
  const circuit = ctx.circuit.states();
  return {
    window: "5m",
    requests: t.window(5 * 60_000),
    latency: t.latency(),
    throughput_rps: t.throughput(),
    overhead_ms: { p50: oh.p50, p95: oh.p95 },
    spend: { byAgent: spend },
    budgets: Object.keys(policy.agents).flatMap((a) => ctx.ledger.snapshot(a, limitsFor(policy, a))),
    circuit: circuit[0] ?? { host: ctx.upstream.host(policy), state: "closed" },
    posture: posture(ctx),
  };
}
