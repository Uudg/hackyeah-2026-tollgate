// Prometheus text for GET /metrics (SPEC §14). Prefix tollgate_.
import type { Ctx } from "../context.ts";
import type { Counter } from "./registry.ts";
import { posture } from "./posture.ts";

const esc = (v: string) => v.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
const labels = (l: Record<string, string>) => {
  const parts = Object.entries(l).map(([k, v]) => `${k}="${esc(v)}"`);
  return parts.length ? `{${parts.join(",")}}` : "";
};

export function prometheusText(ctx: Ctx): string {
  const out: string[] = [];
  const counter = (name: string, help: string, c: Counter) => {
    out.push(`# HELP tollgate_${name} ${help}`, `# TYPE tollgate_${name} counter`);
    for (const { labels: l, value } of c.values.values()) out.push(`tollgate_${name}${labels(l)} ${value}`);
  };
  const gauge = (name: string, help: string, rows: Array<[Record<string, string>, number]>) => {
    out.push(`# HELP tollgate_${name} ${help}`, `# TYPE tollgate_${name} gauge`);
    for (const [l, v] of rows) out.push(`tollgate_${name}${labels(l)} ${v}`);
  };
  const t = ctx.telemetry;
  counter("requests_total", "Chat requests by agent, decision, tier and direction.", t.counters.requests);
  counter("hits_total", "Control hits by control and rule.", t.counters.hits);
  counter("tokens_total", "Tokens by agent and direction.", t.counters.tokens);
  counter("cost_usd_total", "Estimated spend in USD by agent and model.", t.counters.cost);
  counter("upstream_errors_total", "Upstream failures by host.", t.counters.upstreamErrors);
  counter("policy_reloads_total", "Policy reloads by result.", t.counters.policyReloads);
  counter("feed_reloads_total", "Feed reloads by result.", t.counters.feedReloads);
  counter("approvals_total", "Approvals by status.", t.counters.approvals);
  counter("sessions_killed_total", "Sessions killed.", t.counters.sessionsKilled);
  counter("canary_trips_total", "Canary trips by kind.", t.counters.canaryTrips);

  out.push("# HELP tollgate_stage_latency_ms Per-stage latency in milliseconds.", "# TYPE tollgate_stage_latency_ms summary");
  for (const [stage, q] of Object.entries(t.latency())) {
    for (const [k, v] of [["0.5", q.p50], ["0.95", q.p95], ["0.99", q.p99]] as const) out.push(`tollgate_stage_latency_ms{stage="${stage}",quantile="${k}"} ${v}`);
    out.push(`tollgate_stage_latency_ms_count{stage="${stage}"} ${t.stages.get(stage)!.count}`);
  }
  const oh = t.overhead.quantiles();
  gauge("overhead_ms", "Gateway overhead (total minus upstream), milliseconds.", [[{ quantile: "0.5" }, oh.p50], [{ quantile: "0.95" }, oh.p95]]);

  const p = ctx.policy();
  const policy = p.value;
  const budgetRows: Array<[Record<string, string>, number]> = [];
  for (const agent of Object.keys(policy.agents)) {
    const limits = { ...policy.budgets.default, ...(policy.budgets.agents[agent] ?? {}) };
    for (const b of ctx.ledger.snapshot(agent, limits)) budgetRows.push([{ agent, window: b.window, kind: b.kind }, Math.round(b.ratio * 1000) / 1000]);
  }
  gauge("budget_used_ratio", "Budget used / limit per agent, window and kind.", budgetRows);
  gauge("circuit_state", "Upstream circuit state (0 closed, 1 half-open, 2 open).", ctx.circuit.states().map((s) => [{ host: s.host }, s.state === "closed" ? 0 : s.state === "half_open" ? 1 : 2]));
  gauge("policy_version_info", "Loaded policy.", [[{ version: String(policy.version), hash: p.hash }, 1]]);
  const f = ctx.feed();
  gauge("feed_version_info", "Loaded signature feed.", f ? [[{ hash: f.loaded.hash, entries: String(f.loaded.value.entries.length) }, 1]] : []);
  gauge("vulnerable_component", "Feed version-range matches.", ctx.state.versionMatches.map((m) => [{ component: m.component, cve: m.cve ?? "" }, 1]));
  gauge("throughput_rps", "Requests per second over the last 60 s.", [[{}, t.throughput()]]);
  gauge("redteam_bypass_rate", "Bypass rate per control in the latest red-team run.", Object.entries(ctx.state.redteamByControl).filter((e): e is [string, number] => e[1] !== null).map(([control, v]) => [{ control }, v]));
  gauge("posture_score", "Posture score 0-100.", [[{}, posture(ctx).score]]);
  return out.join("\n") + "\n";
}
