// Latency reservoirs, counters and gauges (SPEC §14). Percentiles are computed on demand from ring buffers.
import { STAGES, type DecisionRecord } from "@tollgate/policy";

class Reservoir {
  private buf: number[] = [];
  private i = 0;
  count = 0;
  constructor(private size: number) {}
  add(v: number) {
    this.count++;
    if (this.buf.length < this.size) this.buf.push(v);
    else { this.buf[this.i] = v; this.i = (this.i + 1) % this.size; }
  }
  quantiles(): { p50: number; p95: number; p99: number; n: number } {
    if (this.buf.length === 0) return { p50: 0, p95: 0, p99: 0, n: 0 };
    const s = [...this.buf].sort((a, b) => a - b);
    const q = (p: number) => Math.round(s[Math.min(s.length - 1, Math.floor(p * s.length))]! * 1000) / 1000;
    return { p50: q(0.5), p95: q(0.95), p99: q(0.99), n: this.buf.length };
  }
  resize(size: number) { this.size = size; }
}

/** Counter keyed by a label set, rendered as Prometheus series. */
export class Counter {
  readonly values = new Map<string, { labels: Record<string, string>; value: number }>();
  inc(labels: Record<string, string>, by = 1) {
    const key = JSON.stringify(labels);
    const cur = this.values.get(key);
    if (cur) cur.value += by; else this.values.set(key, { labels, value: by });
  }
}

export class Telemetry {
  readonly stages = new Map<string, Reservoir>();
  readonly overhead: Reservoir;
  readonly counters = {
    requests: new Counter(), hits: new Counter(), tokens: new Counter(), cost: new Counter(), upstreamErrors: new Counter(),
    policyReloads: new Counter(), feedReloads: new Counter(), approvals: new Counter(), sessionsKilled: new Counter(), canaryTrips: new Counter(),
  };
  /** Recent decisions for the 5-minute window and throughput: [ts ms, record summary]. */
  private recent: Array<{ ts: number; agentId: string; decision: string; tier: string; direction: string }> = [];
  readonly startedAt = Date.now();

  constructor(size: number) {
    for (const s of STAGES) this.stages.set(s, new Reservoir(size));
    this.overhead = new Reservoir(size);
  }

  observe(r: DecisionRecord) {
    for (const s of STAGES) this.stages.get(s)!.add(r.latencyMs[s]);
    this.overhead.add(Math.max(0, r.latencyMs.total - r.latencyMs.upstream));
    const tier = r.tier === null ? "-" : String(r.tier);
    this.counters.requests.inc({ agent: r.agentId, decision: r.decision, tier, direction: r.direction });
    for (const h of r.hits) this.counters.hits.inc({ control: h.controlId, rule: h.ruleId });
    if (r.tokensIn) this.counters.tokens.inc({ agent: r.agentId, direction: "in" }, r.tokensIn);
    if (r.tokensOut) this.counters.tokens.inc({ agent: r.agentId, direction: "out" }, r.tokensOut);
    if (r.costUsd) this.counters.cost.inc({ agent: r.agentId, model: r.model }, r.costUsd);
    const now = Date.now();
    this.recent.push({ ts: now, agentId: r.agentId, decision: r.decision, tier, direction: r.direction });
    if (this.recent.length > 50_000 || (this.recent[0] && now - this.recent[0].ts > 3_600_000)) this.recent = this.recent.filter((x) => now - x.ts <= 600_000);
  }

  window(ms: number) {
    const since = Date.now() - ms;
    const items = this.recent.filter((x) => x.ts >= since);
    const by = (k: "decision" | "tier" | "agentId") => items.reduce<Record<string, number>>((acc, x) => { acc[x[k]] = (acc[x[k]] ?? 0) + 1; return acc; }, {});
    return { total: items.length, byDecision: by("decision"), byTier: by("tier"), byAgent: by("agentId") };
  }

  throughput(): number {
    const since = Date.now() - 60_000;
    return Math.round((this.recent.filter((x) => x.ts >= since).length / 60) * 100) / 100;
  }

  latency() {
    return Object.fromEntries([...this.stages].map(([k, r]) => [k, r.quantiles()]));
  }
}
