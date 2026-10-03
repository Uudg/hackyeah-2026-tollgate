// Budget windows (SPEC §5.3): one row per (agent, minute|hour|day window). Pre-check before the pipeline,
// commit after the response.
import type { BudgetLimits } from "@tollgate/policy";
import type { Db } from "../db/client.ts";

const SIZE = { minute: 60, hour: 3600, day: 86400 } as const;
type Kind = keyof typeof SIZE;
const KINDS = Object.keys(SIZE) as Kind[];

export interface Usage { requests: number; tokens_in: number; tokens_out: number; usd: number; compute_ms: number }
export interface Reservation { atS: number; estimate: Usage }
export interface Exceeded { ruleId: string; retryAfterS: number; used: number; limit: number }

const windowStart = (kind: Kind, nowS: number) => Math.floor(nowS / SIZE[kind]) * SIZE[kind];

export class Ledger {
  constructor(private db: Db) {}

  usage(agentId: string, kind: Kind, nowS = Date.now() / 1000): Usage {
    const r = this.db.query("SELECT requests, tokens_in, tokens_out, usd, compute_ms FROM usage_windows WHERE agent_id = ? AND kind = ? AND window_start = ?")
      .get(agentId, kind, windowStart(kind, nowS)) as Usage | null;
    return r ?? { requests: 0, tokens_in: 0, tokens_out: 0, usd: 0, compute_ms: 0 };
  }

  /** First failing check in SPEC order: requests/minute → tokens/hour → USD/day → compute seconds/hour. */
  precheck(agentId: string, limits: BudgetLimits, est: { tokensIn: number; maxTokens: number; costUsd: number }): Exceeded | null {
    const nowS = Date.now() / 1000;
    const retry = (kind: Kind) => Math.max(1, Math.ceil(windowStart(kind, nowS) + SIZE[kind] - nowS));
    const minute = this.usage(agentId, "minute", nowS);
    if (minute.requests + 1 > limits.requests_per_minute) return { ruleId: "budget.requests_per_minute", retryAfterS: retry("minute"), used: minute.requests, limit: limits.requests_per_minute };
    const hour = this.usage(agentId, "hour", nowS);
    const tokens = hour.tokens_in + hour.tokens_out;
    if (tokens + est.tokensIn + est.maxTokens > limits.tokens_per_hour) return { ruleId: "budget.tokens_per_hour", retryAfterS: retry("hour"), used: tokens, limit: limits.tokens_per_hour };
    const day = this.usage(agentId, "day", nowS);
    if (est.costUsd > 0 && day.usd + est.costUsd > limits.usd_per_day) return { ruleId: "budget.usd_per_day", retryAfterS: retry("day"), used: day.usd, limit: limits.usd_per_day };
    if (hour.compute_ms / 1000 >= limits.compute_seconds_per_hour) return { ruleId: "budget.compute_seconds_per_hour", retryAfterS: retry("hour"), used: hour.compute_ms / 1000, limit: limits.compute_seconds_per_hour };
    return null;
  }

  /**
   * Add usage to the agent's minute/hour/day windows. `atS` pins the windows (seconds); a settle uses the
   * reservation's time so the correction lands in the same windows as the reservation.
   */
  commit(agentId: string, u: Usage, atS = Date.now() / 1000): void {
    const q = this.db.query(`INSERT INTO usage_windows (agent_id, kind, window_start, requests, tokens_in, tokens_out, usd, compute_ms)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (agent_id, kind, window_start) DO UPDATE SET requests = requests + excluded.requests,
        tokens_in = tokens_in + excluded.tokens_in, tokens_out = tokens_out + excluded.tokens_out,
        usd = usd + excluded.usd, compute_ms = compute_ms + excluded.compute_ms`);
    this.db.transaction(() => {
      for (const kind of KINDS) q.run(agentId, kind, windowStart(kind, atS), u.requests, u.tokens_in, u.tokens_out, u.usd, Math.round(u.compute_ms));
    })();
  }

  /**
   * Book the pre-check estimate right away. The caller runs it in the same synchronous step as precheck(), so
   * concurrent requests see each other: without it every request in flight passed the same pre-check.
   */
  reserve(agentId: string, estimate: Usage): Reservation {
    const atS = Date.now() / 1000;
    this.commit(agentId, estimate, atS);
    return { atS, estimate };
  }

  /** Replace a reservation with what the request really used (actual − estimate, in the reservation's windows). */
  settle(agentId: string, r: Reservation, actual: Usage): void {
    const e = r.estimate;
    const delta: Usage = {
      requests: actual.requests - e.requests, tokens_in: actual.tokens_in - e.tokens_in, tokens_out: actual.tokens_out - e.tokens_out,
      usd: actual.usd - e.usd, compute_ms: Math.round(actual.compute_ms) - Math.round(e.compute_ms),
    };
    if (Object.values(delta).every((v) => v === 0)) return;
    this.commit(agentId, delta, r.atS);
  }

  /** Windows older than two days are dropped (called every 10 minutes). */
  prune(): void {
    this.db.query("DELETE FROM usage_windows WHERE window_start < ?").run(Math.floor(Date.now() / 1000) - 2 * 86400);
  }

  /** Current usage ratios for /admin/metrics. */
  snapshot(agentId: string, limits: BudgetLimits): Array<{ agentId: string; window: string; kind: string; used: number; limit: number; ratio: number }> {
    const hour = this.usage(agentId, "hour"), day = this.usage(agentId, "day"), minute = this.usage(agentId, "minute");
    const row = (window: string, kind: string, used: number, limit: number) => ({ agentId, window, kind, used, limit, ratio: limit > 0 ? used / limit : 0 });
    return [
      row("minute", "requests", minute.requests, limits.requests_per_minute),
      row("hour", "tokens", hour.tokens_in + hour.tokens_out, limits.tokens_per_hour),
      row("day", "usd", Math.round(day.usd * 1e6) / 1e6, limits.usd_per_day),
      row("hour", "compute_seconds", hour.compute_ms / 1000, limits.compute_seconds_per_hour),
    ];
  }
}
