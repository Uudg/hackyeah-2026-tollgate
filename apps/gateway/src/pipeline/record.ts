// Decision record: collapse every hit into one verdict, persist it (audit chain + SQLite), publish it (SSE, metrics).
import { SEVERITY, type DecisionRecord, type Direction, type Hit, type StageLatency, type Tier } from "@tollgate/policy";
import type { Ctx } from "../context.ts";

export interface Entry { hit: Hit; tier: Tier; direction: Direction }

/** Highest severity wins; the first hit wins a tie (stage order = SPEC order). */
export function decide(entries: readonly Entry[]): Entry | null {
  let best: Entry | null = null;
  for (const e of entries) if (!best || SEVERITY[e.hit.action] > SEVERITY[best.hit.action]) best = e;
  return best;
}

export function latencyHeader(l: StageLatency): string {
  const r = (n: number) => Math.round(n * 100) / 100;
  return `auth=${r(l.auth)};budget=${r(l.budget)};tier0=${r(l.tier0)};tier1=${r(l.tier1)};tier2=${r(l.tier2)};upstream=${r(l.upstream)};output=${r(l.output)};total=${r(l.total)}`;
}

export function tollgateHeaders(r: DecisionRecord): Record<string, string> {
  return {
    "X-Tollgate-Decision": r.decision,
    "X-Tollgate-Rule": r.ruleId ?? "-",
    "X-Tollgate-Tier": r.tier === null ? "-" : String(r.tier),
    "X-Tollgate-Policy": r.policyVersion,
    "X-Tollgate-Event": r.id,
    "X-Tollgate-Latency": latencyHeader(r.latencyMs),
  };
}

const insertSql = `INSERT INTO events (id, ts, agent_id, session_id, model, direction, decision, enforced, tier, rule_id, control_id, owasp,
  policy_version, feed_version, latency_total_ms, latency_json, tokens_in, tokens_out, cost_usd, compute_seconds, http_status,
  excerpt_redacted, hits_json, details_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

export function persist(ctx: Ctx, r: DecisionRecord): void {
  ctx.audit.append(r);
  ctx.db.query(insertSql).run(
    r.id, r.ts, r.agentId, r.sessionId, r.model, r.direction, r.decision, r.enforced ? 1 : 0, r.tier, r.ruleId, r.controlId,
    r.owasp.join(","), r.policyVersion, r.feedVersion, r.latencyMs.total, JSON.stringify(r.latencyMs), r.tokensIn, r.tokensOut,
    r.costUsd, r.computeSeconds, r.httpStatus, r.excerptRedacted, JSON.stringify(r.hits), JSON.stringify(r.details),
  );
  ctx.telemetry.observe(r);
  ctx.bus.emit("decision", r, r.id);
}

interface EventRow {
  id: string; ts: string; agent_id: string; session_id: string; model: string; direction: Direction; decision: DecisionRecord["decision"];
  enforced: number; tier: number | null; rule_id: string | null; control_id: string | null; owasp: string; policy_version: string;
  feed_version: string | null; latency_json: string; tokens_in: number; tokens_out: number; cost_usd: number; compute_seconds: number;
  http_status: number; excerpt_redacted: string | null; hits_json: string; details_json: string;
}

/** SQLite row → DecisionRecord (the audit file holds the same record plus chain fields). */
export function rowToRecord(row: unknown): DecisionRecord {
  const r = row as EventRow;
  return {
    id: r.id, ts: r.ts, agentId: r.agent_id, sessionId: r.session_id, model: r.model ?? "", direction: r.direction, decision: r.decision,
    enforced: r.enforced === 1, tier: r.tier as Tier, ruleId: r.rule_id, controlId: r.control_id, owasp: r.owasp ? r.owasp.split(",") : [],
    hits: JSON.parse(r.hits_json) as Hit[], policyVersion: r.policy_version, policyDeclaredVersion: (JSON.parse(r.details_json) as { policyDeclaredVersion?: number }).policyDeclaredVersion ?? 0,
    feedVersion: r.feed_version, latencyMs: JSON.parse(r.latency_json) as StageLatency, excerptRedacted: r.excerpt_redacted,
    tokensIn: r.tokens_in, tokensOut: r.tokens_out, costUsd: r.cost_usd, computeSeconds: r.compute_seconds, httpStatus: r.http_status,
    details: JSON.parse(r.details_json) as Record<string, unknown>,
  };
}
