// Wire types for every /admin route the dashboard reads, written from docs/SPEC.md §8.
// DecisionRecord, Hit, Policy, SignatureEntry and the SSE event payloads come from @tollgate/policy and are not redefined here.
// Everything below is a typed ASSUMPTION where SPEC §8 gives only a prose shape; each one is marked "ASSUMPTION".
import type { DecisionRecord, Policy, SignatureEntry, Issue } from "@tollgate/policy";

export type Decision = DecisionRecord["decision"];
export type Mode = "monitor" | "enforce";

export const STAGES = ["auth", "budget", "tier0", "tier1", "tier2", "upstream", "output"] as const;
export type Stage = (typeof STAGES)[number];

/** The ten OWASP LLM and ten OWASP Agentic ids, in column order for the coverage matrix. */
export const OWASP_LLM = ["LLM01", "LLM02", "LLM03", "LLM04", "LLM05", "LLM06", "LLM07", "LLM08", "LLM09", "LLM10"] as const;
export const OWASP_ASI = ["ASI01", "ASI02", "ASI03", "ASI04", "ASI05", "ASI06", "ASI07", "ASI08", "ASI09", "ASI10"] as const;
export const OWASP_ALL: readonly string[] = [...OWASP_LLM, ...OWASP_ASI];

// ---------------------------------------------------------------------------------------------------------------------
// GET /admin/metrics and the `metrics.tick` SSE payload (SPEC §8: "the /admin/metrics summary")
// ---------------------------------------------------------------------------------------------------------------------
export interface StageStat { p50: number; p95: number; p99: number; n: number }
export interface BudgetUsage { agentId: string; window: string; used: number; limit: number; ratio: number; kind?: string }
export interface CircuitInfo { host: string; state: "closed" | "open" | "half_open" }
export interface AgentSpend { usd: number; tokensIn: number; tokensOut: number; computeSeconds: number }

export interface MetricsSummary {
  window: string; // "5m"
  requests: {
    total: number;
    byDecision: Partial<Record<Decision, number>>;
    byTier: Record<string, number>; // keys "0" | "1" | "2" | "null" (ASSUMPTION: string keys, JSON objects cannot have number keys)
    byAgent: Record<string, number>;
  };
  latency: Record<string, StageStat>; // keys are StageLatency fields incl. "total"
  throughput_rps: number;
  overhead_ms: { p50: number; p95: number };
  spend: { byAgent: Record<string, AgentSpend> };
  budgets: BudgetUsage[];
  // SPEC writes `circuit: { host, state }` (singular). ASSUMPTION: accept one object or an array.
  circuit: CircuitInfo | CircuitInfo[] | null;
  // ASSUMPTION: breakdown is a flat map of the SPEC §10.1 terms (coverage, mode, semantic, feed, resilience, audit, penalties) -> points.
  posture: { score: number; breakdown: Record<string, number> };
}

// ---------------------------------------------------------------------------------------------------------------------
// GET /admin/policy
// ---------------------------------------------------------------------------------------------------------------------
export interface PolicyHistoryRaw {
  hash: string;
  declared_version: number | null;
  loaded_ts: string;
  // The SQLite column is TEXT. ASSUMPTION: the gateway sends an array, a JSON string or a comma-joined string; gateway.ts normalises.
  changed_paths: string[] | string | null;
}
export interface PolicyHistoryItem { hash: string; declaredVersion: number | null; loadedTs: string; changedPaths: string[] }

export interface PolicyResponseRaw {
  hash: string;
  version: number;
  loadedAt: string;
  path: string;
  policy: Policy;
  changedPaths: string[];
  lastRejected: { ts: string; errors: string[] | Issue[] } | null;
  history: PolicyHistoryRaw[];
}
export interface PolicyInfo extends Omit<PolicyResponseRaw, "history" | "lastRejected"> {
  history: PolicyHistoryItem[];
  lastRejected: { ts: string; errors: string[] } | null;
}

// POST /admin/policy/validate -> { ok, errors }. SPEC does not fix the error element type.
// ASSUMPTION: errors are strings "path: message" or { path, message } objects; both are normalised to strings.
export interface ValidateResponseRaw { ok: boolean; errors?: (string | Issue)[] }
export interface ValidateResult { ok: boolean; errors: string[] }

// ---------------------------------------------------------------------------------------------------------------------
// GET /admin/feed
// ---------------------------------------------------------------------------------------------------------------------
export interface FeedVersionMatch { entryId: string; component: string; version: string; cve: string | null }
export interface FeedResponse {
  hash: string; // "f-<12 hex>"
  source: string;
  loadedAt: string;
  entries: SignatureEntry[];
  versionMatches: FeedVersionMatch[];
}

// ---------------------------------------------------------------------------------------------------------------------
// /admin/audit*
// ---------------------------------------------------------------------------------------------------------------------
export interface AuditQuery {
  limit?: number; cursor?: string; agent?: string; decision?: string; rule?: string; tier?: string;
  owasp?: string; direction?: string; from?: string; to?: string; q?: string;
}
// ASSUMPTION: `direction` is accepted as a filter by /admin/audit (SPEC §10 lists it as a dashboard filter, §8 does not list the query key).
export interface AuditPage { items: DecisionRecord[]; nextCursor: string | null }
export interface AuditVerify { ok: boolean; lines: number; firstBadLine: number | null; headHash: string }

// ---------------------------------------------------------------------------------------------------------------------
// Approvals, sessions, canaries
// ---------------------------------------------------------------------------------------------------------------------
export interface Approval {
  id: string; ts: string; agentId: string; sessionId: string; eventId: string | null; toolName: string;
  arguments: unknown; status: "pending" | "approved" | "denied" | "expired";
  resolvedTs: string | null; resolvedBy: string | null; note: string | null;
}
export interface KilledSession { session_id: string; agent_id: string; ts: string; reason: string; event_id: string | null }
// GET /admin/sessions/killed returns { items: KilledSession[] } with the SQLite column names; DELETE /admin/sessions/killed/:id returns { ok }.
export interface Canary {
  id: string; kind: string; label: string | null; token: string; created_ts: string;
  planted_in: string | null; tripped_count: number; last_tripped_ts: string | null;
}

// ---------------------------------------------------------------------------------------------------------------------
// Red team (SPEC §8 names RedteamRun / RedteamResult without fields; fields below follow the SQLite tables in §5.1)
// ---------------------------------------------------------------------------------------------------------------------
export interface RedteamConfig {
  seeds?: string[]; mutators?: string[]; control?: string; max_depth?: 1 | 2; max_attempts?: number;
  max_minutes?: number; agent?: string; concurrency?: number; include_model_mutators?: boolean;
}
export interface RedteamRun {
  id: string; startedTs: string; finishedTs: string | null; status: "running" | "done" | "aborted";
  policyVersion: string; attempts: number; bypasses: number; config: RedteamConfig | null;
}
export interface RedteamResult {
  id: string; runId: string; seedId: string; controlId: string; owasp: string[]; mutators: string[]; input: string;
  decision: Decision; ruleId: string | null; tier: number | null; bypass: boolean; generatedCasePath: string | null; ts: string;
}
export interface RedteamByControl { controlId: string; attempts: number; bypasses: number; bypassRate: number | null }
export interface RedteamStatus { run: RedteamRun | null; byControl: RedteamByControl[]; recent: RedteamResult[] }
// ASSUMPTION: the wire may use the snake_case SQLite names (started_ts, run_id, rule_id ...) or camelCase; gateway.ts accepts both.

// ---------------------------------------------------------------------------------------------------------------------
// GET /admin/coverage  (SPEC §8: "the coverage map (§10.2) with live enabled/action per control and bypass rate")
// Real shape (checked against the gateway): { controls: CoverageRow[], notCovered: string[], policyVersion }
// ---------------------------------------------------------------------------------------------------------------------
export interface CoverageRow {
  controlId: string;
  label?: string;
  parts?: string;
  policyKey?: string | null;
  tier: string; // "0" | "0/1/2" | "1" | "0 (output)"
  owasp: string[]; // every LLM and ASI id the control covers
  enabled: boolean;
  action: Decision | null; // null for implicit controls with no single action (budget)
  bypassRate: number | null;
}
export interface CoverageResponse { controls: CoverageRow[]; notCovered: string[]; policyVersion?: string }

// ---------------------------------------------------------------------------------------------------------------------
// POST /admin/playground
// ---------------------------------------------------------------------------------------------------------------------
export interface ChatMessage { role: "system" | "user" | "assistant" | "tool"; content: string; [k: string]: unknown }
export interface PlaygroundRequest {
  agentId: string; model: string; messages: ChatMessage[]; tools?: unknown[]; dry_run?: boolean;
  plant_canary?: boolean; session_id?: string;
  // The echo upstream override. The dashboard only fills `content` (UPSTREAM=echo test mode).
  echo?: { content?: string; tool_calls?: unknown[]; status?: number; delay_ms?: number };
}
export interface PlaygroundResponse {
  status: number;
  headers: { decision: string; rule: string; tier: string; policy: string; event: string; latency: string };
  body: unknown;
  record: unknown; // zod-parsed with DecisionRecordSchema in gateway.ts
}
export interface PlaygroundResult extends Omit<PlaygroundResponse, "record"> { record: DecisionRecord }

// ---------------------------------------------------------------------------------------------------------------------
// GET /healthz (public)
// ---------------------------------------------------------------------------------------------------------------------
export interface Healthz {
  ok: boolean; version: string; policy: { hash: string; version: number }; feed: { hash: string; entries: number };
  mode: { semanticProvider: string; upstream: string }; uptime_s: number;
}

export class GatewayError extends Error {
  constructor(public status: number, message: string, public code?: string) {
    super(message);
    this.name = "GatewayError";
  }
}
