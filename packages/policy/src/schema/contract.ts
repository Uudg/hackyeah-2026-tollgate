// schema v1.1 — dashboard / HTTP contract: SSE events and admin + metrics JSON shapes.
import { z } from "zod";
import { DecisionRecordSchema } from "./decision.ts";
import { ActionSchema, ModeSchema, OwaspIdSchema } from "./common.ts";

const Issue = z.object({ path: z.string(), message: z.string() });

/** GET /events (SSE). Wire: "event: <type>\ndata: <json>\n\n", ": ping" every 15 s. Also the audit lines' `event`. */
export const TollgateEventSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("decision"), record: DecisionRecordSchema }),
  z.object({ type: z.literal("policy_loaded"), version: z.string(), declared_version: z.number(), mode: ModeSchema, loaded_at: z.string(), changed: z.array(z.string()) }),
  z.object({ type: z.literal("policy_rejected"), at: z.string(), issues: z.array(Issue), kept_version: z.string() }),
  z.object({ type: z.literal("feed_loaded"), version: z.string(), entries: z.number(), source: z.string(), loaded_at: z.string() }),
  z.object({ type: z.literal("feed_rejected"), at: z.string(), issues: z.array(Issue), kept_version: z.string().nullable() }),
  z.object({ type: z.literal("incident"), kind: z.enum(["canary_leak", "kill_session"]), agent: z.string(), rule_id: z.string(), decision_id: z.string(), source_excerpt: z.string().nullable(), at: z.string() }),
  z.object({ type: z.literal("upstream"), state: z.enum(["closed", "open", "half_open"]), at: z.string() }),
  z.object({ type: z.literal("redteam_run"), run_id: z.string(), attempts: z.number(), bypasses: z.number(), per_control: z.record(z.string(), z.object({ attempts: z.number(), bypasses: z.number() })), done: z.boolean() }),
]);
export type TollgateEvent = z.infer<typeof TollgateEventSchema>;

const Pct = z.object({ p50: z.number(), p95: z.number(), p99: z.number(), n: z.number() });

/** GET /metrics (JSON; ?format=prometheus for text). Rolling window of the last N requests. */
export const MetricsSchema = z.object({
  window: z.number(),
  requests: z.number(),
  rps: z.number(),
  stages: z.object({ tier0: Pct, tier1: Pct, tier2: Pct, upstream: Pct, output: Pct, total: Pct }),
  overhead_ms: Pct,                  // total − upstream
  direct_upstream_ms: Pct.nullable(),// baseline: same model called directly (sampled by /admin/bench)
  decided_by_tier: z.object({ "0": z.number(), "1": z.number(), "2": z.number(), output: z.number() }),
  decisions: z.object({ allow: z.number(), redact: z.number(), block: z.number(), kill_session: z.number() }),
});
export type Metrics = z.infer<typeof MetricsSchema>;

/** GET /admin/policy */
export const AdminPolicySchema = z.object({
  version: z.string(), declared_version: z.number(), mode: ModeSchema, loaded_at: z.string(),
  path: z.string(),
  controls: z.array(z.object({ id: z.string(), enabled: z.boolean(), action: ActionSchema, tier: z.union([z.literal(0), z.literal(1), z.literal(2), z.literal("output")]), owasp: z.array(OwaspIdSchema) })),
  agents: z.array(z.object({ id: z.string(), scopes: z.array(z.string()), task: z.string().nullable() })), // never keys
  last_rejected: z.object({ at: z.string(), issues: z.array(Issue) }).nullable(),
  posture_warnings: z.array(z.string()),  // e.g. version-range feed hits
  semantic_provider: z.enum(["ollama", "mock", "off"]),
  upstream: z.enum(["ollama", "echo"]),
});

/** GET /admin/stats?minutes=60 */
export const AdminStatsSchema = z.object({
  minutes: z.number(),
  by_decision: z.record(z.string(), z.number()),
  by_rule: z.record(z.string(), z.number()),
  by_agent: z.record(z.string(), z.number()),
  per_minute: z.array(z.object({ minute: z.string(), allow: z.number(), redact: z.number(), block: z.number(), kill_session: z.number() })),
});

/** GET /admin/agents */
export const AdminAgentsSchema = z.array(z.object({
  id: z.string(), locked: z.boolean(), locked_reason: z.string().nullable(),
  usage: z.object({ tokens_hour: z.number(), usd_day: z.number(), compute_s_hour: z.number() }),
  limits: z.object({ tokens_per_hour: z.number(), usd_per_day: z.number(), compute_seconds_per_hour: z.number(), max_tool_depth: z.number() }),
}));

/** GET /admin/feed */
export const AdminFeedSchema = z.object({
  version: z.string().nullable(), source: z.string(), loaded_at: z.string().nullable(),
  entries: z.array(z.object({ id: z.string(), title: z.string(), type: z.string(), action: ActionSchema, owasp: z.array(OwaspIdSchema), enabled: z.boolean(), cve: z.string().nullable() })),
});

/** GET /audit/verify */
export const AuditVerifySchema = z.object({ ok: z.boolean(), lines: z.number(), broken_at: z.number().nullable() });

/** GET /admin/redteam */
export const AdminRedteamSchema = z.object({
  last_run: z.object({ run_id: z.string(), started_at: z.string(), finished_at: z.string().nullable(), attempts: z.number(), bypasses: z.number(), policy_version: z.string() }).nullable(),
  per_control: z.array(z.object({ control: z.string(), attempts: z.number(), bypasses: z.number(), rate: z.number() })),
});

/**
 * POST /admin/playground — the dashboard's way to send a chat request as an agent without holding its key.
 * The gateway runs the full pipeline with that agent's identity and returns the record for the stage timeline.
 */
export const PlaygroundRequestSchema = z.object({
  agent: z.string(),
  model: z.string(),
  messages: z.array(z.object({ role: z.enum(["system", "user", "assistant", "tool"]), content: z.string() })).min(1),
  use_tools: z.boolean().default(false),   // attach the demo agent's three tools
  echo: z.string().optional(),              // X-Tollgate-Echo preset, only honoured when UPSTREAM=echo
});
export type PlaygroundRequest = z.infer<typeof PlaygroundRequestSchema>;

export const PlaygroundResponseSchema = z.object({
  status: z.number(),
  decision: ActionSchema,
  rule_id: z.string(),
  content: z.string().nullable(),           // assistant text as the caller received it (redacted), null when blocked
  tool_calls: z.array(z.object({ name: z.string(), arguments: z.string() })),
  error: z.object({ type: z.string(), rule: z.string(), message: z.string() }).nullable(),
  record: DecisionRecordSchema,
});
export type PlaygroundResponse = z.infer<typeof PlaygroundResponseSchema>;

export type AdminPolicy = z.infer<typeof AdminPolicySchema>;
export type AdminStats = z.infer<typeof AdminStatsSchema>;
export type AdminAgents = z.infer<typeof AdminAgentsSchema>;
export type AdminFeed = z.infer<typeof AdminFeedSchema>;
export type AuditVerify = z.infer<typeof AuditVerifySchema>;
export type AdminRedteam = z.infer<typeof AdminRedteamSchema>;
