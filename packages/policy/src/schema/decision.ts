// schema v1 — DecisionRecord: one per request, written to SQLite, audit.jsonl and the /events stream.
import { z } from "zod";
import { ActionSchema, DecisionSchema, ModeSchema, OwaspIdSchema, RuleIdSchema, TierSchema } from "./common.ts";

/** Why a decision is what it is, beyond the rule that fired. */
export const ReasonSchema = z.enum([
  "fail_open",            // semantic timeout/error with on_*: allow → request went through
  "fail_closed",          // semantic timeout/error with on_*: block
  "would_act",            // monitor mode: decision recorded, request forwarded unchanged
  "uncertain",            // tier 1 uncertain → tier 2 ran
  "judge_low_confidence", // tier 2 flagged but below controls.judge.min_confidence → allowed
  "agent_locked",         // agent locked by an earlier kill_session
  "upstream_error",       // upstream non-2xx / unreachable
]);
export type Reason = z.infer<typeof ReasonSchema>;

/** Every control hit, not only the deciding one. Never holds the matched value. */
export const HitSchema = z.object({
  rule_id: RuleIdSchema,
  action: ActionSchema,
  tier: TierSchema,
  owasp: z.array(OwaspIdSchema),
  count: z.number().int().positive().default(1),
  /** Where it was found: "messages[2].content", "tool_calls[0].arguments", "tools[1].description", "output". */
  field: z.string().optional(),
  /** Rule-specific, no raw secrets: { via: "base64", inner: "pii.iban" }, { category: "S9" }, { why: "..." }. */
  detail: z.record(z.string(), z.unknown()).optional(),
});
export type Hit = z.infer<typeof HitSchema>;

/** Milliseconds per stage; absent = stage did not run. */
export const StagesSchema = z.object({
  tier0: z.number().nonnegative(),
  tier1: z.number().nonnegative().optional(),
  tier2: z.number().nonnegative().optional(),
  upstream: z.number().nonnegative().optional(),
  output: z.number().nonnegative().optional(),
  total: z.number().nonnegative(),
});
export type Stages = z.infer<typeof StagesSchema>;

export const DecisionRecordSchema = z.object({
  id: z.string(),                         // ULID-like, sortable
  ts: z.string(),                         // ISO 8601 UTC
  request_id: z.string(),
  agent: z.string(),                      // "anonymous" when auth failed
  model: z.string(),
  decision: DecisionSchema,               // collapsed verdict (what was done, or would be done in monitor)
  enforced: z.boolean(),                  // false in monitor mode
  mode: ModeSchema,
  tier: TierSchema,                       // tier of the deciding hit; "output" for a clean pass
  rule_id: z.union([RuleIdSchema, z.literal("none")]), // "none" = clean pass
  owasp: z.array(OwaspIdSchema),          // union over hits
  policy_version: z.string().regex(/^[a-f0-9]{12}$/),
  feed_version: z.string().regex(/^[a-f0-9]{12}$/).nullable(),
  reason: ReasonSchema.optional(),
  hits: z.array(HitSchema),
  stages: StagesSchema,
  tokens_in: z.number().int().nonnegative(),
  tokens_out: z.number().int().nonnegative(),
  usd: z.number().nonnegative(),
  compute_ms: z.number().nonnegative(),
  redacted_types: z.array(z.string()),    // ["iban", "email", "link"]
  excerpt: z.string().max(200),           // already redacted
  http_status: z.number().int(),
});
export type DecisionRecord = z.infer<typeof DecisionRecordSchema>;
