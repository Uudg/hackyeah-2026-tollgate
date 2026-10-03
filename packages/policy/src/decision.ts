// schema v2 (SPEC §3) — DecisionRecord and Hit. One record per request: SQLite, audit.jsonl, /admin/events.
import { z } from "zod";
import { ActionSchema } from "./schema.ts";

export const DecisionSchema = ActionSchema;
export type Decision = z.infer<typeof DecisionSchema>;
export const DirectionSchema = z.enum(["request", "response", "tool_call"]);
export type Direction = z.infer<typeof DirectionSchema>;
/** null = decided outside the cascade (auth, budget, upstream error). Output-path hits are tier 0. */
export const TierSchema = z.union([z.literal(0), z.literal(1), z.literal(2), z.null()]);
export type Tier = z.infer<typeof TierSchema>;

export const OwaspIdSchema = z.string().regex(/^(LLM|ASI)(0[1-9]|10)$/);

export const HitSchema = z.object({
  controlId: z.string(),
  ruleId: z.string(),
  action: ActionSchema,
  owasp: z.array(OwaspIdSchema),
  span: z.object({ start: z.number().int(), end: z.number().int(), field: z.string() }).optional(),
  excerptRedacted: z.string().max(240).optional(),
  details: z.record(z.string(), z.unknown()).optional(),
});
export type Hit = z.infer<typeof HitSchema>;

export const StageLatencySchema = z.object({
  auth: z.number(), budget: z.number(), tier0: z.number(), tier1: z.number(), tier2: z.number(),
  upstream: z.number(), output: z.number(), total: z.number(),
});
export type StageLatency = z.infer<typeof StageLatencySchema>;
export const STAGES = ["auth", "budget", "tier0", "tier1", "tier2", "upstream", "output", "total"] as const;

export const DecisionRecordSchema = z.object({
  id: z.string(),
  ts: z.string(),
  agentId: z.string(),
  sessionId: z.string(),
  model: z.string(),
  direction: DirectionSchema,
  decision: DecisionSchema,
  enforced: z.boolean(),
  tier: TierSchema,
  ruleId: z.string().nullable(),
  controlId: z.string().nullable(),
  owasp: z.array(OwaspIdSchema),
  hits: z.array(HitSchema),
  policyVersion: z.string().regex(/^p-[a-f0-9]{12}$/),
  policyDeclaredVersion: z.number(),
  feedVersion: z.string().regex(/^f-[a-f0-9]{12}$/).nullable(),
  latencyMs: StageLatencySchema,
  excerptRedacted: z.string().max(200).nullable(),
  tokensIn: z.number().int().nonnegative(),
  tokensOut: z.number().int().nonnegative(),
  costUsd: z.number().nonnegative(),
  computeSeconds: z.number().nonnegative(),
  httpStatus: z.number().int(),
  details: z.record(z.string(), z.unknown()),
});
export type DecisionRecord = z.infer<typeof DecisionRecordSchema>;
