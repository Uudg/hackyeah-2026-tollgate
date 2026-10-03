// schema v1 — shared enums. FROZEN after the freeze commit; change only in the main session.
import { z } from "zod";

/** What a control does when it fires. Severity order: kill_session > block > redact > allow. */
export const ActionSchema = z.enum(["allow", "redact", "block", "kill_session"]);
export type Action = z.infer<typeof ActionSchema>;

/** The collapsed verdict of a request. Same vocabulary as Action. */
export const DecisionSchema = ActionSchema;
export type Decision = Action;

export const SEVERITY: Record<Action, number> = { allow: 0, redact: 1, block: 2, kill_session: 3 };

export const ModeSchema = z.enum(["monitor", "enforce"]);
export type Mode = z.infer<typeof ModeSchema>;

/** Where a decision was made. Auth, budgets and all deterministic checks are tier 0. */
export const TierSchema = z.union([z.literal(0), z.literal(1), z.literal(2), z.literal("output")]);
export type Tier = z.infer<typeof TierSchema>;

export const OWASP_IDS = [
  "LLM01", "LLM02", "LLM03", "LLM04", "LLM05", "LLM06", "LLM07", "LLM08", "LLM09", "LLM10",
  "ASI01", "ASI02", "ASI03", "ASI04", "ASI05", "ASI06", "ASI07", "ASI08", "ASI09", "ASI10",
] as const;
export const OwaspIdSchema = z.enum(OWASP_IDS);
export type OwaspId = z.infer<typeof OwaspIdSchema>;

/** Rule ids look like "pii.iban", "feed.shadowray-cve-2023-48022", "content_safety.S9". */
export const RuleIdSchema = z.string().regex(/^[a-z_]+(\.[A-Za-z0-9_-]+)*$/);
