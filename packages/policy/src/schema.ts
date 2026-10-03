// schema v2 (SPEC §4.1) — policy.yaml. FROZEN; change only in the main session with a one-line justification.
// Every object is strict: a misspelt key ("contorls") is a validation error with its path.
// zod 4: `.prefault({})` parses a missing section as {} so the inner defaults apply.
import { z } from "zod";

export const ActionSchema = z.enum(["allow", "redact", "block", "kill_session"]);
export type Action = z.infer<typeof ActionSchema>;

/** Severity order used to collapse several hits into one decision. */
export const SEVERITY: Record<Action, number> = { allow: 0, redact: 1, block: 2, kill_session: 3 };

export const DurationSchema = z.string().regex(/^\d+(ms|s|m|h|d)$/, 'duration like "150ms", "30s", "5m", "1h", "1d"');
const UNIT_MS = { ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 } as const;
export function parseDuration(d: string): number {
  const m = /^(\d+)(ms|s|m|h|d)$/.exec(d);
  if (!m) throw new Error(`invalid duration: ${d}`);
  return Number(m[1]) * UNIT_MS[m[2] as keyof typeof UNIT_MS];
}

const control = <T extends z.ZodRawShape>(defaultAction: Action, shape: T) =>
  // `{} as never`: every field of a control has a default, but TS cannot see that through the generic shape.
  z.strictObject({ enabled: z.boolean().default(true), action: ActionSchema.default(defaultAction), ...shape }).prefault({} as never);

export const SCOPES = ["chat", "tools", "dry_run", "admin"] as const;

export const AgentSchema = z.strictObject({
  key: z.string().regex(/^tg_[a-z0-9-]+_[A-Za-z0-9]{16,}$/, "key must look like tg_<agent>_<16+ random chars>"),
  scopes: z.array(z.enum(SCOPES)).default(["chat"]),
  models: z.array(z.string()).optional(),
  description: z.string().max(300).optional(),
  memory_namespace: z.string().optional(),
});
export type AgentPolicy = z.infer<typeof AgentSchema>;

const BudgetLimits = {
  tokens_per_hour: z.number().int().positive(),
  usd_per_day: z.number().nonnegative(),
  compute_seconds_per_hour: z.number().positive(),
  max_tool_depth: z.number().int().positive(),
  requests_per_minute: z.number().int().positive(),
};
export type BudgetLimits = { [K in keyof typeof BudgetLimits]: number };

export const PII_ENTITIES = ["email", "phone", "iban", "card", "pesel", "ip"] as const;
export type PiiEntity = (typeof PII_ENTITIES)[number];

export const PolicySchema = z.strictObject({
  version: z.number().int().nonnegative(),
  mode: z.enum(["monitor", "enforce"]).default("enforce"),

  upstream: z.strictObject({
    base_url: z.string().url().default("http://127.0.0.1:11434/v1"),
    api_key: z.string().optional(),
    timeout_ms: z.number().int().positive().default(60000),
  }).prefault({}),

  agents: z.record(z.string().regex(/^[a-z0-9-]+$/), AgentSchema)
    .refine((a) => Object.keys(a).length > 0, "at least one agent"),

  models: z.strictObject({
    allow: z.array(z.string()).min(1),
    deny_registries: z.array(z.string()).default(["*"]),
  }),

  controls: z.strictObject({
    pii: control("redact", {
      entities: z.array(z.enum(PII_ENTITIES)).default(["email", "phone", "iban", "card", "pesel"]),
      scan_system_prompt: z.boolean().default(true),
    }),
    secrets: control("block", {
      entropy_min: z.number().min(0).max(8).default(3.5),
      entropy_min_len: z.number().int().positive().default(32),
      patterns: z.array(z.string().regex(/^[a-z0-9_]+=.+$/, 'extra pattern must be "name=regex"')).default([]),
    }),
    unicode: control("block", {
      max_invisible: z.number().int().nonnegative().default(3),
      max_homoglyphs: z.number().int().nonnegative().default(3),
    }),
    decode: control("block", { max_depth: z.number().int().min(0).max(3).default(2) }),
    prompt_injection: control("block", {
      threshold: z.number().min(0).max(1).default(0.8),
      heuristics: z.boolean().default(true),
    }),
    content_safety: control("block", {
      categories: z.array(z.string().regex(/^S\d{1,2}$/)).default(["S1", "S2", "S9", "S11"]),
    }),
    canaries: control("kill_session", {}),
    link_exfil: control("redact", {
      allow_domains: z.array(z.string()).default([]),
      min_query_len: z.number().int().nonnegative().default(20),
      block_images: z.boolean().default(true),
    }),
    sysprompt: control("redact", {
      ngram: z.number().int().min(3).default(8),
      overlap_threshold: z.number().min(0).max(1).default(0.2),
      min_run: z.number().int().positive().default(12),
    }),
    tool_calls: control("block", {
      allow: z.array(z.string()).default(["*"]),
      deny: z.array(z.string()).default([]),
      require_approval: z.array(z.string()).default([]),
      approval_timeout_ms: z.number().int().positive().default(30000),
      max_arguments_bytes: z.number().int().positive().default(16384),
      scan_descriptions: z.boolean().default(true),
    }),
    signatures: control("block", {
      feed: z.string().default("./feeds/ai-exploits.json"),
      refresh: DurationSchema.default("60s"),
      fail_mode: z.enum(["open", "closed"]).default("open"),
    }),
  }).prefault({}),

  semantic: z.strictObject({
    enabled: z.boolean().default(true),
    provider: z.enum(["local", "jev"]).default("local"),
    fail_mode: z.enum(["open", "closed"]).default("open"),
    classifier_model: z.string().default("llama-guard3:1b"),
    jailbreak_model: z.string().optional(),
    judge_model: z.string().default("llama3.2:3b"),
    timeout_ms: z.number().int().positive().default(1500),
    judge_timeout_ms: z.number().int().positive().default(6000),
    judge_min_confidence: z.number().min(0).max(1).default(0.6),
    uncertain_band: z.tuple([z.number().min(0).max(1), z.number().min(0).max(1)]).default([0.3, 0.8]),
    classify_context: z.boolean().default(false),
    max_chars: z.number().int().positive().default(6000),
  }).prefault({}),

  budgets: z.strictObject({
    pricing_file: z.string().default("./pricing.json"),
    default_max_tokens: z.number().int().positive().default(1024),
    enforce_in_monitor: z.boolean().default(false),
    default: z.strictObject({
      tokens_per_hour: BudgetLimits.tokens_per_hour.default(50000),
      usd_per_day: BudgetLimits.usd_per_day.default(2),
      compute_seconds_per_hour: BudgetLimits.compute_seconds_per_hour.default(600),
      max_tool_depth: BudgetLimits.max_tool_depth.default(8),
      requests_per_minute: BudgetLimits.requests_per_minute.default(120),
    }).prefault({}),
    agents: z.record(z.string(), z.strictObject({
      tokens_per_hour: BudgetLimits.tokens_per_hour.optional(),
      usd_per_day: BudgetLimits.usd_per_day.optional(),
      compute_seconds_per_hour: BudgetLimits.compute_seconds_per_hour.optional(),
      max_tool_depth: BudgetLimits.max_tool_depth.optional(),
      requests_per_minute: BudgetLimits.requests_per_minute.optional(),
    })).default({}),
    loop_breaker: z.strictObject({
      enabled: z.boolean().default(true),
      same_request_within: DurationSchema.default("30s"),
      max_repeats: z.number().int().positive().default(5),
      action: ActionSchema.default("block"),
    }).prefault({}),
    circuit_breaker: z.strictObject({
      enabled: z.boolean().default(true),
      failure_threshold: z.number().int().positive().default(5),
      window: DurationSchema.default("30s"),
      open_for: DurationSchema.default("20s"),
    }).prefault({}),
  }).prefault({}),

  canaries: z.strictObject({
    auto_generate: z.number().int().min(0).default(3),
    tokens: z.array(z.string()).default([]),
  }).prefault({}),

  telemetry: z.strictObject({
    reservoir_size: z.number().int().positive().default(2000),
    sse_heartbeat_ms: z.number().int().positive().default(15000),
    log_level: z.enum(["debug", "info", "warn", "error"]).default("info"),
  }).prefault({}),
}).superRefine((p, ctx) => {
  const [lo, hi] = p.semantic.uncertain_band;
  if (lo > hi) ctx.addIssue({ code: "custom", path: ["semantic", "uncertain_band"], message: "lower bound must be <= upper bound" });
  for (const name of Object.keys(p.budgets.agents)) {
    if (!(name in p.agents)) ctx.addIssue({ code: "custom", path: ["budgets", "agents", name], message: `unknown agent "${name}"` });
  }
  p.controls.secrets.patterns.forEach((pat, i) => {
    try { new RegExp(pat.slice(pat.indexOf("=") + 1)); }
    catch (err) { ctx.addIssue({ code: "custom", path: ["controls", "secrets", "patterns", i], message: `invalid regex: ${(err as Error).message}` }); }
  });
});

export type Policy = z.infer<typeof PolicySchema>;
export type PolicyInput = z.input<typeof PolicySchema>;

/** Effective budget limits for an agent: default merged with its override. */
export function limitsFor(policy: Policy, agentId: string): BudgetLimits {
  return { ...policy.budgets.default, ...(policy.budgets.agents[agentId] ?? {}) } as BudgetLimits;
}
