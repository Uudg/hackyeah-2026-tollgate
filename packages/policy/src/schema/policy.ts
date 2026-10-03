// schema v1 — policy.yaml. FROZEN after the freeze commit; change only in the main session.
// Every object is strict: a misspelt key ("contorls") is a validation error, not silently ignored.
// `.prefault({})` makes a missing section parse as {} so its inner defaults apply (zod 4 semantics).
import { z } from "zod";
import { ActionSchema, ModeSchema } from "./common.ts";

const Control = <T extends z.ZodRawShape>(defaultAction: z.infer<typeof ActionSchema>, shape: T) =>
  z.strictObject({ enabled: z.boolean().default(true), action: ActionSchema.default(defaultAction), ...shape });

export const BudgetLimitsSchema = z.strictObject({
  tokens_per_hour: z.number().int().nonnegative().default(50_000),
  usd_per_day: z.number().nonnegative().default(2),
  compute_seconds_per_hour: z.number().nonnegative().default(600),
  max_tool_depth: z.number().int().nonnegative().default(8),
});
export type BudgetLimits = z.infer<typeof BudgetLimitsSchema>;

export const AgentSchema = z.strictObject({
  key: z.string().regex(/^tg_[A-Za-z0-9-]+_[A-Za-z0-9]+$/, "key must look like tg_<agent>_<random>"),
  scopes: z.array(z.enum(["chat", "tools"])).default(["chat"]),
  /** Declared task; the tier-2 judge checks requests against it. */
  task: z.string().max(500).optional(),
  /** Prepended as a system message on every request from this agent (demo + leak tests). */
  system_prefix: z.string().optional(),
  /** Narrows models.allow for this agent. */
  models: z.array(z.string()).optional(),
  /** Partial override of budgets.default. */
  budget: BudgetLimitsSchema.partial().optional(),
});
export type Agent = z.infer<typeof AgentSchema>;

const PriceSchema = z.strictObject({
  input_per_1k_usd: z.number().nonnegative(),
  output_per_1k_usd: z.number().nonnegative(),
});

export const PII_ENTITIES = ["email", "phone", "iban", "card", "pesel", "ssn"] as const;

export const PolicySchema = z.strictObject({
  /** Human-bumped number. The real identity is the sha256 of the file (policy_version). */
  version: z.number().int().nonnegative(),
  mode: ModeSchema.default("enforce"),

  models: z.strictObject({
    /** Exact names or globs ("llama3.2:*"). */
    allow: z.array(z.string()).min(1),
    /** Registry hosts refused in model names like "evil.io/ns/model" ("*" = any registry prefix). */
    deny_registries: z.array(z.string()).default(["*"]),
    /** USD per 1k tokens. Unknown models fall back to shadow_price_per_1k_usd. */
    prices: z.record(z.string(), PriceSchema).default({}),
    /** Metered price for local/unpriced models so spend is visible even at $0 real cost. */
    shadow_price_per_1k_usd: z.number().nonnegative().default(0),
  }),

  agents: z.record(z.string().regex(/^[a-z0-9-]+$/), AgentSchema)
    .refine((a) => Object.keys(a).length > 0, "at least one agent"),

  /** Request-path (input) controls, tier 0 unless noted. */
  controls: z.strictObject({
    pii: Control("redact", { entities: z.array(z.enum(PII_ENTITIES)).default([...PII_ENTITIES]) }).prefault({}),
    secrets: Control("block", {
      entropy_min: z.number().min(0).max(8).default(4.0),
      entropy_min_len: z.number().int().positive().default(32),
    }).prefault({}),
    unicode: Control("block", {
      max_invisible: z.number().int().nonnegative().default(3),
      max_homoglyphs: z.number().int().nonnegative().default(3),
    }).prefault({}),
    decode: Control("block", {
      max_depth: z.number().int().min(0).max(3).default(2),
      min_len: z.number().int().positive().default(24),
    }).prefault({}),
    /** Soft signals only: they never block alone, they push tier 1 "safe" into the uncertain band. */
    injection_patterns: Control("allow", { extra: z.array(z.string()).default([]) }).prefault({}),
    tool_calls: Control("block", {
      allow: z.array(z.string()).default(["*"]),
      deny: z.array(z.string()).default([]),
      require_approval: z.array(z.string()).default([]),
      internal_hosts: z.array(z.string()).default([
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "localhost", "*.internal",
      ]),
      max_arguments_bytes: z.number().int().positive().default(16_384),
    }).prefault({}),
    /** Signature feed hits; an entry's own action wins over this default. */
    signatures: Control("block", {}).prefault({}),
    /** Tier 1: Llama Guard categories that block. */
    content_safety: Control("block", {
      categories: z.array(z.string().regex(/^S\d{1,2}$/)).default(["S1", "S2", "S3", "S4", "S9", "S11", "S14"]),
    }).prefault({}),
    /** Tier 1 (optional): granite3-guardian jailbreak yes/no. */
    jailbreak: Control("block", {}).extend({ enabled: z.boolean().default(false) }).prefault({}),
    /** Tier 2: LLM judge, only in the uncertain band. */
    judge: Control("block", { min_confidence: z.number().min(0).max(1).default(0.6) }).prefault({}),
  }).prefault({}),

  /** Response-path controls (tier "output"). */
  output: z.strictObject({
    pii: Control("redact", {}).prefault({}),
    secrets: Control("redact", {}).prefault({}),
    link_exfil: Control("redact", {
      /** Suffix match: "example.com" allows "docs.example.com". */
      allow_domains: z.array(z.string()).default([]),
      min_data_len: z.number().int().nonnegative().default(16),
    }).prefault({}),
    system_prompt_leak: Control("redact", {
      min_overlap_tokens: z.number().int().positive().default(12),
    }).prefault({}),
    tool_call: Control("block", {}).prefault({}),
    stream_window: z.number().int().positive().default(64),
  }).prefault({}),

  semantic: z.strictObject({
    enabled: z.boolean().default(true),
    classifier: z.string().default("llama-guard3:1b"),
    guardian: z.string().nullable().default(null),
    judge_model: z.string().default("llama3.2:3b"),
    timeout_ms: z.number().int().positive().default(4000),
    judge_timeout_ms: z.number().int().positive().default(8000),
    on_timeout: z.enum(["allow", "block"]).default("block"),
    on_error: z.enum(["allow", "block"]).default("block"),
    /** Tier-1 score in [min, max) is uncertain → tier 2. Two classifiers disagreeing average to 0.5. */
    uncertain_band: z.strictObject({ min: z.number().min(0).max(1), max: z.number().min(0).max(1) })
      .default({ min: 0.3, max: 0.8 }),
    /** Deterministic stand-in used when SEMANTIC_PROVIDER=mock (no models needed). */
    mock: z.strictObject({
      unsafe_markers: z.array(z.string()).default(["pipe bomb", "make a bomb", "nerve agent"]),
      uncertain_markers: z.array(z.string()).default(["you are dan", "no restrictions"]),
      latency_ms: z.number().int().nonnegative().default(5),
    }).prefault({}),
  }).prefault({}),

  budgets: z.strictObject({
    default: BudgetLimitsSchema.prefault({}),
    /** In monitor mode budgets are recorded only, unless this is true. */
    enforce_in_monitor: z.boolean().default(false),
    loop_breaker: z.strictObject({
      enabled: z.boolean().default(true),
      max_repeats: z.number().int().positive().default(5),
      window_s: z.number().int().positive().default(30),
      action: ActionSchema.default("block"),
    }).prefault({}),
    circuit_breaker: z.strictObject({
      enabled: z.boolean().default(true),
      errors: z.number().int().positive().default(5),
      window_s: z.number().int().positive().default(30),
      cooldown_s: z.number().int().positive().default(20),
    }).prefault({}),
  }).prefault({}),

  feed: z.strictObject({
    /** File path or http(s) URL. */
    source: z.string().default("./feeds/ai-exploits.json"),
    refresh_s: z.number().int().positive().default(60),
  }).prefault({}),

  canaries: z.strictObject({
    enabled: z.boolean().default(true),
    action: ActionSchema.default("kill_session"),
    per_agent: z.number().int().min(0).max(10).default(2),
    prefix: z.string().regex(/^[a-z]{2,8}_$/).default("tgc_"),
    inject_into: z.array(z.enum(["system_prompt"])).default(["system_prompt"]),
  }).prefault({}),
});

export type Policy = z.infer<typeof PolicySchema>;
/** Input shape (before defaults) — what a human writes in policy.yaml. */
export type PolicyInput = z.input<typeof PolicySchema>;
