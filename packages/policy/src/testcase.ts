// schema v2 (SPEC §11.1, §12.1) — tests/cases/**/*.yaml fixtures and tests/redteam/seeds/*.yaml seeds.
import { z } from "zod";
import { DecisionSchema, DirectionSchema, OwaspIdSchema, TierSchema } from "./decision.ts";

const ToolCallSchema = z.object({
  id: z.string().default("call_1"),
  type: z.literal("function").default("function"),
  function: z.object({ name: z.string(), arguments: z.string() }),
});

const MessageSchema = z.object({
  role: z.enum(["system", "developer", "user", "assistant", "tool"]),
  content: z.string().nullable().optional(),
  tool_calls: z.array(ToolCallSchema).optional(),
  tool_call_id: z.string().optional(),
  name: z.string().optional(),
});

/** What the echo upstream returns (sent as the X-Tollgate-Echo header). */
export const MockUpstreamSchema = z.strictObject({
  content: z.string().nullable().optional(),
  tool_calls: z.array(ToolCallSchema).optional(),
  status: z.number().int().optional(),
  delay_ms: z.number().int().nonnegative().optional(),
});
export type MockUpstream = z.infer<typeof MockUpstreamSchema>;

export const ExpectSchema = z.strictObject({
  decision: DecisionSchema.optional(),
  rule: z.string().nullable().optional(),
  rule_in: z.array(z.string()).optional(),
  control: z.string().optional(),
  tier: TierSchema.optional(),
  tier_in: z.array(TierSchema).optional(),
  direction: DirectionSchema.optional(),
  status: z.number().int().optional(),
  enforced: z.boolean().optional(),
  output_contains: z.array(z.string()).optional(),
  output_not_contains: z.array(z.string()).optional(),
  headers: z.record(z.string(), z.string()).optional(),
  last_decision: DecisionSchema.optional(),
  last_rule: z.string().optional(),
  last_status: z.number().int().optional(),
  owasp_includes: z.array(OwaspIdSchema).optional(),
});

export const TestCaseSchema = z.strictObject({
  id: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._+-]*$/),
  control: z.string(),
  owasp: z.array(OwaspIdSchema).default([]),
  tags: z.array(z.string()).default(["deterministic"]),
  agent: z.string().default("demo-agent"),
  model: z.string().default("llama3.2:3b"),
  input: z.string().optional(),
  messages: z.array(MessageSchema).optional(),
  system: z.string().optional(),
  tools: z.array(z.unknown()).optional(),
  mock_upstream: MockUpstreamSchema.optional(),
  headers: z.record(z.string(), z.string()).optional(),
  /** Dotted overrides applied to the test policy for this case only: { "controls.pii.action": "block" }. */
  policy: z.record(z.string(), z.unknown()).optional(),
  repeat: z.number().int().min(1).max(1000).default(1),
  requires: z.array(z.string()).default([]),
  skip: z.string().optional(),
  stream: z.boolean().optional(),
  generated: z.record(z.string(), z.unknown()).optional(),
  expect: ExpectSchema,
}).refine((c) => (c.input === undefined) !== (c.messages === undefined), "exactly one of input or messages");
export type TestCase = z.infer<typeof TestCaseSchema>;
export const TestCaseFileSchema = z.array(TestCaseSchema);

export const SeedSchema = z.strictObject({
  id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/),
  /** controlId that should catch it. */
  control: z.string(),
  owasp: z.array(OwaspIdSchema).default([]),
  /** "garak:<module>", "promptfoo:<plugin>" or "own". */
  source: z.string().regex(/^(garak:|promptfoo:|own\b)/).default("own"),
  direction: z.enum(["request", "response"]).default("request"),
  expected: z.enum(["block", "redact"]).optional(),
  /** Goal family, for reporting only. */
  goal: z.string().optional(),
  text: z.string().min(1),
});
export type Seed = z.infer<typeof SeedSchema>;
export const SeedFileSchema = z.array(SeedSchema);
