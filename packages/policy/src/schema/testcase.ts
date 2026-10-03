// schema v1 — tests/cases/*.yaml fixtures and tests/redteam/seeds/*.yaml seeds.
import { z } from "zod";
import { DecisionSchema, OwaspIdSchema, RuleIdSchema, TierSchema } from "./common.ts";

const ToolCallSchema = z.object({
  id: z.string(),
  type: z.literal("function").default("function"),
  function: z.object({ name: z.string(), arguments: z.string() }),
});

const MessageSchema = z.object({
  role: z.enum(["system", "user", "assistant", "tool"]),
  content: z.string().nullable().default(""),
  tool_calls: z.array(ToolCallSchema).optional(),
  tool_call_id: z.string().optional(),
  name: z.string().optional(),
});

/**
 * What the built-in echo upstream returns for this case (UPSTREAM=echo, header X-Tollgate-Echo).
 * Presets: "pii" (IBAN + email), "secret" (AWS key), "canary" (the agent's first canary),
 * "exfil" (markdown image with data in the URL), "sysprompt" (repeats the system prompt),
 * "tool:<name>" (a tool call to <name> with args {}). Default: echoes the last user message.
 */
export const EchoSchema = z.union([
  z.string().regex(/^(pii|secret|canary|exfil|sysprompt|tool:[a-z_]+)$/),
  z.object({ content: z.string().optional(), tool_calls: z.array(ToolCallSchema).optional() }),
]);

export const ExpectSchema = z.strictObject({
  decision: DecisionSchema.optional(),
  rule: z.union([RuleIdSchema, z.literal("none")]).optional(),
  tier: TierSchema.optional(),
  status: z.number().int().optional(),
  reason: z.string().optional(),
  redacted_types: z.array(z.string()).optional(),
  output_contains: z.array(z.string()).optional(),
  output_not_contains: z.array(z.string()).optional(),
  /** For repeat > 1: asserted on the final response only. */
  last_decision: DecisionSchema.optional(),
  last_rule: RuleIdSchema.optional(),
  last_status: z.number().int().optional(),
});

export const TestCaseSchema = z.strictObject({
  id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/),
  /** Rule id or control prefix the case is grouped under: "pii.iban" or "pii". */
  control: RuleIdSchema,
  owasp: z.array(OwaspIdSchema).min(1),
  agent: z.string().default("demo"),
  model: z.string().default("llama3.2:3b"),
  /** Shorthand for one user message. Exactly one of input / messages. */
  input: z.string().optional(),
  messages: z.array(MessageSchema).optional(),
  system: z.string().optional(),
  tools: z.array(z.unknown()).optional(),
  headers: z.record(z.string(), z.string()).optional(),
  echo: EchoSchema.optional(),
  stream: z.boolean().default(false),
  repeat: z.number().int().min(1).max(500).default(1),
  /** Deep-merged into the test policy for this case only. */
  policy_overrides: z.record(z.string(), z.unknown()).optional(),
  requires: z.literal("ollama").optional(),
  tags: z.array(z.string()).default([]),
  /** Red-team generated cases start "open" (expected to fail) until fixed. */
  status: z.enum(["open", "fixed"]).optional(),
  source: z.string().optional(),
  expect: ExpectSchema,
}).refine((c) => (c.input === undefined) !== (c.messages === undefined), "exactly one of input or messages");
export type TestCase = z.infer<typeof TestCaseSchema>;
export const TestCaseFileSchema = z.array(TestCaseSchema);

export const SeedSchema = z.strictObject({
  id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/),
  goal: z.enum(["system_prompt_extraction", "pii_exfil", "tool_misuse", "jailbreak", "code_execution"]),
  text: z.string().min(1),
  /** Rule id or control prefix that should catch it. */
  expected_control: RuleIdSchema,
  owasp: z.array(OwaspIdSchema).min(1),
  /** "input" seeds go in the user message; "output" seeds are returned by the echo upstream. */
  direction: z.enum(["input", "output"]).default("input"),
  /** "garak:<probe file>", "promptfoo:<plugin>", or "own". */
  source: z.string().regex(/^(garak:|promptfoo:|own$)/),
});
export type Seed = z.infer<typeof SeedSchema>;
export const SeedFileSchema = z.array(SeedSchema);
