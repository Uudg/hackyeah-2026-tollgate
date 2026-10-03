// schema v2 (SPEC §6.1) — feeds/ai-exploits.json. Regexes are compiled during validation so a bad one is
// rejected with its entry path and the last good feed stays active.
import { z } from "zod";
import { ActionSchema } from "./schema.ts";
import { OwaspIdSchema } from "./decision.ts";

export const FEED_SCOPES = ["request", "response", "tool_call", "tool_definition", "model_file", "upstream"] as const;
export type FeedScope = (typeof FEED_SCOPES)[number];

const MAX_PATTERN = 2048;
const Regex = z.string().min(1).max(MAX_PATTERN);
const Flags = z.string().regex(/^[imsu]*$/, "flags may only use i, m, s, u").optional();

export const RegexPatternSchema = z.strictObject({ regex: Regex, flags: Flags });
export const UrlPatternSchema = z.strictObject({
  host: z.string().optional(),
  port: z.number().int().min(1).max(65535).optional(),
  path_regex: Regex.optional(),
  query_min_len: z.number().int().nonnegative().optional(),
  markdown_image: z.boolean().optional(),
  scheme: z.array(z.string()).optional(),
});
export const PicklePatternSchema = z.strictObject({
  dangerous_globals: z.array(z.string()).min(1),
  require_reduce: z.boolean(),
  on_parse_error: z.enum(["block", "allow"]),
  allowed_container_magic: z.array(z.string().regex(/^[a-f0-9]+$/)).optional(),
});
export const ToolDescriptionPatternSchema = z.strictObject({
  regex: Regex, flags: Flags,
  max_length: z.number().int().positive().optional(),
  invisible_chars: z.boolean().optional(),
  html_comments: z.boolean().optional(),
});
export const VersionRangePatternSchema = z.strictObject({
  component: z.literal("ollama"),
  lt: z.string().optional(), lte: z.string().optional(), gte: z.string().optional(),
});

const base = {
  id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/),
  title: z.string(),
  cve: z.string().regex(/^CVE-\d{4}-\d{4,}$/).nullable(),
  published: z.string().optional(),
  description: z.string().optional(),
  scope: z.array(z.enum(FEED_SCOPES)).min(1),
  action: ActionSchema.optional(),
  severity: z.enum(["low", "medium", "high", "critical"]),
  owasp: z.array(OwaspIdSchema),
  references: z.array(z.string().url()),
  enabled: z.boolean().default(true),
};

export const SignatureEntrySchema = z.discriminatedUnion("type", [
  z.strictObject({ ...base, type: z.literal("regex"), pattern: RegexPatternSchema }),
  z.strictObject({ ...base, type: z.literal("url-pattern"), pattern: UrlPatternSchema }),
  z.strictObject({ ...base, type: z.literal("pickle-opcode"), pattern: PicklePatternSchema }),
  z.strictObject({ ...base, type: z.literal("tool-description"), pattern: ToolDescriptionPatternSchema }),
  z.strictObject({ ...base, type: z.literal("version-range"), pattern: VersionRangePatternSchema }),
]);
export type SignatureEntry = z.infer<typeof SignatureEntrySchema>;
/** Alias kept for the HANDOFF vocabulary. */
export type FeedEntry = SignatureEntry;

export const FeedSchema = z.strictObject({
  schema: z.literal(1),
  name: z.string(),
  updated: z.string(),
  description: z.string().optional(),
  entries: z.array(SignatureEntrySchema),
}).superRefine((feed, ctx) => {
  const seen = new Set<string>();
  feed.entries.forEach((e, i) => {
    if (seen.has(e.id)) ctx.addIssue({ code: "custom", path: ["entries", i, "id"], message: `duplicate id ${e.id}` });
    seen.add(e.id);
    const tryCompile = (src: string | undefined, flags: string | undefined, key: string) => {
      if (src === undefined) return;
      try { new RegExp(src, flags); }
      catch (err) { ctx.addIssue({ code: "custom", path: ["entries", i, "pattern", key], message: `invalid regex: ${(err as Error).message}` }); }
    };
    if (e.type === "regex" || e.type === "tool-description") tryCompile(e.pattern.regex, e.pattern.flags, "regex");
    if (e.type === "url-pattern") tryCompile(e.pattern.path_regex, undefined, "path_regex");
  });
});
export type Feed = z.infer<typeof FeedSchema>;
