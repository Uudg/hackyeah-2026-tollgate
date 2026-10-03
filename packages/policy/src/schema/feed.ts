// schema v1 — feeds/ai-exploits.json (file or URL). Every pattern is one string so judges can edit it in place.
import { z } from "zod";
import { ActionSchema, OwaspIdSchema } from "./common.ts";

export const FEED_TYPES = ["regex", "url-pattern", "pickle-opcode", "tool-description", "version-range"] as const;
export const SURFACES = ["input", "tool_args", "tool_description", "output", "model_file", "runtime"] as const;

export const FeedEntrySchema = z.strictObject({
  id: z.string().regex(/^[a-z0-9-]+$/),      // rule id becomes "feed.<id>"
  title: z.string(),
  cve: z.string().regex(/^CVE-\d{4}-\d{4,}$/).nullable(),
  /**
   * How `pattern` is read:
   *  regex            JS regex over text on the given surfaces
   *  url-pattern      JS regex over each extracted URL ("scheme://host:port/path?query")
   *  tool-description JS regex over tool names/descriptions/parameter descriptions
   *  pickle-opcode    JS regex over "module.name" globals found by the pickle walker (Model Customs, stretch)
   *  version-range    "<component> <op> <semver>", e.g. "ollama < 0.1.34" — posture warning, never blocks chat
   */
  type: z.enum(FEED_TYPES),
  pattern: z.string().min(1).max(2048),
  flags: z.string().regex(/^[imsu]*$/).default("i"),
  applies_to: z.array(z.enum(SURFACES)).min(1),
  action: ActionSchema,
  severity: z.enum(["low", "medium", "high", "critical"]).default("high"),
  owasp: z.array(OwaspIdSchema).min(1),
  source: z.string().url(),
  enabled: z.boolean().default(true),
});
export type FeedEntry = z.infer<typeof FeedEntrySchema>;

export const FeedSchema = z.strictObject({
  version: z.number().int().nonnegative(),
  updated_at: z.string(),
  entries: z.array(FeedEntrySchema),
}).superRefine((feed, ctx) => {
  const seen = new Set<string>();
  feed.entries.forEach((e, i) => {
    if (seen.has(e.id)) ctx.addIssue({ code: "custom", path: ["entries", i, "id"], message: `duplicate id ${e.id}` });
    seen.add(e.id);
    if (e.type === "version-range") {
      if (!/^[a-z0-9-]+\s*(<|<=|>|>=)\s*\d+(\.\d+){0,2}$/.test(e.pattern))
        ctx.addIssue({ code: "custom", path: ["entries", i, "pattern"], message: "version-range must be '<component> <op> <x.y.z>'" });
      return;
    }
    try { new RegExp(e.pattern, e.flags); }
    catch (err) { ctx.addIssue({ code: "custom", path: ["entries", i, "pattern"], message: `invalid regex: ${(err as Error).message}` }); }
  });
});
export type Feed = z.infer<typeof FeedSchema>;
