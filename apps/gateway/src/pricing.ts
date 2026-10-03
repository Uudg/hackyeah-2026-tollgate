// pricing.json loader (SPEC §5.2): exact model name → first matching glob in file order → default.
import { z } from "zod";
import { globMatch } from "@tollgate/controls";
import { sha256, type LoadResult, zodIssues } from "@tollgate/policy/loader";

const Price = z.strictObject({
  input_per_1k: z.number().nonnegative(),
  output_per_1k: z.number().nonnegative(),
  local: z.boolean().optional(),
  /** A made-up commercial price for a demo alias: spend and USD budgets are real, no money is spent. */
  shadow: z.boolean().optional(),
  /** Alias: the model actually sent upstream (records, budgets and spend keep the alias name). */
  upstream_model: z.string().min(1).optional(),
  note: z.string().optional(),
});
export const PricingSchema = z.strictObject({
  currency: z.literal("USD"),
  models: z.record(z.string(), Price),
  default: Price,
});
export type Pricing = z.infer<typeof PricingSchema>;
export type Price = z.infer<typeof Price>;

export function parsePricingText(raw: string): LoadResult<Pricing> {
  let data: unknown;
  try { data = JSON.parse(raw); }
  catch (err) { return { ok: false, errors: [{ path: "(json)", message: (err as Error).message }] }; }
  const parsed = PricingSchema.safeParse(data);
  if (!parsed.success) return { ok: false, errors: zodIssues(parsed.error) };
  return { ok: true, value: parsed.data, hash: sha256(raw).slice(0, 12), loadedAt: new Date().toISOString(), raw };
}

export function priceFor(p: Pricing, model: string): { price: Price; matched: string | null } {
  const exact = p.models[model];
  if (exact) return { price: exact, matched: model };
  for (const [pattern, price] of Object.entries(p.models)) if (pattern.includes("*") && globMatch(pattern, model)) return { price, matched: pattern };
  return { price: p.default, matched: null };
}

export const costUsd = (price: Price, tokensIn: number, tokensOut: number) =>
  Math.round(((tokensIn / 1000) * price.input_per_1k + (tokensOut / 1000) * price.output_per_1k) * 1e6) / 1e6;
