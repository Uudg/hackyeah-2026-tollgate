// Stages 4 and 5: tier-1 classifier and tier-2 judge through the SemanticProvider (SPEC §2.2 stages 4–5).
// Timeouts and errors follow semantic.fail_mode and are recorded as semantic.unavailable hits.
import type { Hit, Policy } from "@tollgate/policy";
import type { SemanticProvider } from "../semantic/provider.ts";

export interface SemanticOutcome {
  hits: Array<{ hit: Hit; tier: 1 | 2 }>;
  tier1Ms: number;
  tier2Ms: number;
  details: Record<string, unknown>;
}

const unavailable = (ruleId: string, policy: Policy, reason: string): Hit => ({
  controlId: "prompt_injection", ruleId, action: policy.semantic.fail_mode === "closed" ? "block" : "allow",
  owasp: ["LLM01"], details: { reason, fail_mode: policy.semantic.fail_mode },
});

export function semanticSkipped(policy: Policy, provider: SemanticProvider): string | null {
  if (provider.name === "off") return "off";
  if (!policy.semantic.enabled) return "disabled";
  if (policy.semantic.provider !== "local") return `provider ${policy.semantic.provider} not implemented`;
  const pi = policy.controls.prompt_injection, cs = policy.controls.content_safety;
  const piActive = pi.enabled && pi.action !== "allow", csActive = cs.enabled && cs.action !== "allow";
  if (!piActive && !csActive) return "no active semantic control";
  return null;
}

/** Llama Guard 3 hazard taxonomy (S1–S14), named in the confirm prompt and the record. */
const GUARD_CATEGORIES: Record<string, string> = {
  S1: "violent crimes", S2: "non-violent crimes (fraud, money laundering, theft, hacking)", S3: "sex-related crimes",
  S4: "child sexual exploitation", S5: "defamation", S6: "specialized advice", S7: "privacy violations",
  S8: "intellectual property", S9: "indiscriminate weapons", S10: "hate", S11: "suicide and self-harm",
  S12: "sexual content", S13: "elections", S14: "code interpreter abuse",
};
/** Judge categories that mean injection rather than harmful content. */
const INJECTION_CATEGORIES = new Set(["prompt_injection", "jailbreak", "data_exfiltration", "tool_abuse"]);

export async function runSemantic(text: string, policy: Policy, provider: SemanticProvider, task: string, history: Array<{ role: "user" | "assistant"; content: string }>): Promise<SemanticOutcome> {
  const out: SemanticOutcome = { hits: [], tier1Ms: 0, tier2Ms: 0, details: {} };
  const s = policy.semantic, pi = policy.controls.prompt_injection, cs = policy.controls.content_safety;
  const t1 = performance.now();
  let c;
  try {
    c = await provider.classify(text, { policy, task, history, signal: AbortSignal.timeout(s.timeout_ms) });
  } catch (err) {
    out.tier1Ms = performance.now() - t1;
    out.details.tier1 = "unavailable";
    out.hits.push({ hit: unavailable("semantic.unavailable", policy, failReason(err, s.timeout_ms)), tier: 1 });
    return out;
  }
  out.tier1Ms = performance.now() - t1;
  out.details.tier1 = { score: c.score, categories: c.categories, raw: c.raw, model: c.model, ms: Math.round(c.ms * 10) / 10, parsed: c.parsed };

  // Tier-2 call shared by both paths. Returns null when the judge is unavailable (the hit is already recorded).
  const judge = async (flagged?: { category: string; name: string }) => {
    const t2 = performance.now();
    try {
      const j = await provider.judge(text, { policy, task, history, signal: AbortSignal.timeout(s.judge_timeout_ms), ...(flagged ? { flagged } : {}) });
      out.tier2Ms = performance.now() - t2;
      out.details.tier2 = { verdict: j.verdict, confidence: j.confidence, category: j.category, reason: j.reason, model: j.model, ms: Math.round(j.ms * 10) / 10, ...(flagged ? { confirming: flagged.category } : {}) };
      return j;
    } catch (err) {
      out.tier2Ms = performance.now() - t2;
      out.details.tier2 = "unavailable";
      out.hits.push({ hit: unavailable("semantic.judge_unavailable", policy, failReason(err, s.judge_timeout_ms)), tier: 2 });
      return null;
    }
  };
  const injectionHit = (j: { confidence: number; category: string; reason: string }) =>
    ({ hit: { controlId: "prompt_injection", ruleId: "inject.judge", action: pi.action, owasp: ["LLM01", "ASI01", "ASI10"], details: { confidence: j.confidence, category: j.category, reason: j.reason } } as Hit, tier: 2 as const });

  // Content safety: a listed category. With confirm_with_judge the judge decides; if it cannot run, the classifier's verdict stands.
  const listed = cs.enabled ? c.categories.find((k) => cs.categories.includes(k)) : undefined;
  if (listed) {
    const csHit = (tier: 1 | 2, extra: Record<string, unknown>) =>
      ({ hit: { controlId: "content_safety", ruleId: `content_safety.${listed}`, action: cs.action, owasp: ["LLM01"], details: { category: listed, score: c.score, ...extra } } as Hit, tier });
    if (!cs.confirm_with_judge || cs.action === "allow") { out.hits.push(csHit(1, {})); return out; }
    const j = await judge({ category: listed, name: GUARD_CATEGORIES[listed] ?? listed });
    if (j === null) { out.hits.push(csHit(1, { confirmed: false, reason: "judge unavailable; classifier verdict applied" })); return out; }
    if (j.verdict === "block" && j.confidence >= s.judge_min_confidence) {
      out.hits.push(INJECTION_CATEGORIES.has(j.category) && pi.enabled ? injectionHit(j) : csHit(2, { confirmed: true, judge: j.reason }));
    }
    return out;
  }

  // Llama Guard has no injection category, so "unsafe" in a category the policy does not list is a soft signal
  // for the judge, not an injection verdict. With a jailbreak model configured the score is a real vote.
  const guardOnly = c.categories.length > 0 && !s.jailbreak_model;
  if (pi.enabled && c.parsed && c.score >= pi.threshold && !guardOnly) {
    out.hits.push({ hit: { controlId: "prompt_injection", ruleId: "inject.classifier", action: pi.action, owasp: ["LLM01", "ASI01"], details: { score: c.score, categories: c.categories } }, tier: 1 });
    return out;
  }
  const [lo, hi] = s.uncertain_band;
  const uncertain = c.parsed === false || (c.score >= lo && c.score < hi) || guardOnly;
  if (!pi.enabled || !uncertain) return out;
  const j = await judge();
  if (j && j.verdict === "block" && j.confidence >= s.judge_min_confidence) out.hits.push(injectionHit(j));
  return out;
}

function failReason(err: unknown, timeoutMs: number): string {
  return (err as Error).name === "TimeoutError" ? `timeout after ${timeoutMs} ms` : (err as Error).message.slice(0, 200);
}
