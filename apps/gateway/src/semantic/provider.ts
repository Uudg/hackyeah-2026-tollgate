// SemanticProvider (SPEC §2.1): tier-1 classifier and tier-2 judge behind one interface.
// Adapters: ollama (real), mock (deterministic, no network), off (tiers skipped).
import type { Policy } from "@tollgate/policy";

export interface ClassifyResult {
  /** 0..1; 1 = unsafe / injection. */
  score: number;
  categories: string[];
  raw: string;
  /** false when no vote could be parsed (goes to the judge). */
  parsed: boolean;
  ms: number;
  model: string;
}

export interface JudgeResult {
  verdict: "allow" | "block";
  confidence: number;
  category: string;
  reason: string;
  ms: number;
  model: string;
}

export interface SemanticContext {
  policy: Policy;
  /** Agent description from the policy, used in the judge prompt. */
  task: string;
  /** Previous user/assistant turns (oldest first) when semantic.classify_context is true. */
  history: Array<{ role: "user" | "assistant"; content: string }>;
  signal: AbortSignal;
  /** Set when the judge confirms a tier-1 content-safety flag instead of looking for injection. */
  flagged?: { category: string; name: string };
}

export interface SemanticProvider {
  readonly name: "ollama" | "mock" | "off";
  classify(text: string, ctx: SemanticContext): Promise<ClassifyResult>;
  judge(text: string, ctx: SemanticContext): Promise<JudgeResult>;
  /** Which configured models are available (for /healthz and the posture score). */
  status(policy: Policy): Promise<{ classifier: boolean; judge: boolean }>;
}

export const sleep = (ms: number, signal?: AbortSignal) => new Promise<void>((resolve, reject) => {
  const t = setTimeout(resolve, ms);
  signal?.addEventListener("abort", () => { clearTimeout(t); reject(signal.reason ?? new Error("aborted")); }, { once: true });
});
