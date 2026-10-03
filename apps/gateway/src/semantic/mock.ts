// Deterministic semantic provider (SPEC §2.1). No network. Markers are matched as whole words, case-insensitive,
// so the "DAN" marker does not fire on "dangerous".
import { sleep, type SemanticProvider } from "./provider.ts";

export function createMockProvider(markers: string[]): SemanticProvider {
  const res = markers.map((m) => new RegExp(`\\b${m.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\s+/g, "\\s+")}\\b`, "i"));
  return {
    name: "mock",
    async classify(text, ctx) {
      const t0 = performance.now();
      await sleep(20, ctx.signal);
      // TG-MOCK-UNSAFE-S<n> answers like Llama Guard flagging that category.
      const cat = /TG-MOCK-UNSAFE-(S\d{1,2})\b/.exec(text)?.[1];
      if (cat) return { score: 1, categories: [cat], raw: `unsafe\n${cat}`, parsed: true, ms: performance.now() - t0, model: "mock" };
      const hit = res.find((re) => re.test(text));
      const score = hit ? 1 : text.includes("TG-MOCK-UNCERTAIN") ? 0.5 : 0;
      return { score, categories: [], raw: hit ? "unsafe" : score === 0.5 ? "uncertain" : "safe", parsed: true, ms: performance.now() - t0, model: "mock" };
    },
    async judge(text, ctx) {
      const t0 = performance.now();
      await sleep(50, ctx.signal);
      const block = text.includes("TG-MOCK-JUDGE-BLOCK");
      return block
        ? { verdict: "block", confidence: 0.9, category: ctx.flagged ? "other" : "prompt_injection", reason: "mock judge: marker TG-MOCK-JUDGE-BLOCK", ms: performance.now() - t0, model: "mock" }
        : { verdict: "allow", confidence: 0.9, category: "none", reason: "mock judge", ms: performance.now() - t0, model: "mock" };
    },
    async status() { return { classifier: true, judge: true }; },
  };
}
