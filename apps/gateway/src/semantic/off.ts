// SEMANTIC_PROVIDER=off: tiers 1 and 2 never run (the pipeline checks the name before calling).
import type { SemanticProvider } from "./provider.ts";

export const offProvider: SemanticProvider = {
  name: "off",
  async classify() { throw new Error("semantic provider is off"); },
  async judge() { throw new Error("semantic provider is off"); },
  async status() { return { classifier: false, judge: false }; },
};
