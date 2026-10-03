import { expect, test } from "bun:test";
import { normalizeConfidence, parseGuard } from "./ollama.ts";

test("judge confidence outside 0..1 is mapped back", () => {
  expect(normalizeConfidence(0.9)).toBe(0.9);
  expect(normalizeConfidence(9)).toBe(0.9);
  expect(normalizeConfidence(95)).toBe(0.95);
  expect(normalizeConfidence(400)).toBe(1);
  expect(normalizeConfidence(-1)).toBe(0);
});

test("Llama Guard output parsing", () => {
  expect(parseGuard("safe")).toEqual({ score: 0, categories: [], parsed: true });
  expect(parseGuard("unsafe\nS2,S9")).toEqual({ score: 1, categories: ["S2", "S9"], parsed: true });
  expect(parseGuard("I cannot help").parsed).toBe(false);
});
