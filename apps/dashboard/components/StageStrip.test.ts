// Playground stage strip when Ollama is slow or times out: times read "6.3 s" (never "6.32s ms") and a failed tier
// reads "timed out" or "unavailable" (never "undefined").
import { describe, expect, test } from "bun:test";
import type { DecisionRecord, Hit } from "@tollgate/policy";
import { fmtMsUnit } from "../lib/format.ts";
import { buildCells, stageTime } from "./StageStrip.tsx";

const record = (over: Partial<DecisionRecord>): DecisionRecord => ({
  id: "01TEST", ts: "2026-10-04T05:00:00.000Z", agentId: "demo-agent", sessionId: "s1", model: "llama3.2:3b",
  direction: "request", decision: "allow", enforced: true, tier: null, ruleId: null, controlId: null, owasp: [], hits: [],
  policyVersion: "p-0123456789ab", policyDeclaredVersion: 1, feedVersion: null,
  latencyMs: { auth: 0.1, budget: 0.1, tier0: 0.2, tier1: 0, tier2: 0, upstream: 0, output: 0, total: 0.5 },
  excerptRedacted: null, tokensIn: 0, tokensOut: 0, costUsd: 0, computeSeconds: 0, httpStatus: 200, details: {},
  ...over,
});
const unavailable = (ruleId: string, reason: string): Hit => ({ controlId: "prompt_injection", ruleId, action: "allow", owasp: ["LLM01"], details: { reason, fail_mode: "open" } });
const text = (rec: DecisionRecord) => buildCells(rec).map((c) => [stageTime(c), ...c.lines].join(" ")).join(" | ");

describe("deterministic · dashboard stage strip on a slow Ollama", () => {
  test("seconds are formatted once, with one unit", () => {
    expect(fmtMsUnit(6321.4)).toBe("6.3 s");
    expect(fmtMsUnit(92.4)).toBe("92 ms");
    expect(fmtMsUnit(undefined)).toBe("-");
  });

  test("a judge timeout reads 'timed out' with its time, never 'undefined' or 's ms'", () => {
    const rec = record({
      latencyMs: { auth: 0.1, budget: 0.1, tier0: 0.2, tier1: 73, tier2: 6002.7, upstream: 0, output: 0, total: 6080 },
      hits: [unavailable("semantic.judge_unavailable", "timeout after 6000 ms")],
      details: { tier1: { score: 0.5, categories: [], raw: "safe", model: "llama-guard3:1b", ms: 73 }, tier2: "unavailable" },
    });
    const cells = buildCells(rec);
    const t2 = cells.find((c) => c.stage === "tier2")!;
    expect(stageTime(t2)).toBe("6.0 s");
    expect(t2.lines[0]).toBe("timed out");
    expect(text(rec)).not.toMatch(/undefined|s ms/);
  });

  test("a classifier that is down reads 'unavailable'; a pending tier shows no time", () => {
    const rec = record({
      latencyMs: { auth: 0.1, budget: 0.1, tier0: 0.2, tier1: 1500.4, tier2: 0, upstream: 0, output: 0, total: 1501 },
      hits: [unavailable("semantic.unavailable", "connect ECONNREFUSED 127.0.0.1:11434")],
      details: { tier1: "unavailable" },
    });
    const cells = buildCells(rec);
    expect(cells.find((c) => c.stage === "tier1")!.lines[0]).toBe("unavailable");
    expect(stageTime(cells.find((c) => c.stage === "tier2")!)).toBe("");
    expect(text(rec)).not.toMatch(/undefined|s ms/);
  });

  test("a judge object with missing fields prints only what is there", () => {
    const rec = record({ latencyMs: { auth: 0.1, budget: 0.1, tier0: 0.2, tier1: 60, tier2: 700, upstream: 0, output: 0, total: 761 }, details: { tier1: { categories: [] }, tier2: { model: "llama3.2:3b" } } });
    expect(text(rec)).not.toMatch(/undefined|score \?/);
  });
});
