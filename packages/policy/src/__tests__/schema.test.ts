import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseFeed, parsePolicy } from "../loader.ts";
import { owaspFor, RULE_OWASP } from "../owasp.ts";
import { TestCaseSchema } from "../schema/testcase.ts";

const root = resolve(import.meta.dir, "../../../..");
const minimal = "version: 1\nmodels: { allow: [llama3.2:3b] }\nagents: { demo: { key: tg_demo_123 } }\n";

describe("policy schema", () => {
  test("shipped policy.yaml is valid", () => {
    const res = parsePolicy(readFileSync(resolve(root, "policy.yaml"), "utf8"));
    expect(res.ok ? null : res.issues).toBeNull();
  });
  test("minimal file gets every default", () => {
    const res = parsePolicy(minimal);
    if (!res.ok) throw new Error(JSON.stringify(res.issues));
    expect(res.value.mode).toBe("enforce");
    expect(res.value.controls.pii.action).toBe("redact");
    expect(res.value.semantic.on_timeout).toBe("block");
    expect(res.value.budgets.loop_breaker.max_repeats).toBe(5);
    expect(res.version).toMatch(/^[a-f0-9]{12}$/);
  });
  test("misspelt key is rejected with its path", () => {
    const res = parsePolicy(minimal + "contorls: {}\n");
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.issues[0]?.message).toContain("contorls");
  });
  test("bad action enum is rejected", () => {
    const res = parsePolicy(minimal + "controls: { pii: { action: banana } }\n");
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.issues[0]?.path).toBe("controls.pii.action");
  });
  test("invalid YAML is a typed failure, not a throw", () => {
    const res = parsePolicy("version: [1\n");
    expect(res.ok).toBe(false);
  });
  test("version changes with content", () => {
    const a = parsePolicy(minimal), b = parsePolicy(minimal + "mode: monitor\n");
    expect(a.ok && b.ok && a.version !== b.version).toBe(true);
  });
});

describe("feed schema", () => {
  test("shipped feed is valid", () => {
    const res = parseFeed(readFileSync(resolve(root, "feeds/ai-exploits.json"), "utf8"));
    expect(res.ok ? null : res.issues).toBeNull();
  });
  test("bad regex is rejected with the entry path", () => {
    const feed = { version: 1, updated_at: "x", entries: [{ id: "a", title: "a", cve: null, type: "regex", pattern: "(", applies_to: ["input"], action: "block", owasp: ["LLM01"], source: "https://x.example" }] };
    const res = parseFeed(JSON.stringify(feed));
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.issues[0]?.path).toBe("entries.0.pattern");
  });
});

describe("owasp table", () => {
  test("prefix lookup", () => {
    expect(owaspFor("content_safety.S9")).toEqual(["LLM01"]);
    expect(owaspFor("pii.iban")).toEqual(["LLM02"]);
    expect(owaspFor("nope.nothing")).toEqual([]);
  });
  test("every rule id is well-formed", () => {
    for (const id of Object.keys(RULE_OWASP)) expect(id).toMatch(/^[a-z_]+(\.[A-Za-z0-9_-]+)*$/);
  });
});

describe("test case schema", () => {
  test("input or messages, not both", () => {
    const base = { id: "a", control: "pii", owasp: ["LLM02"], expect: { decision: "allow" } };
    expect(TestCaseSchema.safeParse({ ...base, input: "x" }).success).toBe(true);
    expect(TestCaseSchema.safeParse(base).success).toBe(false);
    expect(TestCaseSchema.safeParse({ ...base, input: "x", messages: [] }).success).toBe(false);
  });
});
