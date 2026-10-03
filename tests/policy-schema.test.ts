// SPEC §11.2: shipped policies, feed, fixtures and seeds all validate; strictness and hashing behave.
import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import YAML from "yaml";
import { SeedFileSchema, TestCaseFileSchema } from "@tollgate/policy";
import { loadFeed, loadPolicy, parsePolicyText } from "@tollgate/policy/loader";

const root = resolve(import.meta.dir, "..");
const r = (p: string) => join(root, p);

describe("policy-schema [deterministic]", () => {
  for (const f of ["policy.yaml", "policy.strict.yaml", "policy.monitor.yaml", "tests/policy.test.yaml"]) {
    test(`${f} validates`, () => {
      const res = loadPolicy(r(f));
      expect(res.ok ? null : res.errors).toBeNull();
    });
  }

  test("feed validates and compiles every regex", () => {
    const res = loadFeed(r("feeds/ai-exploits.json"));
    expect(res.ok ? res.value.entries.length : res.errors).toBe(14);
  });

  const base = readFileSync(r("policy.yaml"), "utf8");

  test("misspelt key is rejected with its path", () => {
    const res = parsePolicyText(base.replace(/^controls:/m, "contorls:"));
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.errors.map((e) => e.message).join(" ")).toContain("contorls");
  });

  test("bad enum is rejected with its path", () => {
    const res = parsePolicyText(base.replace(/^mode: enforce/m, "mode: banana"));
    expect(res.ok ? null : res.errors[0]?.path).toBe("mode");
  });

  test("hash is stable under key order and comments", () => {
    const a = parsePolicyText(base);
    const b = parsePolicyText("# extra comment\n" + base.replace(/^(version: \d+)(.*)$/m, "$1"));
    expect(a.ok && b.ok && a.hash === b.hash).toBe(true);
    const swapped = parsePolicyText(base.replace(/^mode: enforce.*$/m, "") + "\nmode: enforce\n");
    expect(a.ok && swapped.ok && a.hash === swapped.hash).toBe(true);
  });

  test("every fixture file validates and ids are unique", () => {
    const ids = new Set<string>();
    for (const f of readdirSync(r("tests/cases")).filter((x) => x.endsWith(".yaml"))) {
      const parsed = TestCaseFileSchema.safeParse(YAML.parse(readFileSync(r(`tests/cases/${f}`), "utf8")));
      expect(parsed.success ? null : `${f}: ${parsed.error.issues[0]?.path.join(".")} ${parsed.error.issues[0]?.message}`).toBeNull();
      for (const c of parsed.data ?? []) { expect(ids.has(c.id) ? c.id : null).toBeNull(); ids.add(c.id); }
    }
  });

  test("every seed file validates", () => {
    for (const f of readdirSync(r("tests/redteam/seeds")).filter((x) => x.endsWith(".yaml"))) {
      const parsed = SeedFileSchema.safeParse(YAML.parse(readFileSync(r(`tests/redteam/seeds/${f}`), "utf8")));
      expect(parsed.success ? null : `${f}: ${parsed.error.issues[0]?.path.join(".")} ${parsed.error.issues[0]?.message}`).toBeNull();
    }
  });
});
