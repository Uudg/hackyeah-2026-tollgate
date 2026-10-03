// Loads and validates every fixture under tests/cases/** (SPEC §11.1). Duplicate ids fail the run.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import YAML from "yaml";
import { TestCaseFileSchema, type TestCase } from "@tollgate/policy";

export interface LoadedCase { file: string; c: TestCase }

function yamlFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) return yamlFiles(p);
    return /\.ya?ml$/.test(name) ? [p] : [];
  });
}

export function loadCases(dir: string, root: string): LoadedCase[] {
  const out: LoadedCase[] = [];
  const seen = new Map<string, string>();
  for (const path of yamlFiles(dir).sort()) {
    const file = relative(root, path);
    const data: unknown = YAML.parse(readFileSync(path, "utf8")) ?? [];
    const parsed = TestCaseFileSchema.safeParse(data);
    if (!parsed.success) {
      const msg = parsed.error.issues.slice(0, 5).map((i) => `${i.path.join(".")}: ${i.message}`).join("\n  ");
      throw new Error(`${file} is not a valid fixture file:\n  ${msg}`);
    }
    for (const c of parsed.data) {
      const prev = seen.get(c.id);
      if (prev) throw new Error(`duplicate fixture id "${c.id}" in ${file} (also in ${prev})`);
      seen.set(c.id, file);
      out.push({ file, c });
    }
  }
  return out;
}
