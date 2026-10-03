// bun run validate — checks policy.yaml, the feed, every test fixture and red-team seed against the frozen schemas.
// Exit 1 on the first file with issues (all issues of that file are printed).
import { readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import YAML from "yaml";
import { parseFeed, parsePolicy, readText, formatIssues, type Issue } from "../loader.ts";
import { SeedFileSchema, TestCaseFileSchema } from "../schema/testcase.ts";

const root = resolve(import.meta.dir, "../../../..");
const policyPath = resolve(root, process.env.POLICY_PATH ?? "policy.yaml");
const feedPath = resolve(root, process.env.FEED_PATH ?? "feeds/ai-exploits.json");

let failed = 0;
const report = (file: string, issues: Issue[] | null, note = "") => {
  if (issues === null) return console.log(`ok    ${file}${note}`);
  failed++;
  console.log(`FAIL  ${file}`);
  for (const i of issues.slice(0, 20)) console.log(`      ${i.path}: ${i.message}`);
};

function check(path: string, parse: (raw: string) => { ok: true } | { ok: false; issues: Issue[] }, note = "") {
  const raw = readText(path);
  if (raw === null) return report(path, [{ path: "(file)", message: "not found" }]);
  const res = parse(raw);
  report(path.replace(root + "/", ""), res.ok ? null : res.issues, note);
}

check(policyPath, parsePolicy);
check(feedPath, parseFeed);

const ids = new Map<string, string>();
function yamlList(dir: string, schema: typeof TestCaseFileSchema | typeof SeedFileSchema) {
  let files: string[] = [];
  try { files = readdirSync(dir).filter((f) => f.endsWith(".yaml")).sort(); }
  catch { return; } // folder not created yet
  for (const f of files) {
    check(join(dir, f), (raw) => {
      let data: unknown;
      try { data = YAML.parse(raw) ?? []; }
      catch (err) { return { ok: false, issues: [{ path: "(yaml)", message: (err as Error).message }] }; }
      const parsed = schema.safeParse(data);
      if (!parsed.success) return { ok: false, issues: formatIssues(parsed.error) };
      const dupes: Issue[] = [];
      parsed.data.forEach((c, i) => {
        const prev = ids.get(c.id);
        if (prev) dupes.push({ path: `${i}.id`, message: `duplicate id ${c.id} (also in ${prev})` });
        ids.set(c.id, f);
      });
      return dupes.length ? { ok: false, issues: dupes } : { ok: true };
    });
  }
}
yamlList(join(root, "tests/cases"), TestCaseFileSchema);
yamlList(join(root, "tests/redteam/seeds"), SeedFileSchema);

if (failed) {
  console.log(`\n${failed} file(s) invalid`);
  process.exit(1);
}
console.log("\nall valid");
