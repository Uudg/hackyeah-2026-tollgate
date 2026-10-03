// bun run policy:check [file] — validate a policy file; prints zod issues, exit 1 on failure.
import { loadPolicy } from "@tollgate/policy/loader";

const path = process.argv[2] ?? "./policy.yaml";
const res = loadPolicy(path);
if (!res.ok) {
  console.error(`policy rejected: ${path}`);
  for (const e of res.errors) console.error(`  ${e.path}: ${e.message}`);
  process.exit(1);
}
console.log(`policy ok: ${path} version ${res.value.version} hash ${res.hash} (${Object.keys(res.value.agents).length} agents)`);
