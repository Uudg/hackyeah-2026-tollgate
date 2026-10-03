// bun run feed:check [file] — validate a signature feed; every regex is compiled. Exit 1 on failure.
import { loadFeed } from "@tollgate/policy/loader";

const path = process.argv[2] ?? "./feeds/ai-exploits.json";
const res = loadFeed(path);
if (!res.ok) {
  console.error(`feed rejected: ${path}`);
  for (const e of res.errors) console.error(`  ${e.path}: ${e.message}`);
  process.exit(1);
}
const enabled = res.value.entries.filter((e) => e.enabled).length;
console.log(`feed ok: ${path} hash ${res.hash} (${res.value.entries.length} entries, ${enabled} enabled)`);
