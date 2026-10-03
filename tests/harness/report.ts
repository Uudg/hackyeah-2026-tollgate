// Collects per-case results and prints the summary table after the run (SPEC §11.2). Also writes
// tests/.last-report.json, which the dashboard reads for "generated cases passing".
import { writeFileSync } from "node:fs";
import { join } from "node:path";

export interface CaseResult { id: string; control: string; owasp: string[]; status: "pass" | "fail" | "skip"; ms: number; tags: string[]; reason?: string }

const results: CaseResult[] = [];
export const record = (r: CaseResult) => { results.push(r); };
/** Open red-team bypasses (tests/cases/generated/*-open.yaml): counted, not run, not in pass/fail/skip. */
const backlog: string[] = [];
export const recordBacklog = (id: string) => { backlog.push(id); };

export function printSummary(meta: { policy: string; feed: string | null; root: string; startedAt: number }) {
  if (results.length === 0 && backlog.length === 0) return;
  const byControl = new Map<string, { pass: number; fail: number; skip: number; owasp: Set<string>; modelSkips: number }>();
  const byOwasp = new Map<string, { pass: number; total: number }>();
  for (const r of results) {
    const row = byControl.get(r.control) ?? { pass: 0, fail: 0, skip: 0, owasp: new Set<string>(), modelSkips: 0 };
    row[r.status]++;
    if (r.status === "skip" && r.tags.includes("model")) row.modelSkips++;
    r.owasp.forEach((o) => row.owasp.add(o));
    byControl.set(r.control, row);
    if (r.status !== "skip") for (const o of r.owasp) {
      const s = byOwasp.get(o) ?? { pass: 0, total: 0 };
      s.total++; if (r.status === "pass") s.pass++;
      byOwasp.set(o, s);
    }
  }
  const pad = (s: string | number, n: number) => String(s).padStart(n);
  const lines = [`Tollgate test summary  (policy ${meta.policy}, feed ${meta.feed ?? "none"})`, `${"control".padEnd(18)}${pad("pass", 6)}${pad("fail", 6)}${pad("skip", 6)}   OWASP`];
  for (const [control, r] of [...byControl].sort()) {
    const note = r.modelSkips ? `     (${r.modelSkips} skipped: model-backed)` : "";
    lines.push(`${control.padEnd(18)}${pad(r.pass, 6)}${pad(r.fail, 6)}${pad(r.skip, 6)}   ${[...r.owasp].sort().join(", ")}${note}`);
  }
  const owaspLine = [...byOwasp].sort(([a], [b]) => a.localeCompare(b)).map(([o, s]) => `${o} ${s.pass}/${s.total}`).join("  ");
  lines.push(`by OWASP id: ${owaspLine}`);
  const total = { pass: results.filter((r) => r.status === "pass").length, fail: results.filter((r) => r.status === "fail").length, skip: results.filter((r) => r.status === "skip").length };
  lines.push(`TOTAL  ${total.pass} pass · ${total.fail} fail · ${total.skip} skip   in ${((Date.now() - meta.startedAt) / 1000).toFixed(1)} s`);
  if (backlog.length) lines.push(`known open bypasses (red-team backlog): ${backlog.length}   not run, not counted above; tests/cases/generated/*-open.yaml, run them with TOLLGATE_BACKLOG=1 bun test`);
  for (const r of results.filter((x) => x.status === "fail")) lines.push(`  FAIL ${r.id}: ${r.reason ?? ""}`);
  console.log("\n" + lines.join("\n"));
  const generated = results.filter((r) => r.tags.includes("generated"));
  writeFileSync(join(meta.root, "tests/.last-report.json"), JSON.stringify({
    ts: new Date().toISOString(), policy: meta.policy, feed: meta.feed, total, results,
    generated: { total: generated.length + backlog.length, passing: generated.filter((r) => r.status === "pass").length, backlog: backlog.length },
  }, null, 2));
}
