// bun run redteam: starts a Red Team Loop run on the live gateway (POST /admin/redteam/run), follows it, and prints
// control | attempts | bypasses | bypass rate. The run itself happens inside the gateway (runner.ts), same as the dashboard.
import { parseArgs } from "node:util";
import "../env.ts";

const { values: a } = parseArgs({
  options: {
    seeds: { type: "string" },
    mutators: { type: "string" },
    control: { type: "string" },
    depth: { type: "string" },
    "max-attempts": { type: "string" },
    minutes: { type: "string" },
    concurrency: { type: "string" },
    "include-model-mutators": { type: "boolean" },
    "rng-seed": { type: "string" },
    gateway: { type: "string" },
    help: { type: "boolean", short: "h" },
  },
});

if (a.help) {
  console.log(`bun run redteam [--control prompt_injection] [--seeds a,b] [--mutators base64,leetspeak] [--depth 1|2]
  [--max-attempts 500] [--minutes 10] [--concurrency 4] [--include-model-mutators] [--rng-seed N] [--gateway http://localhost:8787]
Needs ADMIN_TOKEN (from .env or the environment) and a running gateway.`);
  process.exit(0);
}

const GATEWAY = (a.gateway ?? process.env.TOLLGATE_URL ?? `http://localhost:${process.env.TOLLGATE_PORT ?? 8787}`).replace(/\/$/, "");
const ADMIN = process.env.ADMIN_TOKEN ?? "";
const list = (v?: string) => (v ? v.split(",").map((s) => s.trim()).filter(Boolean) : undefined);
const num = (v?: string) => (v === undefined ? undefined : Number(v));

const body = {
  seeds: list(a.seeds), mutators: list(a.mutators), control: a.control,
  max_depth: num(a.depth), max_attempts: num(a["max-attempts"]), max_minutes: num(a.minutes), concurrency: num(a.concurrency),
  include_model_mutators: a["include-model-mutators"], rng_seed: num(a["rng-seed"]),
};
const headers = { authorization: `Bearer ${ADMIN}`, "content-type": "application/json" };

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${GATEWAY}/admin${path}`, { ...init, headers });
  const json = (await res.json()) as T & { error?: { message: string } };
  if (!res.ok) throw new Error(`${res.status} ${json.error?.message ?? JSON.stringify(json)}`);
  return json;
}

interface Status {
  run: { id: string; status: string; attempts: number; bypasses: number; config: { skipped?: number; stop_reason?: string | null; rng_seed?: number } | null } | null;
  byControl: Array<{ controlId: string; attempts: number; bypasses: number; bypassRate: number | null }>;
  recent: Array<{ seedId: string; mutators: string[]; decision: string; ruleId: string | null; bypass: boolean; generatedCasePath: string | null }>;
}

try {
  const { runId } = await api<{ runId: string }>("/redteam/run", { method: "POST", body: JSON.stringify(body) });
  console.log(`run ${runId} started against ${GATEWAY}`);
  let s: Status;
  for (;;) {
    await Bun.sleep(1000);
    s = await api<Status>(`/redteam/status?runId=${runId}`);
    if (!s.run) throw new Error("run disappeared");
    process.stdout.write(`\r  ${s.run.status}: ${s.run.attempts} attempts, ${s.run.bypasses} bypasses   `);
    if (s.run.status !== "running") break;
  }
  process.stdout.write("\n\n");
  const rows = s.byControl.map((r) => [r.controlId, String(r.attempts), String(r.bypasses), r.bypassRate === null ? "-" : `${(r.bypassRate * 100).toFixed(1)} %`]);
  const head = ["control", "attempts", "bypasses", "bypass rate"];
  const w = head.map((h, i) => Math.max(h.length, ...rows.map((r) => r[i]!.length)));
  const line = (r: string[]) => `| ${r.map((c, i) => (i === 0 ? c.padEnd(w[i]!) : c.padStart(w[i]!))).join(" | ")} |`;
  console.log([line(head), `|${w.map((n) => "-".repeat(n + 2)).join("|")}|`, ...rows.map(line)].join("\n"));
  const total = s.run!.attempts;
  console.log(`\ntotal ${total} attempts, ${s.run!.bypasses} bypasses (${total ? ((s.run!.bypasses / total) * 100).toFixed(1) : "0"} %), ${s.run!.config?.skipped ?? 0} skipped, rng seed ${s.run!.config?.rng_seed ?? "?"}${s.run!.config?.stop_reason ? `, stopped: ${s.run!.config.stop_reason}` : ""}`);
  const files = [...new Set(s.recent.map((r) => r.generatedCasePath).filter(Boolean))];
  if (files.length) console.log(`failing cases written to ${files.join(", ")}`);
  process.exit(s.run!.status === "done" ? 0 : 1);
} catch (err) {
  console.error(`red team run failed: ${err instanceof Error ? err.message : String(err)}`);
  if (!ADMIN) console.error("ADMIN_TOKEN is not set (run ./scripts/setup.sh or export it).");
  process.exit(1);
}
