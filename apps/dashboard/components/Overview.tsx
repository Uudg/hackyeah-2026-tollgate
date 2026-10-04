"use client";
import Link from "next/link";
import { useMemo } from "react";
import type { DecisionRecord } from "@tollgate/policy";
import { api } from "@/lib/gateway";
import { useAsync, useNow } from "@/lib/hooks";
import { fmtInt, fmtMsUnit, fmtPct, fmtTime, fmtUsd, relTime } from "@/lib/format";
import { Canary } from "./Canary";
import { useLive } from "./Live";
import { DecisionBadge, Empty, ErrorNote, Loading, PageHeader, Panel, ScrollX, Tile, cn } from "./ui";
import { HBars, LatencyBars, RatioBar, StackedBars, type Bucket } from "./charts";

const MINUTES = 60;

async function loadHistory(): Promise<DecisionRecord[]> {
  const from = new Date(Date.now() - MINUTES * 60_000).toISOString();
  const out: DecisionRecord[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < 4; i++) {
    const page = await api.audit({ limit: 500, from, cursor });
    out.push(...page.items);
    if (!page.nextCursor) break;
    cursor = page.nextCursor;
  }
  return out;
}

function bucketize(records: DecisionRecord[], now: number): Bucket[] {
  const start = Math.floor(now / 60_000) * 60_000 - (MINUTES - 1) * 60_000;
  const buckets: Bucket[] = Array.from({ length: MINUTES }, (_, i) => ({
    label: i === MINUTES - 1 ? "now" : `-${MINUTES - 1 - i}m`,
    segs: [{ key: "redact", value: 0 }, { key: "block", value: 0 }, { key: "kill_session", value: 0 }],
  }));
  for (const r of records) {
    if (r.decision === "allow") continue;
    const i = Math.floor((new Date(r.ts).getTime() - start) / 60_000);
    if (i < 0 || i >= MINUTES) continue;
    const seg = buckets[i]!.segs.find((s) => s.key === r.decision);
    if (seg) seg.value++;
  }
  return buckets;
}

export default function Overview() {
  const { metrics: tick, decisions, policy, policyRejected, policyFlash } = useLive();
  const init = useAsync(() => api.metrics(), []);
  const history = useAsync(loadHistory, []);
  const now = useNow(5000);

  const metrics = tick ?? init.data;
  const records = useMemo(() => {
    const map = new Map<string, DecisionRecord>();
    for (const r of history.data ?? []) map.set(r.id, r);
    for (const r of decisions) map.set(r.id, r);
    return [...map.values()];
  }, [history.data, decisions]);
  const buckets = useMemo(() => bucketize(records, now), [records, now]);
  // Newest first: past records from /admin/audit plus live SSE decisions, so the list is filled on page load.
  const latest = useMemo(() => [...records].sort((a, b) => (a.ts < b.ts ? 1 : a.ts > b.ts ? -1 : 0)).slice(0, 12), [records]);

  if (init.error && !metrics) return <ErrorNote onRetry={init.reload}>{init.error}</ErrorNote>;
  if (!metrics) return <Loading what="Loading metrics" />;

  const byD = metrics.requests.byDecision;
  const blocked = (byD.block ?? 0) + (byD.kill_session ?? 0);
  const spendRows = Object.entries(metrics.spend.byAgent).map(([agent, s]) => ({ agent, ...s }));
  const usd = spendRows.reduce((a, s) => a + s.usd, 0);
  const tokens = spendRows.reduce((a, s) => a + s.tokensIn + s.tokensOut, 0);
  const total = metrics.latency.total;
  const stageRows = (["auth", "budget", "tier0", "tier1", "tier2", "upstream", "output"] as const)
    .map((s) => ({ stage: s, p50: metrics.latency[s]?.p50 ?? 0, p95: metrics.latency[s]?.p95 ?? 0 }));
  const budgets = [...metrics.budgets].sort((a, b) => b.ratio - a.ratio).slice(0, 7);
  const circuits = metrics.circuit ? (Array.isArray(metrics.circuit) ? metrics.circuit : [metrics.circuit]) : [];
  const breakdown = Object.entries(metrics.posture.breakdown);

  return (
    <>
      <PageHeader title="Overview" sub={`Window ${metrics.window}. Updates every 2 s from the event stream.`} />

      {policy && (
        <div key={policyFlash} className={cn("mb-3 rounded-md border px-3 py-2 text-[12px]", policyRejected ? "border-block/40 bg-block-bg" : "border-line bg-panel", policyFlash > 0 && !policyRejected && "flash")}>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <span className="mono text-[12px] font-medium">v{policy.version} · {policy.hash} · {policy.policy.mode}</span>
            <span className="text-mute">loaded {relTime(policy.loadedAt, now)}</span>
            {policy.policy.mode === "monitor" && <span className="text-mute">monitor mode: decisions are recorded as &quot;would block&quot; and traffic passes</span>}
            <Link href="/policy" className="ml-auto inline-flex text-accent underline max-md:min-h-10 max-md:items-center">Open policy</Link>
          </div>
          {policyRejected && (
            <div className="mt-1.5 text-block">
              <div className="font-semibold">Last edit rejected, previous version still active ({relTime(policyRejected.ts, now)})</div>
              <ul className="mono mt-0.5 space-y-0.5 text-[11px]">{policyRejected.errors.slice(0, 5).map((e, i) => <li key={i}>{e}</li>)}</ul>
            </div>
          )}
        </div>
      )}

      <div className="grid grid-cols-2 gap-2 md:grid-cols-3 xl:grid-cols-6">
        <Tile label="Posture score" value={<>{metrics.posture.score}<span className="text-[13px] font-normal text-mute"> / 100</span></>} sub="hover for breakdown">
          <div className="mb-1 font-semibold">Score terms (points)</div>
          <dl>
            {breakdown.map(([k, v]) => (
              <div key={k} className="flex justify-between gap-2 py-px"><dt className="text-mute">{k}</dt><dd className="mono">{k === "penalties" && v > 0 ? `-${v}` : v}</dd></div>
            ))}
          </dl>
        </Tile>
        <Tile label="Requests (5 m)" value={fmtInt(metrics.requests.total)} sub={`${metrics.throughput_rps} req/s`} />
        <Tile label="Blocked (5 m)" value={fmtInt(blocked)} sub={`${fmtInt(byD.redact ?? 0)} redacted · ${fmtPct(metrics.requests.total ? blocked / metrics.requests.total : 0, 1)} blocked`} />
        <Tile label="Spend today" value={fmtUsd(usd)} sub={`${fmtInt(tokens)} tokens`} />
        <Tile label="Latency p50 / p95" value={<>{fmtMsUnit(total?.p50)} <span className="text-[13px] font-normal text-mute">/ {fmtMsUnit(total?.p95)}</span></>} sub="total, whole request" />
        <Tile label="Gateway overhead p50" value={fmtMsUnit(metrics.overhead_ms.p50)} sub={`p95 ${fmtMsUnit(metrics.overhead_ms.p95)}, total minus upstream`} />
      </div>

      <div className="mt-3 grid grid-cols-1 gap-3 lg:grid-cols-3">
        <Panel className="lg:col-span-2" title="Non-allow decisions per minute, last 60 min"
          actions={<span className="flex gap-3 text-[11px] text-mute">{(["redact", "block", "kill_session"] as const).map((k) => <span key={k}><i className="mr-1 inline-block h-2 w-2 rounded-sm align-middle" style={{ background: { redact: "#c08a14", block: "#b3261e", kill_session: "#6a3fa3" }[k] }} />{k === "kill_session" ? "kill" : k}</span>)}</span>}>
          {history.loading && records.length === 0 ? <Loading /> : <StackedBars data={buckets} />}
          {history.error && <div className="mt-2"><ErrorNote onRetry={history.reload}>History: {history.error}</ErrorNote></div>}
        </Panel>
        <Panel title="Spend by agent, today">
          {spendRows.length ? <HBars rows={spendRows.sort((a, b) => b.usd - a.usd).map((s) => ({ label: s.agent, value: s.usd }))} format={fmtUsd} /> : <Empty>No spend yet.</Empty>}
          <p className="mt-2 text-[11px] text-mute">Local models are priced at 0 unless pricing.json says otherwise; tokens and compute still count against budgets.</p>
        </Panel>

        <Panel title="Latency per stage">
          <LatencyBars rows={stageRows} />
        </Panel>
        <Panel title="Budgets, highest use first" actions={circuits.map((c) => <span key={c.host} className="mono text-[11px] text-mute">circuit {c.host}: {c.state}</span>)}>
          <ul className="space-y-2">
            {budgets.map((b) => (
              <li key={`${b.agentId}-${b.kind}-${b.window}`}>
                <div className="mb-0.5 flex justify-between gap-2 text-[11px]">
                  <span className="truncate">{b.agentId} <span className="text-mute">{b.kind ?? ""}/{b.window}</span></span>
                  <span className="mono shrink-0 text-mute">{b.kind === "usd" ? `${fmtUsd(b.used)} of ${fmtUsd(b.limit)}` : `${fmtInt(b.used)} of ${fmtInt(b.limit)}`} · {fmtPct(b.ratio)}</span>
                </div>
                <RatioBar ratio={b.ratio} />
              </li>
            ))}
          </ul>
        </Panel>
        <Panel title="Live decisions" actions={<Link href="/security" className="inline-flex text-[11px] text-accent underline max-md:min-h-10 max-md:items-center">All events</Link>} bodyClass="p-0">
          {latest.length === 0 ? <Empty><Canary state="idle" className="mx-auto mb-1.5 block w-16" />Waiting for traffic.</Empty> : (
            <ScrollX className="max-h-[300px] overflow-y-auto">
              <table className="tbl">
                <tbody>
                  {latest.map((d) => (
                    <tr key={d.id}>
                      <td className="mono text-mute">{fmtTime(d.ts)}</td>
                      <td>{d.agentId}</td>
                      <td><DecisionBadge decision={d.decision} enforced={d.enforced} /></td>
                      <td className="mono"><Link className="hover:underline" href={`/security/events/${d.id}`}>{d.ruleId ?? "-"}</Link></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </ScrollX>
          )}
        </Panel>
      </div>
    </>
  );
}
