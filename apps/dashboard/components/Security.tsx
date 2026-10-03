"use client";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import type { DecisionRecord } from "@tollgate/policy";
import { api, exportAudit } from "@/lib/gateway";
import { OWASP_ALL, type AuditQuery, type AuditVerify } from "@/lib/contract";
import { useAsync, useNow } from "@/lib/hooks";
import { useConnection } from "@/lib/gateway";
import { downloadText, errMsg, fmtDateTime, fmtTime, relTime, shortId } from "@/lib/format";
import { useLive } from "./Live";
import { Chip, DecisionBadge, Empty, ErrorNote, Loading, PageHeader, Panel, ScrollX } from "./ui";

const RANGES = [
  { id: "15m", label: "Last 15 min", ms: 15 * 60_000 },
  { id: "1h", label: "Last hour", ms: 3600_000 },
  { id: "24h", label: "Last 24 h", ms: 86_400_000 },
  { id: "all", label: "All time", ms: 0 },
] as const;

/** Columns that only show from the md breakpoint up; on a phone the row is Time, Agent and Decision with the rule under it. */
const WIDE = "max-md:hidden";

interface Filters { agent: string; decision: string; rule: string; tier: string; owasp: string; direction: string; range: string; q: string }
const EMPTY: Filters = { agent: "", decision: "", rule: "", tier: "", owasp: "", direction: "", range: "1h", q: "" };

function matches(r: DecisionRecord, f: Filters, fromMs: number | null): boolean {
  if (f.agent && r.agentId !== f.agent) return false;
  if (f.decision && r.decision !== f.decision) return false;
  if (f.rule && !(r.ruleId ?? "").toLowerCase().includes(f.rule.toLowerCase())) return false;
  if (f.tier && String(r.tier ?? "-") !== f.tier) return false;
  if (f.owasp && !r.owasp.includes(f.owasp)) return false;
  if (f.direction && r.direction !== f.direction) return false;
  if (fromMs !== null && new Date(r.ts).getTime() < fromMs) return false;
  if (f.q && !`${r.ruleId ?? ""} ${r.excerptRedacted ?? ""} ${r.model}`.toLowerCase().includes(f.q.toLowerCase())) return false;
  return true;
}

function useDebounced<T>(v: T, ms = 300): T {
  const [d, setD] = useState(v);
  useEffect(() => { const t = setTimeout(() => setD(v), ms); return () => clearTimeout(t); }, [v, ms]);
  return d;
}

function KilledSessions() {
  const { hub } = useLive();
  const req = useAsync(() => api.killedSessions(), []);
  const [err, setErr] = useState<string | null>(null);
  const { reload } = req;
  useEffect(() => hub.on("session.killed", () => reload()), [hub, reload]);
  const items = req.data?.items ?? [];
  return (
    <details className="mb-3 rounded-md border border-line bg-panel">
      <summary className="cursor-pointer px-3 py-2 text-[12px] font-semibold">Killed sessions ({items.length})</summary>
      <div className="border-t border-line">
        {err && <div className="p-2"><ErrorNote>{err}</ErrorNote></div>}
        {items.length === 0 ? <Empty>No killed sessions.</Empty> : (
          <ScrollX>
            <table className="tbl">
              <thead><tr><th>Killed</th><th>Agent</th><th>Session</th><th>Reason</th><th>Event</th><th /></tr></thead>
              <tbody>
                {items.map((k) => (
                  <tr key={k.session_id}>
                    <td>{fmtDateTime(k.ts)}</td><td>{k.agent_id}</td><td className="mono">{k.session_id}</td><td className="mono">{k.reason}</td>
                    <td>{k.event_id ? <Link className="mono inline-flex min-h-10 items-center text-accent underline md:min-h-0" href={`/security/events/${k.event_id}`}>{shortId(k.event_id)}</Link> : "-"}</td>
                    <td className="text-right"><button className="btn" onClick={async () => { try { setErr(null); await api.restoreSession(k.session_id); reload(); } catch (e) { setErr(errMsg(e)); } }}>Restore</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </ScrollX>
        )}
      </div>
    </details>
  );
}

export default function Security() {
  const router = useRouter();
  const { policy, decisions } = useLive();
  const now = useNow(15000);
  const [f, setF] = useState<Filters>(EMPTY);
  // "Now" for the time-range filter, fixed when the range is chosen so the list does not refetch every minute.
  const [anchor, setAnchor] = useState(() => Date.now());
  const df = useDebounced(f);
  const [rows, setRows] = useState<DecisionRecord[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [more, setMore] = useState<{ loading: boolean; error: string | null }>({ loading: false, error: null });
  const [verify, setVerify] = useState<{ busy: boolean; result?: AuditVerify; error?: string }>({ busy: false });

  const range = RANGES.find((r) => r.id === df.range);
  const fromIso = range && range.ms ? new Date(anchor - range.ms).toISOString() : undefined;
  const query: AuditQuery = useMemo(() => ({
    agent: df.agent, decision: df.decision, rule: df.rule, tier: df.tier, owasp: df.owasp, direction: df.direction, q: df.q, from: fromIso,
  }), [df, fromIso]);

  // Rows loaded from the other data source (mock <-> live) must not stay on screen after the switch.
  const conn = useConnection();
  const connKey = `${conn.mode}:${conn.epoch}`;
  const [rowsKey, setRowsKey] = useState(connKey);
  if (rowsKey !== connKey) { setRowsKey(connKey); setRows([]); setCursor(null); }

  const list = useAsync(async () => {
    const page = await api.audit({ ...query, limit: 100 });
    setRows(page.items);
    setCursor(page.nextCursor);
    return page;
  }, [query]);

  const fromMs = fromIso ? new Date(fromIso).getTime() : null;
  const oldest = rows.length ? rows[rows.length - 1]!.ts : null;
  const merged = useMemo(() => {
    const seen = new Set(rows.map((r) => r.id));
    const live = decisions.filter((d) => !seen.has(d.id) && matches(d, df, fromMs) && (!cursor || (oldest !== null && d.ts >= oldest)));
    return [...live, ...rows].sort((a, b) => (a.id < b.id ? 1 : -1));
  }, [rows, decisions, df, fromMs, cursor, oldest]);

  const agents = useMemo(() => ["anonymous", ...Object.keys(policy?.policy.agents ?? {})], [policy]);
  const set = (k: keyof Filters) => (e: { target: { value: string } }) => {
    if (k === "range") setAnchor(Date.now());
    setF((x) => ({ ...x, [k]: e.target.value }));
  };

  async function loadMore() {
    if (!cursor) return;
    setMore({ loading: true, error: null });
    try {
      const page = await api.audit({ ...query, limit: 100, cursor });
      setRows((r) => [...r, ...page.items]);
      setCursor(page.nextCursor);
      setMore({ loading: false, error: null });
    } catch (e) { setMore({ loading: false, error: errMsg(e) }); }
  }
  async function runVerify() {
    setVerify({ busy: true });
    try { setVerify({ busy: false, result: await api.auditVerify() }); } catch (e) { setVerify({ busy: false, error: errMsg(e) }); }
  }

  return (
    <>
      <PageHeader title="Security events" sub="Every decision, newest first. New events appear at the top as they happen."
        actions={<>
          <button className="btn" onClick={() => exportAudit("jsonl", query, downloadText)}>Export JSONL</button>
          <button className="btn" onClick={() => exportAudit("csv", query, downloadText)}>Export CSV</button>
          <button className="btn btn-dark" onClick={runVerify} disabled={verify.busy}>{verify.busy ? "Verifying…" : "Verify chain"}</button>
        </>} />

      {(verify.result || verify.error) && (
        <div className="mono mb-3 rounded-md border border-line bg-panel px-3 py-2 text-[12px]" role="status">
          {verify.error ? <span className="text-block">{verify.error}</span>
            : verify.result!.ok ? `OK ${verify.result!.lines} lines, head ${verify.result!.headHash}`
            : <span className="text-block">BROKEN at line {verify.result!.firstBadLine} ({verify.result!.lines} lines checked)</span>}
        </div>
      )}

      <KilledSessions />

      <Panel className="mb-3" bodyClass="grid grid-cols-2 gap-2 md:grid-cols-4 xl:grid-cols-8">
        <div><label className="label" htmlFor="f-range">Time</label>
          <select id="f-range" className="field w-full" value={f.range} onChange={set("range")}>{RANGES.map((r) => <option key={r.id} value={r.id}>{r.label}</option>)}</select></div>
        <div><label className="label" htmlFor="f-agent">Agent</label>
          <select id="f-agent" className="field w-full" value={f.agent} onChange={set("agent")}><option value="">All</option>{agents.map((a) => <option key={a}>{a}</option>)}</select></div>
        <div><label className="label" htmlFor="f-dec">Decision</label>
          <select id="f-dec" className="field w-full" value={f.decision} onChange={set("decision")}><option value="">All</option><option>allow</option><option>redact</option><option>block</option><option>kill_session</option></select></div>
        <div><label className="label" htmlFor="f-tier">Tier</label>
          <select id="f-tier" className="field w-full" value={f.tier} onChange={set("tier")}><option value="">All</option><option value="0">0</option><option value="1">1</option><option value="2">2</option><option value="-">none</option></select></div>
        <div><label className="label" htmlFor="f-owasp">OWASP</label>
          <select id="f-owasp" className="field w-full" value={f.owasp} onChange={set("owasp")}><option value="">All</option>{OWASP_ALL.map((o) => <option key={o}>{o}</option>)}</select></div>
        <div><label className="label" htmlFor="f-dir">Direction</label>
          <select id="f-dir" className="field w-full" value={f.direction} onChange={set("direction")}><option value="">All</option><option>request</option><option>response</option><option>tool_call</option></select></div>
        <div><label className="label" htmlFor="f-rule">Rule contains</label>
          <input id="f-rule" className="field w-full" placeholder="pii." value={f.rule} onChange={set("rule")} /></div>
        <div><label className="label" htmlFor="f-q">Search</label>
          <input id="f-q" className="field w-full" placeholder="rule, excerpt, model" value={f.q} onChange={set("q")} /></div>
        <div className="col-span-2 md:col-span-4 xl:col-span-8"><button className="btn" onClick={() => { setAnchor(Date.now()); setF(EMPTY); }}>Reset filters</button></div>
      </Panel>

      {list.error && <ErrorNote onRetry={list.reload}>{list.error}</ErrorNote>}
      <Panel bodyClass="p-0" title={`${merged.length} events${cursor ? " loaded, more available" : ""}`}>
        {list.loading && merged.length === 0 ? <Loading /> : merged.length === 0 ? <Empty>No events match these filters.</Empty> : (
          <ScrollX className="max-h-[70vh] overflow-y-auto">
            <table className="tbl">
              <thead><tr><th>Time</th><th>Agent</th><th>Decision<span className="md:hidden"> / rule</span></th><th className={WIDE}>Tier</th><th className={WIDE}>Rule</th><th className={WIDE}>OWASP</th><th className={WIDE}>Model</th><th className={`num ${WIDE}`}>Latency ms</th><th className={WIDE}>Policy</th></tr></thead>
              <tbody>
                {merged.map((r) => (
                  <tr key={r.id} className="cursor-pointer" onClick={() => router.push(`/security/events/${r.id}`)}>
                    <td className="mono"><Link href={`/security/events/${r.id}`} className="hover:underline" title={`${fmtDateTime(r.ts)} (${relTime(r.ts, now)})`}>{fmtTime(r.ts)}</Link></td>
                    <td>{r.agentId}</td>
                    <td>
                      <DecisionBadge decision={r.decision} enforced={r.enforced} />
                      {/* On narrow screens the Rule column is hidden, so the rule id sits under the badge. */}
                      <div className="mono mt-0.5 break-all md:hidden">{r.ruleId ?? "no rule"}</div>
                    </td>
                    <td className={`text-center ${WIDE}`}>{r.tier ?? "-"}</td>
                    <td className={`mono ${WIDE}`}>{r.ruleId ?? "-"}</td>
                    <td className={WIDE}><span className="flex gap-1">{r.owasp.length ? r.owasp.slice(0, 3).map((o) => <Chip key={o}>{o}</Chip>) : "-"}{r.owasp.length > 3 && <Chip>+{r.owasp.length - 3}</Chip>}</span></td>
                    <td className={`mono text-mute ${WIDE}`}>{r.model}</td>
                    <td className={`num mono ${WIDE}`}>{Number(r.latencyMs.total.toFixed(1))}</td>
                    <td className={`mono text-mute ${WIDE}`}>{r.policyVersion}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </ScrollX>
        )}
        {(cursor || more.error) && (
          <div className="flex items-center gap-3 border-t border-line px-3 py-2">
            <button className="btn" onClick={loadMore} disabled={more.loading}>{more.loading ? "Loading…" : "Load more"}</button>
            {more.error && <span className="text-[12px] text-block">{more.error}</span>}
          </div>
        )}
      </Panel>
    </>
  );
}
