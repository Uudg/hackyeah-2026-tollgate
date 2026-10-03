"use client";
import { api } from "@/lib/gateway";
import { CONTROL_LABELS } from "@/lib/coverage";
import { OWASP_ASI, OWASP_LLM, type CoverageRow, type Decision } from "@/lib/contract";
import { fmtPct } from "@/lib/format";
import { useAsync } from "@/lib/hooks";
import { useLive } from "./Live";
import { useEffect } from "react";
import { DecisionBadge, ErrorNote, Loading, PageHeader, Panel, ScrollX, cn } from "./ui";

const TINT: Record<Decision, string> = {
  allow: "bg-allow-bg border-allow/50", redact: "bg-redact-bg border-redact/50", block: "bg-block-bg border-block/50", kill_session: "bg-kill-bg border-kill/50",
};

function Cell({ row, id }: { row: CoverageRow; id: string }) {
  if (!row.owasp.includes(id)) return <td className="px-0.5 text-center" aria-label="not covered"><span className="text-mute">·</span></td>;
  const label = `${row.controlId} covers ${id}${row.enabled ? `, action ${row.action ?? "n/a"}` : ", disabled in the current policy"}`;
  const cls = !row.enabled ? "hatch border-line-strong bg-[#f7f8f9]" : row.action ? TINT[row.action] : "border-line-strong bg-[#dfe2e6]";
  return <td className="px-0.5 text-center"><span title={label} role="img" aria-label={label} className={cn("inline-block h-4 w-6 rounded-[3px] border", cls)} /></td>;
}

export default function Coverage() {
  const { hub } = useLive();
  const req = useAsync(() => api.coverage(), []);
  const { reload } = req;
  useEffect(() => {
    const offs = [hub.on("policy.loaded", () => reload()), hub.on("redteam.done", () => reload())];
    return () => offs.forEach((f) => f());
  }, [hub, reload]);

  const data = req.data;
  const rows = data?.controls ?? [];
  const cols = [...OWASP_LLM, ...OWASP_ASI];
  const notCovered = new Set(data?.notCovered ?? []);

  return (
    <>
      <PageHeader title="Coverage map" sub="Which control covers which OWASP risk, with the live state from the current policy. Updates when the policy reloads." />
      {req.error && <ErrorNote onRetry={req.reload}>{req.error}</ErrorNote>}
      {!data && req.loading && <Loading />}
      {data && (
        <Panel bodyClass="p-0">
          <ScrollX>
            <table className="tbl" style={{ minWidth: 980 }}>
              <thead>
                <tr>
                  <th>Control</th><th>Tier</th>
                  {cols.map((c) => <th key={c} className={cn("px-0.5 text-center text-[10.5px]", notCovered.has(c) && "text-ink underline decoration-dotted underline-offset-2")} title={notCovered.has(c) ? `${c}: not covered` : c}>{c.replace("LLM", "L").replace("ASI", "A")}</th>)}
                  <th>State</th><th className="num">Bypass rate</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.controlId} className={cn(!r.enabled && "text-faint")}>
                    <td><div className="mono font-medium">{r.controlId}</div><div className="text-[11px] text-mute">{r.label ?? CONTROL_LABELS[r.controlId] ?? ""}</div></td>
                    <td className="text-mute">{r.tier}</td>
                    {cols.map((c) => <Cell key={c} row={r} id={c} />)}
                    <td>{r.enabled ? (r.action ? <DecisionBadge decision={r.action} /> : <span className="text-mute">always on</span>) : <span>disabled</span>}</td>
                    <td className="num">{fmtPct(r.bypassRate, 1)}</td>
                  </tr>
                ))}
                <tr className="bg-[#f7f8f9] font-medium">
                  <td>Covered right now</td><td />
                  {cols.map((c) => {
                    const on = rows.some((r) => r.enabled && r.owasp.includes(c));
                    return <td key={c} className="text-center">{on ? "✓" : <span className="text-faint">-</span>}</td>;
                  })}
                  <td /><td />
                </tr>
              </tbody>
            </table>
          </ScrollX>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-line px-3 py-2 text-[11px] text-mute">
            <span>Cell tint = current action:</span>
            {(["allow", "redact", "block", "kill_session"] as Decision[]).map((d) => <span key={d} className="inline-flex items-center gap-1"><i className={cn("inline-block h-3 w-5 rounded-[3px] border", TINT[d])} />{d}</span>)}
            <span className="inline-flex items-center gap-1"><i className="hatch inline-block h-3 w-5 rounded-[3px] border border-line-strong bg-[#f7f8f9]" />control disabled</span>
            <span className="inline-flex items-center gap-1"><i className="inline-block h-3 w-5 rounded-[3px] border border-line-strong bg-[#dfe2e6]" />no single action</span>
          </div>
          <div className="border-t border-line px-3 py-2 text-[12px]">
            <b>Not covered:</b> <span className="mono">{[...notCovered].join(", ") || "none"}</span>
            <span className="text-mute"> (vector and embedding weaknesses, misinformation, human-agent trust exploitation are out of scope for a gateway)</span>
          </div>
        </Panel>
      )}
    </>
  );
}
