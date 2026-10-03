"use client";
import { useEffect, useRef, useState } from "react";
import type { Approval } from "@/lib/contract";
import { api } from "@/lib/gateway";
import { errMsg, fmtDateTime, pretty } from "@/lib/format";
import { useAsync, useNow } from "@/lib/hooks";
import { useLive } from "./Live";
import { Empty, ErrorNote, JsonBlock, Loading, PageHeader, Panel } from "./ui";
import Link from "next/link";

export default function Approvals() {
  const { hub, policy } = useLive();
  const now = useNow(500);
  const pending = useAsync(() => api.approvals("pending"), []);
  const [expiry, setExpiry] = useState<Record<string, number>>({});
  const [resolved, setResolved] = useState<(Approval | { id: string; status: string; toolName?: string })[]>([]);
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const pendingRef = useRef<Approval[]>([]);
  const { reload } = pending;
  useEffect(() => { pendingRef.current = pending.data?.items ?? []; });

  const timeoutMs = policy?.policy.controls.tool_calls.approval_timeout_ms ?? 30000;

  useEffect(() => {
    const offs = [
      hub.on("approval.pending", (e) => { setExpiry((x) => ({ ...x, [e.id]: new Date(e.expiresAt).getTime() })); reload(); }),
      hub.on("approval.resolved", (e) => {
        const a = pendingRef.current.find((x) => x.id === e.id);
        setResolved((r) => (r.some((x) => x.id === e.id) ? r : [{ id: e.id, status: e.status, toolName: a?.toolName }, ...r].slice(0, 20)));
        reload();
      }),
    ];
    return () => offs.forEach((f) => f());
  }, [hub, reload]);

  async function resolve(a: Approval, decision: "approve" | "deny") {
    setBusy(a.id); setErr(null);
    try { await api.resolveApproval(a.id, decision, notes[a.id]); reload(); } catch (e) { setErr(errMsg(e)); }
    setBusy(null);
  }

  const items = pending.data?.items ?? [];
  return (
    <>
      <PageHeader title="Approvals" sub={<>Tool calls that match <span className="mono">controls.tool_calls.require_approval</span> wait here. An unanswered call is blocked after {Math.round(timeoutMs / 1000)} s.</>} />
      {(pending.error || err) && <div className="mb-3"><ErrorNote onRetry={pending.error ? pending.reload : undefined}>{pending.error ?? err}</ErrorNote></div>}
      {pending.loading && !pending.data && <Loading />}
      {pending.data && items.length === 0 && <Panel><Empty>Nothing waiting for approval.</Empty></Panel>}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        {items.map((a) => {
          const exp = expiry[a.id] ?? new Date(a.ts).getTime() + timeoutMs;
          const left = Math.max(0, Math.ceil((exp - now) / 1000));
          return (
            <Panel key={a.id} title={<><span className="mono">{a.toolName}</span> <span className="font-normal text-mute">requested by {a.agentId}</span></>}
              actions={<span className="mono text-[12px]" aria-label={`${left} seconds left`}>{left > 0 ? `${left} s left` : "expiring"}</span>}>
              <div className="mb-1.5 text-[11px] text-mute">{fmtDateTime(a.ts)} · session <span className="mono">{a.sessionId}</span>{a.eventId && <> · <Link className="text-accent underline" href={`/security/events/${a.eventId}`}>event</Link></>}</div>
              <div className="label">Arguments</div>
              <JsonBlock value={pretty(a.arguments)} max={200} />
              <div className="mt-2 h-1 w-full rounded-full bg-[#eceef1]"><div className="h-full rounded-full bg-ink" style={{ width: `${Math.min(100, (left * 1000 / timeoutMs) * 100)}%` }} /></div>
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <input className="field min-w-[120px] flex-1" placeholder="Note (optional)" value={notes[a.id] ?? ""} onChange={(e) => setNotes((n) => ({ ...n, [a.id]: e.target.value }))} aria-label="Note" />
                <button className="btn btn-primary" disabled={busy === a.id} onClick={() => resolve(a, "approve")}>Approve</button>
                <button className="btn btn-dark" disabled={busy === a.id} onClick={() => resolve(a, "deny")}>Deny</button>
              </div>
            </Panel>
          );
        })}
      </div>
      {resolved.length > 0 && (
        <Panel className="mt-3" title="Resolved this session" bodyClass="p-0">
          <table className="tbl"><tbody>{resolved.map((r) => <tr key={r.id}><td className="mono">{r.id}</td><td>{r.toolName ?? ""}</td><td>{r.status}</td></tr>)}</tbody></table>
        </Panel>
      )}
    </>
  );
}
