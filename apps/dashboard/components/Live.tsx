"use client";
// App-wide live state: connection mode, SSE ring buffer, current policy, pending approvals count, toasts.
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import type { DecisionRecord } from "@tollgate/policy";
import { api, probeGateway, useConnection, type Connection } from "@/lib/gateway";
import type { MetricsSummary, PolicyInfo } from "@/lib/contract";
import { EventHub, useEvents, type StreamStatus } from "@/lib/useEvents";
import { useAsync } from "@/lib/hooks";
import { shortId } from "@/lib/format";

export interface Toast {
  id: number; kind: "info" | "error"; title: string; lines?: string[]; href?: string; hrefLabel?: string; sticky?: boolean;
}

interface LiveCtx {
  conn: Connection;
  hub: EventHub;
  status: StreamStatus;
  decisions: DecisionRecord[];
  metrics: MetricsSummary | null;
  policy: PolicyInfo | null;
  policyRejected: { ts: string; errors: string[] } | null;
  /** increments on every policy.loaded so views can flash */
  policyFlash: number;
  pendingApprovals: number;
  toasts: Toast[];
  dismissToast: (id: number) => void;
  pushToast: (t: Omit<Toast, "id">) => void;
  refreshPolicy: () => void;
}

const Ctx = createContext<LiveCtx | null>(null);
export function useLive(): LiveCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error("useLive outside <LiveProvider>");
  return v;
}

let toastSeq = 1;
const MAX_TOASTS = 3;

export function LiveProvider({ children }: { children: ReactNode }) {
  const conn = useConnection();
  const [hub] = useState(() => new EventHub());
  const events = useEvents(hub);
  const policyReq = useAsync(() => api.policy(), []);
  const approvalsReq = useAsync(() => api.approvals("pending"), []);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [rejectedEvent, setRejected] = useState<{ ts: string; errors: string[] } | null>(null);
  const [flash, setFlash] = useState(0);
  const firstEpoch = useRef(conn.epoch);

  const dismissToast = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), []);
  const pushToast = useCallback((t: Omit<Toast, "id">) => {
    const id = toastSeq++;
    // At most 3 toasts on screen: the oldest one goes first. Info toasts leave after 5 s, errors after 12 s, sticky ones stay until dismissed.
    setToasts((prev) => [...prev, { ...t, id }].slice(-MAX_TOASTS));
    if (!t.sticky) setTimeout(() => setToasts((prev) => prev.filter((x) => x.id !== id)), t.kind === "error" ? 12000 : 5000);
  }, []);

  useEffect(() => { void probeGateway(); }, []);

  // A rejected edit that is newer than the loaded policy stays visible in the top bar until the next successful load.
  const policy = policyReq.data ?? null;
  const rejected = rejectedEvent ?? (policy?.lastRejected && policy.lastRejected.ts > policy.loadedAt ? policy.lastRejected : null);

  const { reload: reloadPolicy } = policyReq;
  const { reload: reloadApprovals } = approvalsReq;

  useEffect(() => {
    const offs = [
      hub.on("policy.loaded", (e) => {
        setRejected(null);
        setFlash((n) => n + 1);
        reloadPolicy();
        const more = e.changedPaths.length > 6 ? [`+${e.changedPaths.length - 6} more`] : [];
        pushToast({ kind: "info", title: `Policy v${e.version} loaded · ${e.hash}`, lines: e.changedPaths.length ? [...e.changedPaths.slice(0, 6), ...more] : ["no changed keys reported"], href: "/policy", hrefLabel: "Open policy" });
      }),
      hub.on("policy.rejected", (e) => {
        setRejected({ ts: e.ts, errors: e.errors });
        reloadPolicy();
        pushToast({ kind: "error", title: "Policy rejected, last good version kept", lines: e.errors.slice(0, 5), sticky: true, href: "/policy", hrefLabel: "Fix in editor" });
      }),
      hub.on("feed.loaded", (e) => pushToast({ kind: "info", title: `Feed loaded · ${e.version}`, lines: [`${e.entries} entries, ${e.enabledEntries} enabled`, e.source] })),
      hub.on("feed.rejected", (e) => pushToast({ kind: "error", title: "Feed rejected, last good kept", lines: e.errors.slice(0, 4) })),
      hub.on("session.killed", (e) => pushToast({ kind: "info", title: `Session killed · ${e.agentId}`, lines: [`session ${shortId(e.sessionId)}`, e.reason], href: `/security/events/${e.eventId}`, hrefLabel: "Open event" })),
      hub.on("canary.tripped", (e) => pushToast({ kind: "info", title: `Canary tripped · ${e.kind}`, lines: [`${e.agentId}, ${e.direction}`], href: `/security/events/${e.eventId}`, hrefLabel: "Open event" })),
      hub.on("approval.pending", (e) => { reloadApprovals(); pushToast({ kind: "info", title: `Approval needed · ${e.toolName}`, lines: [`agent ${e.agentId}`], href: "/approvals", hrefLabel: "Review" }); }),
      hub.on("approval.resolved", () => reloadApprovals()),
    ];
    return () => offs.forEach((f) => f());
  }, [hub, pushToast, reloadPolicy, reloadApprovals]);

  // Tell the operator when the data source flips (gateway down -> mock, gateway back -> live).
  useEffect(() => {
    if (conn.epoch === firstEpoch.current) return;
    // Toasts raised by the other data source (for example mock-stream events) must not outlive the switch.
    setToasts([]);
    pushToast(conn.mode === "mock"
      ? { kind: "error", title: "Gateway unreachable: showing mock data", lines: [conn.reason ?? ""] }
      : { kind: "info", title: "Gateway reachable again: live data" });
  }, [conn.epoch, conn.mode, conn.reason, pushToast]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (events.malformed === 1) pushToast({ kind: "error", title: "Dropped a malformed decision event", lines: ["The stream payload did not match DecisionRecord."] });
  }, [events.malformed, pushToast]);

  const value = useMemo<LiveCtx>(() => ({
    conn, hub, status: events.status, decisions: events.decisions, metrics: events.metrics, policy, policyRejected: rejected, policyFlash: flash,
    pendingApprovals: approvalsReq.data?.items.length ?? 0, toasts, dismissToast, pushToast, refreshPolicy: reloadPolicy,
  }), [conn, hub, events.status, events.decisions, events.metrics, policy, rejected, flash, approvalsReq.data, toasts, dismissToast, pushToast, reloadPolicy]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
