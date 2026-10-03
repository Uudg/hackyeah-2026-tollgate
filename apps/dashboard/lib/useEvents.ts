"use client";
// SSE client for /admin/events (named events per SPEC §8), with reconnect, a 500-record ring buffer and a mock generator.
import { useEffect, useRef, useState } from "react";
import type { DecisionRecord, EventName, TollgateEvents } from "@tollgate/policy";
import { eventsUrl, isMetrics, parseRecordSoft, probeGateway, useConnection } from "./gateway";
import type { MetricsSummary } from "./contract";
import { startMockStream, subscribeMock } from "./mock";

export const RING_SIZE = 500;

export const EVENT_NAMES: EventName[] = [
  "decision", "policy.loaded", "policy.rejected", "feed.loaded", "feed.rejected", "feed.version_match", "pricing.loaded",
  "budget.exceeded", "approval.pending", "approval.resolved", "session.killed", "circuit.state",
  "redteam.progress", "redteam.bypass", "redteam.done", "canary.tripped", "metrics.tick",
];

export type Listener<K extends EventName> = (data: TollgateEvents[K], id: string) => void;

/** Typed fan-out so pages can subscribe to specific events without owning an EventSource. */
export class EventHub {
  private map = new Map<EventName, Set<(d: never, id: string) => void>>();
  on<K extends EventName>(name: K, fn: Listener<K>): () => void {
    const set = this.map.get(name) ?? new Set<(d: never, id: string) => void>();
    this.map.set(name, set);
    const f = fn as (d: never, id: string) => void;
    set.add(f);
    return () => { set.delete(f); };
  }
  emit<K extends EventName>(name: K, data: TollgateEvents[K], id: string): void {
    this.map.get(name)?.forEach((fn) => (fn as Listener<K>)(data, id));
  }
}

export type StreamStatus = "connecting" | "open" | "reconnecting" | "mock";

export interface EventsState {
  status: StreamStatus;
  /** newest first, at most RING_SIZE */
  decisions: DecisionRecord[];
  /** latest metrics.tick */
  metrics: MetricsSummary | null;
  /** count of dropped malformed `decision` events (shown once as a toast) */
  malformed: number;
}

export function useEvents(hub: EventHub): EventsState {
  const conn = useConnection();
  const [status, setStatus] = useState<StreamStatus>(conn.mode === "mock" ? "mock" : "connecting");
  const [decisions, setDecisions] = useState<DecisionRecord[]>([]);
  const [metrics, setMetrics] = useState<MetricsSummary | null>(null);
  const [malformed, setMalformed] = useState(0);
  const pending = useRef<DecisionRecord[]>([]);

  // Batch decision updates so a burst of events renders once per frame.
  useEffect(() => {
    const t = setInterval(() => {
      if (pending.current.length === 0) return;
      const batch = pending.current;
      pending.current = [];
      setDecisions((prev) => [...batch.reverse(), ...prev].slice(0, RING_SIZE));
    }, 250);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    pending.current = [];
    // The data source changed (live <-> mock): drop the old ring buffer.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setDecisions([]);
    setMetrics(null);

    // Events from a source that is no longer the current one (mock after the switch to live, or the reverse) are dropped.
    let active = true;
    const dispatch = (name: EventName, data: unknown, id: string) => {
      if (!active) return;
      if (name === "decision") {
        const rec = parseRecordSoft(data);
        if (!rec) { setMalformed((n) => n + 1); return; }
        pending.current.push(rec);
        hub.emit("decision", rec, id);
        return;
      }
      if (name === "metrics.tick") {
        if (isMetrics(data)) setMetrics(data);
        return;
      }
      hub.emit(name, data as never, id);
    };

    // ---- mock ----
    if (conn.mode === "mock") {
      setStatus("mock");
      const off = subscribeMock(dispatch);
      const stop = startMockStream();
      return () => { active = false; off(); stop(); };
    }

    // ---- live ----
    let es: EventSource | null = null;
    let retry: ReturnType<typeof setTimeout> | null = null;
    let attempt = 0;
    let disposed = false;

    const connect = () => {
      if (disposed) return;
      setStatus(attempt === 0 ? "connecting" : "reconnecting");
      es = new EventSource(eventsUrl());
      es.onopen = () => { attempt = 0; setStatus("open"); };
      for (const name of EVENT_NAMES) {
        es.addEventListener(name, (ev) => {
          const m = ev as MessageEvent<string>;
          let data: unknown;
          try { data = JSON.parse(m.data); } catch { setMalformed((n) => n + 1); return; }
          dispatch(name, data, m.lastEventId);
        });
      }
      es.onerror = () => {
        setStatus("reconnecting");
        // The browser retries by itself while readyState is CONNECTING (and resends Last-Event-ID).
        // When it gave up (CLOSED, e.g. a 401 or a refused connection) reconnect by hand with backoff.
        if (es && es.readyState === EventSource.CLOSED) {
          es.close();
          attempt++;
          if (attempt >= 3) void probeGateway(); // the probe decides whether the gateway is really down
          retry = setTimeout(connect, Math.min(10_000, 1000 * 2 ** attempt));
        }
      };
    };
    connect();

    return () => {
      disposed = true;
      active = false;
      if (retry) clearTimeout(retry);
      es?.close();
    };
    // conn.epoch changes when the mode flips (live <-> mock), which must restart the stream.
  }, [conn.mode, conn.epoch, hub]);

  return { status, decisions, metrics, malformed };
}
