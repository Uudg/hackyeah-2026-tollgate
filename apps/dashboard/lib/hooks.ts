"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { useConnection } from "./gateway";
import { errMsg } from "./format";

export interface Async<T> { data: T | undefined; error: string | null; loading: boolean; reload: () => void; setData: (v: T | undefined) => void }

/** Runs `fn` on mount, when `deps` change and when the gateway mode flips (live <-> mock). Last call wins. */
export function useAsync<T>(fn: () => Promise<T>, deps: readonly unknown[] = []): Async<T> {
  const conn = useConnection();
  const [data, setData] = useState<T | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const seq = useRef(0);
  const fnRef = useRef(fn);
  const connKey = useRef(`${conn.mode}:${conn.epoch}`);
  useEffect(() => { fnRef.current = fn; });

  useEffect(() => {
    const my = ++seq.current;
    // A request starts here, so the loading flag must flip here too.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setLoading(true);
    // The data source flipped (live <-> mock): what is on screen came from the other source, so drop it.
    const key = `${conn.mode}:${conn.epoch}`;
    if (connKey.current !== key) { connKey.current = key; setData(undefined); setError(null); }
    fnRef.current().then(
      (v) => { if (my === seq.current) { setData(v); setError(null); setLoading(false); } },
      (e) => { if (my === seq.current) { setError(errMsg(e)); setLoading(false); } },
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [conn.mode, conn.epoch, tick, ...deps]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { data, error, loading, reload, setData };
}

/** Re-renders every `ms` so relative times and countdowns stay fresh. */
export function useNow(ms = 1000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(t);
  }, [ms]);
  return now;
}
