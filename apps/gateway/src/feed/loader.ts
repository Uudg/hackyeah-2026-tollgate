// Signature feed source (SPEC §6): a watched file, or an http(s) URL polled every controls.signatures.refresh.
// Invalid content is rejected and the last good feed stays active. fail_mode decides what happens when no feed
// could be loaded at all: open = run without signatures, closed = refuse to start.
import { resolve } from "node:path";
import { compileFeed } from "@tollgate/controls";
import { createFileStore, parseFeedText, type FileStore } from "@tollgate/policy/loader";
import type { Feed, Policy } from "@tollgate/policy";
import type { Loaded } from "@tollgate/policy/loader";
import type { EventBus } from "../events.ts";
import type { FeedSnapshot } from "../context.ts";
import { log } from "../log.ts";

export interface FeedSource { current(): FeedSnapshot | null; reload(): Promise<boolean>; close(): void }

export function createFeedSource(source: string, policy: () => Policy, bus: EventBus, opts: { watch: boolean; timers: boolean }, onLoaded: () => void): FeedSource {
  let snap: FeedSnapshot | null = null;
  const accept = (loaded: Loaded<Feed>) => {
    const prev = snap?.loaded.hash;
    snap = { loaded, compiled: compileFeed(loaded.value), source };
    if (prev === loaded.hash) return;
    bus.emit("feed.loaded", { version: loaded.hash, entries: loaded.value.entries.length, enabledEntries: loaded.value.entries.filter((e) => e.enabled).length, source, ts: loaded.loadedAt });
    onLoaded();
  };
  const reject = (errors: string[]) => {
    bus.emit("feed.rejected", { ts: new Date().toISOString(), errors, source });
    log("warn", "feed rejected; keeping the last good feed", { source, errors: errors.slice(0, 5) });
  };

  if (/^https?:\/\//.test(source)) {
    const fetchOnce = async (): Promise<boolean> => {
      try {
        const res = await fetch(source, { signal: AbortSignal.timeout(5000) });
        const parsed = parseFeedText(await res.text());
        if (parsed.ok) { accept(parsed); return true; }
        reject(parsed.errors.map((e) => `${e.path}: ${e.message}`));
      } catch (err) {
        reject([`fetch failed: ${(err as Error).message}`]);
      }
      return false;
    };
    let timer: ReturnType<typeof setTimeout> | null = null;
    const loop = async () => {
      await fetchOnce();
      if (opts.timers) timer = setTimeout(loop, parseRefresh(policy()));
    };
    void loop();
    return { current: () => snap, reload: fetchOnce, close: () => { if (timer) clearTimeout(timer); } };
  }

  const path = resolve(source);
  let store: FileStore<Feed> | null = null;
  try {
    store = createFileStore(path, parseFeedText, {
      onLoaded: (next) => accept(next),
      onRejected: (errors) => reject(errors.map((e) => `${e.path}: ${e.message}`)),
    }, { watch: opts.watch });
  } catch (err) {
    if (policy().controls.signatures.fail_mode === "closed") throw err;
    reject([(err as Error).message]);
  }
  return {
    current: () => snap,
    reload: async () => (store ? store.reload().ok : false),
    close: () => store?.close(),
  };
}

function parseRefresh(p: Policy): number {
  const m = /^(\d+)(ms|s|m|h|d)$/.exec(p.controls.signatures.refresh);
  const unit = { ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[(m?.[2] ?? "s") as "s"];
  return Math.max(5000, Number(m?.[1] ?? 60) * unit);
}
