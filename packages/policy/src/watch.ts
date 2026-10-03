// Debounced directory watch with last-good fallback (SPEC §4.3).
import { watch, type FSWatcher } from "node:fs";
import { basename, dirname } from "node:path";
import { sha256 } from "./hash.ts";
import { readText, type Issue, type Loaded, type LoadResult } from "./loader.ts";

/**
 * Watch one file. Watches its directory (survives editors that save via rename), debounces 150 ms,
 * and calls onChange only when the bytes changed. Returns a stop function.
 */
export function watchFile(path: string, onChange: (raw: string) => void, debounceMs = 150): () => void {
  const name = basename(path);
  let timer: ReturnType<typeof setTimeout> | null = null;
  let last = sha256(readText(path) ?? "");
  const fire = () => {
    timer = null;
    const raw = readText(path);
    if (raw === null) return; // mid-rename; the next event brings the new file
    const h = sha256(raw);
    if (h === last) return;
    last = h;
    onChange(raw);
  };
  const w: FSWatcher = watch(dirname(path), (_e, file) => {
    if (file !== null && file !== name) return;
    if (timer) clearTimeout(timer);
    timer = setTimeout(fire, debounceMs);
  });
  return () => { if (timer) clearTimeout(timer); w.close(); };
}

/** Shallow dotted diff (depth ≤ 3, max 20 paths), e.g. ["controls.pii.action", "mode"]. */
export function changedPaths(a: unknown, b: unknown, prefix = "", depth = 0, out: string[] = []): string[] {
  if (out.length >= 20 || JSON.stringify(a) === JSON.stringify(b)) return out;
  const obj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
  if (depth >= 3 || !obj(a) || !obj(b)) { out.push(prefix || "(root)"); return out; }
  for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) changedPaths(a[k], b[k], prefix ? `${prefix}.${k}` : k, depth + 1, out);
  return out;
}

export interface Hooks<T> {
  onLoaded?: (next: Loaded<T>, prev: Loaded<T> | null, changed: string[]) => void;
  onRejected?: (errors: Issue[], kept: Loaded<T>) => void;
}

export interface FileStore<T> {
  current(): Loaded<T>;
  /** Validate and apply raw text (used by the watcher, manual reload and tests). */
  apply(raw: string): LoadResult<T>;
  /** In-process override that bypasses the file (test harness). */
  set(next: Loaded<T>): void;
  reload(): LoadResult<T>;
  close(): void;
}

/** Startup with an invalid file throws (no last good yet). After that, bad files are rejected and the old version stays. */
export function createFileStore<T>(path: string, parse: (raw: string) => LoadResult<T>, hooks: Hooks<T> = {}, opts: { watch?: boolean } = {}): FileStore<T> {
  const raw = readText(path);
  if (raw === null) throw new Error(`${path}: file not found`);
  const first = parse(raw);
  if (!first.ok) throw new Error(`${path} is invalid:\n${first.errors.map((e) => `  ${e.path}: ${e.message}`).join("\n")}`);
  let current: Loaded<T> = first;
  hooks.onLoaded?.(current, null, []);

  const swap = (next: Loaded<T>) => {
    if (next.hash === current.hash) return;
    const prev = current;
    current = next;
    hooks.onLoaded?.(next, prev, changedPaths(prev.value, next.value));
  };
  const apply = (text: string): LoadResult<T> => {
    const res = parse(text);
    if (res.ok) swap(res);
    else hooks.onRejected?.(res.errors, current);
    return res;
  };
  const stop = opts.watch === false ? () => {} : watchFile(path, apply);
  return {
    current: () => current,
    apply,
    set: swap,
    reload: () => { const t = readText(path); return t === null ? { ok: false, errors: [{ path: "(file)", message: `${path} not found` }] } : apply(t); },
    close: stop,
  };
}
