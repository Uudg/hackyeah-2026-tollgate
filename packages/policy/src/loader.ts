// Policy + feed loading with last-good fallback and debounced file watching.
// Bun/Node only (fs, crypto) — the dashboard imports "@tollgate/policy" (schemas only), never this file.
import { createHash } from "node:crypto";
import { existsSync, readFileSync, watch, type FSWatcher } from "node:fs";
import { basename, dirname } from "node:path";
import YAML from "yaml";
import type { z } from "zod";
import { PolicySchema, type Policy } from "./schema/policy.ts";
import { FeedSchema, type Feed } from "./schema/feed.ts";

export interface Issue { path: string; message: string }
export type ParseResult<T> = { ok: true; value: T; version: string } | { ok: false; issues: Issue[] };

/** First 12 hex chars of sha256 over the raw file bytes. */
export function contentVersion(raw: string): string {
  return createHash("sha256").update(raw).digest("hex").slice(0, 12);
}

export function formatIssues(error: z.ZodError): Issue[] {
  return error.issues.map((i) => ({ path: i.path.map(String).join(".") || "(root)", message: i.message }));
}

function parseWith<T>(schema: z.ZodType<T>, raw: string, format: "yaml" | "json"): ParseResult<T> {
  let data: unknown;
  try {
    data = format === "yaml" ? YAML.parse(raw) : JSON.parse(raw);
  } catch (err) {
    // Typed failure: the caller logs it with the file path and emits *_rejected.
    return { ok: false, issues: [{ path: `(${format})`, message: (err as Error).message }] };
  }
  const parsed = schema.safeParse(data);
  if (!parsed.success) return { ok: false, issues: formatIssues(parsed.error) };
  return { ok: true, value: parsed.data, version: contentVersion(raw) };
}

export const parsePolicy = (raw: string): ParseResult<Policy> => parseWith(PolicySchema, raw, "yaml");
export const parseFeed = (raw: string): ParseResult<Feed> => parseWith(FeedSchema, raw, "json");

export function readText(path: string): string | null {
  return existsSync(path) ? readFileSync(path, "utf8") : null;
}

/**
 * Watch one file for content changes. Watches the directory (survives editors that save via rename),
 * debounces, and only calls onChange when the file hash actually changed.
 */
export function watchFile(path: string, onChange: (raw: string) => void, debounceMs = 150): () => void {
  const name = basename(path);
  let timer: ReturnType<typeof setTimeout> | null = null;
  let lastHash = contentVersion(readText(path) ?? "");
  const fire = () => {
    timer = null;
    const raw = readText(path);
    if (raw === null) return; // mid-rename; the next event brings the new file
    const hash = contentVersion(raw);
    if (hash === lastHash) return;
    lastHash = hash;
    onChange(raw);
  };
  const watcher: FSWatcher = watch(dirname(path), (_event, file) => {
    if (file !== null && file !== name) return;
    if (timer) clearTimeout(timer);
    timer = setTimeout(fire, debounceMs);
  });
  return () => {
    if (timer) clearTimeout(timer);
    watcher.close();
  };
}

/** Top-level dotted keys whose value differs (max 20), e.g. "controls.pii", "mode". */
export function changedPaths(a: unknown, b: unknown, prefix = "", depth = 0, out: string[] = []): string[] {
  if (out.length >= 20) return out;
  if (JSON.stringify(a) === JSON.stringify(b)) return out;
  const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
  if (depth >= 3 || !isObj(a) || !isObj(b)) {
    out.push(prefix || "(root)");
    return out;
  }
  for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) {
    changedPaths(a[k], b[k], prefix ? `${prefix}.${k}` : k, depth + 1, out);
  }
  return out;
}

export interface Loaded<T> { value: T; version: string; loadedAt: string; raw: string }

export interface Store<T> {
  current(): Loaded<T>;
  /** Re-read the file now (manual reload for editors that do not trigger fs.watch). */
  reload(): ParseResult<T>;
  close(): void;
}

export interface StoreHooks<T> {
  onLoaded?: (next: Loaded<T>, prev: Loaded<T> | null) => void;
  onRejected?: (issues: Issue[], kept: Loaded<T>) => void;
}

/**
 * Last-good store over a watched file. Startup with an invalid file throws (there is no last good yet);
 * after that a bad file is rejected and the previous version stays active.
 */
export function createFileStore<T>(
  path: string,
  parse: (raw: string) => ParseResult<T>,
  hooks: StoreHooks<T> = {},
  opts: { watch?: boolean } = {},
): Store<T> {
  const first = readText(path);
  if (first === null) throw new Error(`${path}: file not found`);
  const initial = parse(first);
  if (!initial.ok) {
    throw new Error(`${path} is invalid:\n` + initial.issues.map((i) => `  ${i.path}: ${i.message}`).join("\n"));
  }
  let current: Loaded<T> = { value: initial.value, version: initial.version, loadedAt: new Date().toISOString(), raw: first };
  hooks.onLoaded?.(current, null);

  const apply = (raw: string): ParseResult<T> => {
    const res = parse(raw);
    if (!res.ok) {
      hooks.onRejected?.(res.issues, current);
      return res;
    }
    if (res.version === current.version) return res;
    const prev = current;
    current = { value: res.value, version: res.version, loadedAt: new Date().toISOString(), raw };
    hooks.onLoaded?.(current, prev);
    return res;
  };

  const stop = opts.watch === false ? () => {} : watchFile(path, apply);
  return {
    current: () => current,
    reload: () => {
      const raw = readText(path);
      return raw === null ? { ok: false, issues: [{ path: "(file)", message: `${path} not found` }] } : apply(raw);
    },
    close: stop,
  };
}
