// Typed fetchers for every /admin route. Each fetcher has a live path (fetch against the gateway) and a mock path (lib/mock.ts).
// Mode rules:
//   NEXT_PUBLIC_MOCK=1            -> mock for good ("forced")
//   otherwise                      -> live; a network failure that /healthz confirms (gateway unreachable) flips to mock and starts a recovery probe
//   HTTP errors (401, 404, 409...) -> thrown as GatewayError and shown in the UI; they never flip the mode
//   mock data exists only while mode === "mock"; switching back to live stops the mock stream and drops its listeners
//   a failed write (POST/PUT/DELETE) is never answered with a fake mock result
import { DecisionRecordSchema, type DecisionRecord } from "@tollgate/policy";
import { useSyncExternalStore } from "react";
import type {
  Approval, AuditPage, AuditQuery, AuditVerify, Canary, CoverageResponse, FeedResponse, Healthz, KilledSession,
  MetricsSummary, PolicyInfo, PolicyResponseRaw, PlaygroundRequest, PlaygroundResponse, PlaygroundResult, RedteamConfig,
  RedteamResult, RedteamRun, RedteamStatus, ValidateResponseRaw, ValidateResult,
} from "./contract";
import { GatewayError } from "./contract";
import * as mock from "./mock";
import { mockPlayground } from "./mockPlayground";

export const GATEWAY_URL = (process.env.NEXT_PUBLIC_GATEWAY_URL || "http://localhost:8787").replace(/\/$/, "");
const TOKEN = process.env.NEXT_PUBLIC_ADMIN_TOKEN ?? "";
const FORCED_MOCK = process.env.NEXT_PUBLIC_MOCK === "1";

// ---------------------------------------------------------------------------------------------------------------------
// connection store (live | mock), shared by fetchers, the SSE hook and the top bar
// ---------------------------------------------------------------------------------------------------------------------
export interface Connection { mode: "live" | "mock"; forced: boolean; reason: string | null; epoch: number }
let conn: Connection = { mode: FORCED_MOCK ? "mock" : "live", forced: FORCED_MOCK, reason: FORCED_MOCK ? "NEXT_PUBLIC_MOCK=1" : null, epoch: 0 };
const subs = new Set<() => void>();
let recoveryTimer: ReturnType<typeof setInterval> | null = null;

function setConn(next: Partial<Connection>): void {
  conn = { ...conn, ...next };
  if (conn.mode === "live") mock.stopMock();
  subs.forEach((f) => f());
}
export const getConnection = (): Connection => conn;
export function useConnection(): Connection {
  return useSyncExternalStore((f) => { subs.add(f); return () => subs.delete(f); }, getConnection, getConnection);
}

/** Called by any fetcher or by the SSE hook when the gateway cannot be reached at all. */
export function reportUnreachable(why: string): void {
  if (conn.forced || conn.mode === "mock") return;
  console.warn(`[tollgate] switching to mock data: ${why}`);
  setConn({ mode: "mock", reason: why, epoch: conn.epoch + 1 });
  if (!recoveryTimer) {
    recoveryTimer = setInterval(async () => {
      try {
        const res = await fetch(`${GATEWAY_URL}/healthz`, { signal: AbortSignal.timeout(5000) });
        if (res.ok) {
          if (recoveryTimer) clearInterval(recoveryTimer);
          recoveryTimer = null;
          setConn({ mode: "live", reason: null, epoch: conn.epoch + 1 });
        }
      } catch { /* still down: the badge keeps saying "mock data" */ }
    }, 4000);
  }
}

/**
 * One fetch failed: ask /healthz up to three times before declaring the gateway down, so a single dropped request never swaps
 * real data for mock data. Only a real network error (TypeError: refused, DNS, CORS) counts as "down". A timeout or an abort
 * is NOT proof: on a busy page (dev build, hydration) the timer can fire before the response is handled, and any HTTP answer
 * at all means the gateway is there.
 */
async function confirmUnreachable(): Promise<boolean> {
  for (let i = 0; i < 3; i++) {
    try {
      await fetch(`${GATEWAY_URL}/healthz`, { signal: AbortSignal.timeout(5000) });
      return false;
    } catch (e) {
      if (!(e instanceof TypeError)) return false;
    }
    if (i < 2) await new Promise((r) => setTimeout(r, 700));
  }
  return true;
}

/** First-load probe: if the gateway really is down, fall back before the first page fetch fails noisily. */
export async function probeGateway(): Promise<void> {
  if (conn.forced || conn.mode === "mock") return;
  if (await confirmUnreachable()) reportUnreachable(`gateway unreachable at ${GATEWAY_URL}`);
}

// ---------------------------------------------------------------------------------------------------------------------
// transport
// ---------------------------------------------------------------------------------------------------------------------
function authHeaders(extra?: Record<string, string>): Record<string, string> {
  return { ...(TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {}), ...extra };
}

async function errorFrom(res: Response): Promise<GatewayError> {
  let message = `${res.status} ${res.statusText}`;
  let code: string | undefined;
  try {
    const j = (await res.json()) as { error?: { message?: string; code?: string; type?: string } };
    if (j.error) { message = j.error.message ?? j.error.type ?? message; code = j.error.code; }
  } catch { /* body was not JSON; keep the status line */ }
  if (res.status === 401) message = `401 unauthorized: set NEXT_PUBLIC_ADMIN_TOKEN to the gateway ADMIN_TOKEN (${message})`;
  return new GatewayError(res.status, message, code);
}

async function call<T>(
  path: string,
  init: { method?: string; body?: string; headers?: Record<string, string>; as?: "json" | "text" } | undefined,
  mockFn: () => T | Promise<T>,
): Promise<T> {
  if (conn.mode === "mock") return withMockErrors(mockFn);
  let res: Response;
  try {
    res = await fetch(`${GATEWAY_URL}${path}`, {
      method: init?.method ?? "GET", body: init?.body, headers: authHeaders(init?.headers), signal: AbortSignal.timeout(20000),
    });
  } catch (e) {
    if (e instanceof DOMException && e.name === "TimeoutError") throw new GatewayError(0, `gateway timed out on ${path}`);
    if (e instanceof DOMException && e.name === "AbortError") throw new GatewayError(0, `request to ${path} was cancelled`);
    const down = await confirmUnreachable();
    if (!down) throw new GatewayError(0, `request to ${path} failed, but the gateway answers /healthz. Try again.`);
    reportUnreachable(`gateway unreachable at ${GATEWAY_URL}`);
    const method = init?.method ?? "GET";
    if (method !== "GET") throw new GatewayError(0, `gateway unreachable at ${GATEWAY_URL}: ${method} ${path} was not sent`);
    return withMockErrors(mockFn);
  }
  if (!res.ok) throw await errorFrom(res);
  return (init?.as === "text" ? await res.text() : await res.json()) as T;
}

async function withMockErrors<T>(fn: () => T | Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    const status = (e as { status?: number }).status;
    if (status) throw new GatewayError(status, (e as Error).message);
    throw e;
  }
}

const qs = (o: object): string => {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(o)) if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  const s = p.toString();
  return s ? `?${s}` : "";
};

// ---------------------------------------------------------------------------------------------------------------------
// normalisers
// ---------------------------------------------------------------------------------------------------------------------
const pathsOf = (v: string[] | string | null | undefined): string[] => {
  if (Array.isArray(v)) return v;
  if (!v) return [];
  try {
    const j: unknown = JSON.parse(v);
    if (Array.isArray(j)) return j.map(String);
  } catch { /* not JSON: comma-joined text */ }
  return v.split(",").map((s) => s.trim()).filter(Boolean);
};
const errStr = (e: string | { path: string; message: string }): string =>
  typeof e === "string" ? e : e.path ? `${e.path}: ${e.message}` : e.message;

function normalisePolicy(r: PolicyResponseRaw): PolicyInfo {
  return {
    ...r,
    lastRejected: r.lastRejected ? { ts: r.lastRejected.ts, errors: (r.lastRejected.errors as (string | { path: string; message: string })[]).map(errStr) } : null,
    history: r.history.map((h) => ({ hash: h.hash, declaredVersion: h.declared_version, loadedTs: h.loaded_ts, changedPaths: pathsOf(h.changed_paths) })),
  };
}

type Snake = Record<string, unknown>;
const pickKey = <T,>(o: Snake, ...keys: string[]): T | undefined => {
  for (const k of keys) if (o[k] !== undefined) return o[k] as T;
  return undefined;
};
function normaliseRun(raw: unknown): RedteamRun {
  const o = raw as Snake;
  const cfg = pickKey<unknown>(o, "config", "config_json");
  let config: RedteamConfig | null = null;
  if (typeof cfg === "string") { try { config = JSON.parse(cfg) as RedteamConfig; } catch { config = null; } } else if (cfg && typeof cfg === "object") config = cfg as RedteamConfig;
  return {
    id: String(o.id), startedTs: String(pickKey(o, "startedTs", "started_ts") ?? ""), finishedTs: (pickKey<string | null>(o, "finishedTs", "finished_ts") ?? null),
    status: o.status as RedteamRun["status"], policyVersion: String(pickKey(o, "policyVersion", "policy_version") ?? ""),
    attempts: Number(o.attempts ?? 0), bypasses: Number(o.bypasses ?? 0), config,
  };
}
function normaliseResult(raw: unknown): RedteamResult {
  const o = raw as Snake;
  const arr = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : typeof v === "string" && v ? v.split(",") : []);
  return {
    id: String(o.id), runId: String(pickKey(o, "runId", "run_id") ?? ""), seedId: String(pickKey(o, "seedId", "seed_id") ?? ""),
    controlId: String(pickKey(o, "controlId", "control_id") ?? ""), owasp: arr(o.owasp), mutators: arr(o.mutators), input: String(o.input ?? ""),
    decision: o.decision as RedteamResult["decision"], ruleId: pickKey<string | null>(o, "ruleId", "rule_id") ?? null,
    tier: (o.tier as number | null | undefined) ?? null, bypass: Boolean(o.bypass),
    generatedCasePath: pickKey<string | null>(o, "generatedCasePath", "generated_case_path") ?? null, ts: String(o.ts ?? ""),
  };
}
function normaliseStatus(raw: unknown): RedteamStatus {
  const o = raw as { run?: unknown; byControl?: RedteamStatus["byControl"]; recent?: unknown[] };
  return { run: o.run ? normaliseRun(o.run) : null, byControl: o.byControl ?? [], recent: (o.recent ?? []).map(normaliseResult) };
}

export const isMetrics = (x: unknown): x is MetricsSummary =>
  !!x && typeof x === "object" && "requests" in x && "latency" in x && "posture" in x;

function parseRecord(x: unknown): DecisionRecord {
  const r = DecisionRecordSchema.safeParse(x);
  if (!r.success) throw new GatewayError(0, `gateway sent a malformed DecisionRecord: ${r.error.issues[0]?.path.join(".")}: ${r.error.issues[0]?.message}`);
  return r.data;
}
/** For SSE: returns null instead of throwing so one bad event does not stop the stream. */
export function parseRecordSoft(x: unknown): DecisionRecord | null {
  const r = DecisionRecordSchema.safeParse(x);
  return r.success ? r.data : null;
}

// ---------------------------------------------------------------------------------------------------------------------
// the API
// ---------------------------------------------------------------------------------------------------------------------
export const api = {
  healthz: () => call<Healthz>("/healthz", undefined, () => ({
    ok: true, version: "mock", policy: { hash: mock.mockPolicy().hash, version: mock.mockPolicy().version }, feed: { hash: mock.mockFeed().hash, entries: mock.mockFeed().entries.length },
    mode: { semanticProvider: "mock", upstream: "echo" }, uptime_s: 0,
  })),

  metrics: () => call<MetricsSummary>("/admin/metrics", undefined, () => mock.mockMetrics()),

  policy: async (): Promise<PolicyInfo> => normalisePolicy(await call<PolicyResponseRaw>("/admin/policy", undefined, () => mock.mockPolicy())),
  policyRaw: () => call<string>("/admin/policy/raw", { as: "text" }, () => mock.mockPolicyRaw()),
  validatePolicy: async (yaml: string): Promise<ValidateResult> => {
    const r = await call<ValidateResponseRaw>("/admin/policy/validate", { method: "POST", body: yaml, headers: { "Content-Type": "text/yaml" } }, () => mock.mockValidate(yaml));
    return { ok: r.ok, errors: (r.errors ?? []).map(errStr) };
  },
  savePolicy: (yaml: string) => call<{ queued: boolean }>("/admin/policy/raw", { method: "PUT", body: yaml, headers: { "Content-Type": "text/yaml" } }, () => mock.mockSavePolicy(yaml)),

  feed: () => call<FeedResponse>("/admin/feed", undefined, () => mock.mockFeed()),
  reloadFeed: () => call<{ ok?: boolean }>("/admin/feed/reload", { method: "POST" }, () => mock.mockReloadFeed()),

  audit: async (q: AuditQuery = {}): Promise<AuditPage> => {
    const r = await call<{ items: unknown[]; nextCursor: string | null }>(`/admin/audit${qs(q)}`, undefined, () => mock.mockAudit(q));
    return { items: r.items.map(parseRecord), nextCursor: r.nextCursor ?? null };
  },
  auditOne: async (id: string): Promise<DecisionRecord> => parseRecord(await call<unknown>(`/admin/audit/${encodeURIComponent(id)}`, undefined, () => mock.mockAuditOne(id))),
  auditVerify: () => call<AuditVerify>("/admin/audit/verify", undefined, () => mock.mockAuditVerify()),

  approvals: (status = "pending") => call<{ items: Approval[] }>(`/admin/approvals${qs({ status })}`, undefined, () => mock.mockApprovals(status)),
  resolveApproval: (id: string, decision: "approve" | "deny", note?: string) =>
    call<{ ok: boolean; approval: Approval }>(`/admin/approvals/${encodeURIComponent(id)}`, { method: "POST", body: JSON.stringify({ decision, note }), headers: { "Content-Type": "application/json" } }, () => mock.mockResolveApproval(id, decision, note)),

  killedSessions: () => call<{ items: KilledSession[] }>("/admin/sessions/killed", undefined, () => mock.mockKilled()),
  restoreSession: (id: string) => call<{ ok: boolean }>(`/admin/sessions/killed/${encodeURIComponent(id)}`, { method: "DELETE" }, () => mock.mockRestoreSession(id)),
  canaries: () => call<{ items: Canary[] }>("/admin/canaries", undefined, () => mock.mockCanaries()),

  redteamStatus: async (runId?: string): Promise<RedteamStatus> => normaliseStatus(await call<unknown>(`/admin/redteam/status${qs({ runId })}`, undefined, () => mock.mockRedteamStatus())),
  redteamRuns: async (): Promise<RedteamRun[]> => {
    const r = await call<{ items?: unknown[] } | unknown[]>("/admin/redteam/runs", undefined, () => mock.mockRedteamRuns());
    return (Array.isArray(r) ? r : r.items ?? []).map(normaliseRun);
  },
  redteamStart: (cfg: RedteamConfig) => call<{ runId: string }>("/admin/redteam/run", { method: "POST", body: JSON.stringify(cfg), headers: { "Content-Type": "application/json" } }, () => mock.mockRedteamStart(cfg)),
  redteamAbort: () => call<{ ok?: boolean }>("/admin/redteam/abort", { method: "POST" }, () => mock.mockRedteamAbort()),

  coverage: () => call<CoverageResponse>("/admin/coverage", undefined, () => mock.mockCoverage()),

  playground: async (req: PlaygroundRequest): Promise<PlaygroundResult> => {
    const r = await call<PlaygroundResponse>("/admin/playground", { method: "POST", body: JSON.stringify(req), headers: { "Content-Type": "application/json" } }, () => mockPlayground(req));
    return { ...r, record: parseRecord(r.record) };
  },
};

// ---------------------------------------------------------------------------------------------------------------------
// audit export: live = browser navigates to the export URL (token in the query, like EventSource); mock = generated file
// ---------------------------------------------------------------------------------------------------------------------
export function auditExportUrl(format: "jsonl" | "csv", q: AuditQuery): string {
  const { limit: _l, cursor: _c, ...filters } = q;
  void _l; void _c;
  return `${GATEWAY_URL}/admin/audit/export${qs({ format, ...filters, token: TOKEN || undefined })}`;
}
export function exportAudit(format: "jsonl" | "csv", q: AuditQuery, download: (name: string, text: string, type: string) => void): void {
  if (conn.mode === "mock") {
    download(`tollgate-audit-mock.${format}`, mock.mockAuditExport(format, q), format === "csv" ? "text/csv" : "application/x-ndjson");
    return;
  }
  window.location.assign(auditExportUrl(format, q));
}

export const eventsUrl = (): string => `${GATEWAY_URL}/admin/events${qs({ token: TOKEN || undefined })}`;
