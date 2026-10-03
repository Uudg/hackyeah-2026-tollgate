// createGateway(opts): builds every part of the gateway and returns the Hono app (SPEC §1.4).
// server.ts calls it with options from the environment; the test harness calls it in-process.
import { Hono } from "hono";
import { cors } from "hono/cors";
import { resolve } from "node:path";
import { PolicySchema, type Policy } from "@tollgate/policy";
import { createFileStore, parsePolicyText, policyHash, sha256, formatIssue, type FileStore, type Loaded } from "@tollgate/policy/loader";
import YAML from "yaml";
import type { GatewayOptions } from "./config.ts";
import type { Ctx } from "./context.ts";
import { openDb } from "./db/client.ts";
import { EventBus } from "./events.ts";
import { AuditWriter } from "./audit/writer.ts";
import { Telemetry } from "./telemetry/registry.ts";
import { Ledger } from "./budget/ledger.ts";
import { LoopBreaker } from "./budget/loop.ts";
import { CircuitBreaker } from "./budget/circuit.ts";
import { CanaryStore } from "./canaries.ts";
import { Approvals } from "./approvals.ts";
import { createMockProvider } from "./semantic/mock.ts";
import { createOllamaProvider, warmUp } from "./semantic/ollama.ts";
import { offProvider } from "./semantic/off.ts";
import { createEchoUpstream } from "./upstream/echo.ts";
import { createHttpUpstream } from "./upstream/http.ts";
import { parsePricingText, type Pricing } from "./pricing.ts";
import { createFeedSource } from "./feed/loader.ts";
import { checkVersions } from "./feed/versions.ts";
import { chatRoutes } from "./routes/chat.ts";
import { adminRoutes } from "./routes/admin/index.ts";
import { prometheusText } from "./telemetry/prometheus.ts";
import { metricsSummary } from "./telemetry/summary.ts";
import { verifyFile } from "./audit/verify.ts";
import { log } from "./log.ts";

const VERSION = "0.1.0";

/** Used when pricing.json is missing: every model at the default price, local Ollama families at 0. */
const FALLBACK_PRICING: Pricing = {
  currency: "USD",
  models: { "llama3.2:*": { input_per_1k: 0, output_per_1k: 0, local: true }, "qwen2.5:*": { input_per_1k: 0, output_per_1k: 0, local: true } },
  default: { input_per_1k: 0.001, output_per_1k: 0.002 },
};

export interface Gateway {
  app: Hono;
  ctx: Ctx;
  /** In-process policy override (tests): validated like a file, bypasses the watcher. */
  setPolicy(p: unknown): Loaded<Policy>;
  getPolicy(): Loaded<Policy>;
  /** Clears budget windows, loop-breaker history, killed sessions and circuit state (test isolation). */
  resetState(): void;
  close(): void;
}

export function createGateway(opts: GatewayOptions): Gateway {
  const bus = new EventBus();
  const db = openDb(opts.dataDir);
  const timers: Array<ReturnType<typeof setInterval>> = [];
  let lastRaw = "";
  let ctxRef: Ctx | null = null;

  const policyStore: FileStore<Policy> = createFileStore(opts.policyPath, (raw) => { lastRaw = raw; return parsePolicyText(raw); }, {
    onLoaded: (next, prev, changed) => {
      db.query("INSERT OR REPLACE INTO policy_versions (hash, declared_version, loaded_ts, changed_paths, raw_yaml) VALUES (?, ?, ?, ?, ?)")
        .run(next.hash, next.value.version, next.loadedAt, JSON.stringify(changed), next.raw);
      bus.emit("policy.loaded", { version: next.value.version, hash: next.hash, prevHash: prev?.hash ?? null, ts: next.loadedAt, changedPaths: changed });
      if (prev) log("info", "policy loaded", { hash: next.hash, prev: prev.hash, changed });
      ctxRef?.telemetry.counters.policyReloads.inc({ result: "loaded" });
      if (ctxRef) ctxRef.state.lastRejected = null;
      if (ctxRef && opts.timers) void checkVersions(ctxRef);
    },
    onRejected: (errors) => {
      const formatted = errors.map(formatIssue);
      const ts = new Date().toISOString();
      if (ctxRef) ctxRef.state.lastRejected = { ts, errors: formatted };
      ctxRef?.telemetry.counters.policyReloads.inc({ result: "rejected" });
      bus.emit("policy.rejected", { hash: sha256(lastRaw), ts, errors: formatted, issues: errors });
      log("warn", "policy rejected; keeping the last good version", { errors: formatted.slice(0, 5) });
    },
  }, { watch: opts.watch });

  const pricingPath = resolve(opts.pricingPath ?? policyStore.current().value.budgets.pricing_file);
  let pricingStore: FileStore<Pricing> | null = null;
  try {
    pricingStore = createFileStore(pricingPath, parsePricingText, {
      onLoaded: (next) => bus.emit("pricing.loaded", { hash: next.hash, ts: next.loadedAt, models: Object.keys(next.value.models).length }),
      onRejected: (errors) => log("warn", "pricing.json rejected; keeping the last good version", { errors: errors.map(formatIssue).slice(0, 5) }),
    }, { watch: opts.watch });
  } catch (err) {
    log("warn", "pricing.json missing or invalid; using built-in default prices", { error: (err as Error).message.slice(0, 200) });
  }

  const telemetry = new Telemetry(policyStore.current().value.telemetry.reservoir_size);
  const semantic = opts.semanticProvider === "mock" ? createMockProvider(opts.mockMarkers)
    : opts.semanticProvider === "off" ? offProvider
    : createOllamaProvider(opts.ollamaUrl, opts.ollamaKeepAlive);
  const upstream = opts.upstream === "echo" ? createEchoUpstream() : createHttpUpstream();

  const feedSource = createFeedSource(opts.feedPath ?? policyStore.current().value.controls.signatures.feed, () => policyStore.current().value, bus, { watch: opts.watch, timers: opts.timers }, () => {
    if (!ctxRef) return;
    ctxRef.state.feedLoadedAt = Date.now();
    ctxRef.telemetry.counters.feedReloads.inc({ result: "loaded" });
    if (opts.timers) void checkVersions(ctxRef);
  });

  const ctx: Ctx = {
    opts, db, bus, telemetry, semantic, upstream,
    audit: new AuditWriter(opts.dataDir, opts.auditMaxMb * 1024 * 1024),
    ledger: new Ledger(db),
    loop: new LoopBreaker(db),
    circuit: new CircuitBreaker((host, state) => bus.emit("circuit.state", { host, state })),
    canaries: new CanaryStore(db, () => policyStore.current().value),
    approvals: new Approvals(db, bus),
    policy: () => policyStore.current(),
    feed: () => feedSource.current(),
    pricing: () => pricingStore?.current().value ?? FALLBACK_PRICING,
    reloadFeed: () => feedSource.reload(),
    pricingMissing: new Set(),
    state: {
      versionMatches: [], ollamaVersion: null, classifierReachable: null, lastVerify: null, lastRejected: null,
      feedLoadedAt: feedSource.current() ? Date.now() : null, latestBypassRate: null,
    },
  };
  ctxRef = ctx;
  ctx.canaries.ensureGenerated();
  ctx.state.lastVerify = { ok: verifyFile(ctx.audit.path).ok, at: Date.now() };

  const refreshSemanticStatus = async () => {
    const s = await semantic.status(ctx.policy().value);
    ctx.state.classifierReachable = s.classifier;
  };
  if (opts.timers) {
    void checkVersions(ctx);
    void refreshSemanticStatus();
    if (opts.semanticProvider === "ollama") {
      const s = ctx.policy().value.semantic;
      void warmUp(opts.ollamaUrl, opts.ollamaKeepAlive, [s.classifier_model, s.judge_model, ...(s.jailbreak_model ? [s.jailbreak_model] : [])]);
    }
    timers.push(setInterval(() => bus.emit("metrics.tick", metricsSummary(ctx)), 2000));
    timers.push(setInterval(() => void refreshSemanticStatus(), 30_000));
    timers.push(setInterval(() => ctx.ledger.prune(), 10 * 60_000));
  }

  const app = new Hono();
  const origins = opts.corsOrigins;
  app.use("/admin/*", cors({ origin: origins, allowHeaders: ["Authorization", "Content-Type", "Last-Event-ID"], exposeHeaders: ["Content-Disposition"] }));
  app.use("/v1/*", cors({ origin: origins, exposeHeaders: ["X-Tollgate-Decision", "X-Tollgate-Rule", "X-Tollgate-Tier", "X-Tollgate-Policy", "X-Tollgate-Event", "X-Tollgate-Latency"] }));
  app.route("/", chatRoutes(ctx));
  app.route("/admin", adminRoutes(ctx, opts.policyPath));
  app.get("/healthz", async (c) => {
    const p = ctx.policy();
    const f = ctx.feed();
    const models = await semantic.status(p.value);
    return c.json({
      ok: true, version: VERSION,
      policy: { hash: p.hash, version: p.value.version },
      feed: { hash: f?.loaded.hash ?? null, entries: f?.loaded.value.entries.length ?? 0 },
      mode: { semanticProvider: semantic.name, upstream: upstream.name },
      upstream: { reachable: ctx.state.ollamaVersion !== null || upstream.name === "echo", ollamaVersion: ctx.state.ollamaVersion },
      models, uptime_s: Math.round((Date.now() - telemetry.startedAt) / 1000),
    });
  });
  app.get("/metrics", (c) => {
    if (opts.metricsAuth && opts.adminToken && c.req.header("authorization") !== `Bearer ${opts.adminToken}`) return c.text("admin token required\n", 401);
    return c.text(prometheusText(ctx), 200, { "content-type": "text/plain; version=0.0.4" });
  });
  app.notFound((c) => c.json({ error: { type: "not_found", message: `${c.req.method} ${c.req.path} is not a Tollgate route` } }, 404));
  app.onError((err, c) => {
    log("error", "unhandled error", { path: c.req.path, error: err.message });
    return c.json({ error: { type: "internal_error", message: "internal gateway error" } }, 500);
  });

  return {
    app, ctx,
    setPolicy(p) {
      const value = PolicySchema.parse(p);
      const raw = YAML.stringify(value);
      const loaded: Loaded<Policy> = { ok: true, value, hash: policyHash(value), loadedAt: new Date().toISOString(), raw };
      policyStore.set(loaded);
      return policyStore.current();
    },
    getPolicy: () => policyStore.current(),
    resetState() {
      db.exec("DELETE FROM usage_windows; DELETE FROM request_hashes; DELETE FROM killed_sessions;");
      ctx.circuit.reset();
    },
    close() {
      for (const t of timers) clearInterval(t);
      policyStore.close();
      pricingStore?.close();
      feedSource.close();
      ctx.audit.close();
      db.close();
    },
  };
}
