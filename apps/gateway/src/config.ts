// Gateway options. server.ts builds them from the environment (SPEC §2.1, .env.example); tests pass them directly.
import { fromRoot } from "./env.ts";

export type SemanticProviderName = "ollama" | "mock" | "off";
export type UpstreamName = "ollama" | "echo";

export interface GatewayOptions {
  policyPath: string;
  /** Signature feed: file path or http(s) URL. Default: policy.controls.signatures.feed. */
  feedPath?: string;
  pricingPath?: string;
  dataDir: string;
  upstream: UpstreamName;
  semanticProvider: SemanticProviderName;
  ollamaUrl: string;
  ollamaKeepAlive: string;
  /** Case-insensitive whole-word markers that make the mock classifier return score 1. */
  mockMarkers: string[];
  /** null = admin routes are open (TOLLGATE_INSECURE_ADMIN=1 or tests that opt in). */
  adminToken: string | null;
  corsOrigins: string[];
  metricsAuth: boolean;
  auditMaxMb: number;
  demoModel: string;
  /** Watch policy, feed and pricing files for changes (off in most tests). */
  watch: boolean;
  /** Red Team Loop seed corpus and the folder its failing cases go to (default: tests/redteam/seeds, tests/cases/generated). */
  seedsDir?: string;
  generatedDir?: string;
  /** Background timers: metrics.tick, pruning, version checks. Off in tests that need a quiet process. */
  timers: boolean;
}

const DEFAULT_MARKERS = "ignore previous instructions,jailbreak,DAN";

export function optionsFromEnv(env: Record<string, string | undefined> = process.env): GatewayOptions {
  const pick = <T extends string>(v: string | undefined, allowed: readonly T[], dflt: T): T => (allowed.includes(v as T) ? (v as T) : dflt);
  return {
    policyPath: fromRoot(env.TOLLGATE_POLICY ?? "./policy.yaml"),
    feedPath: env.TOLLGATE_FEED ? (/^https?:/.test(env.TOLLGATE_FEED) ? env.TOLLGATE_FEED : fromRoot(env.TOLLGATE_FEED)) : undefined,
    pricingPath: env.TOLLGATE_PRICING ? fromRoot(env.TOLLGATE_PRICING) : undefined,
    dataDir: fromRoot(env.TOLLGATE_DATA_DIR ?? "./data"),
    upstream: pick(env.UPSTREAM, ["ollama", "echo"] as const, "ollama"),
    semanticProvider: pick(env.SEMANTIC_PROVIDER, ["ollama", "mock", "off"] as const, "ollama"),
    ollamaUrl: (env.OLLAMA_URL ?? "http://127.0.0.1:11434").replace(/\/$/, ""),
    ollamaKeepAlive: env.OLLAMA_KEEP_ALIVE ?? "30m",
    mockMarkers: (env.SEMANTIC_MOCK_MARKERS ?? DEFAULT_MARKERS).split(",").map((s) => s.trim()).filter(Boolean),
    adminToken: env.ADMIN_TOKEN ? env.ADMIN_TOKEN : null,
    corsOrigins: ["http://localhost:3000", ...(env.TOLLGATE_CORS_ORIGINS ?? "").split(",").map((s) => s.trim()).filter(Boolean)],
    metricsAuth: env.TOLLGATE_METRICS_AUTH === "1",
    auditMaxMb: Number(env.TOLLGATE_AUDIT_MAX_MB ?? 200),
    demoModel: env.DEMO_MODEL ?? "llama3.2:3b",
    watch: true,
    timers: true,
  };
}
