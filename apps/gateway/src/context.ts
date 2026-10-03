// Everything a request needs, built once by createGateway(). The pipeline reads policy/feed snapshots through
// the getters so a hot reload swaps them atomically between requests.
import type { Feed, Policy } from "@tollgate/policy";
import type { Loaded } from "@tollgate/policy/loader";
import type { CompiledFeed } from "@tollgate/controls";
import type { GatewayOptions } from "./config.ts";
import type { Db } from "./db/client.ts";
import type { EventBus } from "./events.ts";
import type { AuditWriter } from "./audit/writer.ts";
import type { Telemetry } from "./telemetry/registry.ts";
import type { Ledger } from "./budget/ledger.ts";
import type { LoopBreaker } from "./budget/loop.ts";
import type { CircuitBreaker } from "./budget/circuit.ts";
import type { CanaryStore } from "./canaries.ts";
import type { Approvals } from "./approvals.ts";
import type { SemanticProvider } from "./semantic/provider.ts";
import type { Upstream } from "./upstream/types.ts";
import type { Pricing } from "./pricing.ts";

export interface FeedSnapshot { loaded: Loaded<Feed>; compiled: CompiledFeed; source: string }

export interface VersionMatch { entryId: string; component: string; version: string; cve: string | null }

export interface Ctx {
  opts: GatewayOptions;
  db: Db;
  bus: EventBus;
  audit: AuditWriter;
  telemetry: Telemetry;
  ledger: Ledger;
  loop: LoopBreaker;
  circuit: CircuitBreaker;
  canaries: CanaryStore;
  approvals: Approvals;
  semantic: SemanticProvider;
  upstream: Upstream;
  policy(): Loaded<Policy>;
  feed(): FeedSnapshot | null;
  pricing(): Pricing;
  reloadFeed(): Promise<boolean>;
  /** Models already reported with pricing.missing. */
  pricingMissing: Set<string>;
  state: {
    versionMatches: VersionMatch[];
    ollamaVersion: string | null;
    classifierReachable: boolean | null;
    lastVerify: { ok: boolean; at: number } | null;
    lastRejected: { ts: string; errors: string[] } | null;
    feedLoadedAt: number | null;
    latestBypassRate: number | null;
    /** Bypass rate per control from the latest finished red-team run (null = no attempts). */
    redteamByControl: Record<string, number | null>;
  };
}
