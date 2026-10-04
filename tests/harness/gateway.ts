// Boots createGateway() in-process on a random port with the echo upstream (SPEC §11.2).
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import YAML from "yaml";
import { createGateway, type Gateway } from "../../apps/gateway/src/app.ts";
import type { GatewayOptions } from "../../apps/gateway/src/config.ts";

export const ROOT = resolve(import.meta.dir, "../..");
export const TEST_POLICY = join(ROOT, "tests/policy.test.yaml");
export const ADMIN_TOKEN = "test-admin-token";

export interface TestGateway {
  url: string;
  dataDir: string;
  gw: Gateway;
  /** tests/policy.test.yaml as written (input form), for dotted overrides. */
  basePolicy: Record<string, unknown>;
  admin: Record<string, string>;
  keyFor(agent: string): string;
  stop(): void;
}

export function startGateway(over: Partial<GatewayOptions> = {}): TestGateway {
  const ownDir = over.dataDir === undefined;
  const dataDir = over.dataDir ?? mkdtempSync(join(tmpdir(), "tollgate-test-"));
  const opts: GatewayOptions = {
    policyPath: TEST_POLICY,
    feedPath: join(ROOT, "feeds/ai-exploits.json"),
    pricingPath: join(ROOT, "pricing.json"),
    dataDir,
    upstream: "echo",
    semanticProvider: "ollama",
    ollamaUrl: "http://127.0.0.1:11434",
    ollamaKeepAlive: "30m",
    mockMarkers: ["ignore previous instructions", "jailbreak", "DAN"],
    adminToken: ADMIN_TOKEN,
    corsOrigins: ["http://localhost:3000"],
    metricsAuth: false,
    auditMaxMb: 200,
    demoModel: "llama3.2:3b",
    watch: false,
    timers: false,
    ...over,
  };
  const gw = createGateway(opts);
  const server = Bun.serve({ port: 0, fetch: gw.app.fetch, idleTimeout: 0 });
  const basePolicy = YAML.parse(gw.getPolicy().raw) as Record<string, unknown>;
  const agents = gw.getPolicy().value.agents;
  return {
    url: `http://localhost:${server.port}`,
    dataDir, gw, basePolicy,
    admin: { authorization: `Bearer ${ADMIN_TOKEN}` },
    keyFor: (agent) => {
      const a = agents[agent];
      if (!a) throw new Error(`fixture names unknown agent "${agent}"`);
      return a.key;
    },
    stop() {
      server.stop(true);
      gw.close();
      if (ownDir) rmSync(dataDir, { recursive: true, force: true });
    },
  };
}

/** Apply dotted overrides ({ "controls.pii.action": "block" }) to a deep copy. Agent ids may contain "-". */
export function deepSet(base: Record<string, unknown>, overrides: Record<string, unknown>): Record<string, unknown> {
  const out = structuredClone(base);
  for (const [path, value] of Object.entries(overrides)) {
    const keys = path.split(".");
    let node = out as Record<string, unknown>;
    for (const k of keys.slice(0, -1)) {
      if (typeof node[k] !== "object" || node[k] === null) node[k] = {};
      node = node[k] as Record<string, unknown>;
    }
    node[keys[keys.length - 1]!] = value;
  }
  return out;
}

/** JSON for an HTTP header: headers carry Latin-1 only, so every non-ASCII character is written as a \\u escape. */
export const asciiJson = (v: unknown) => JSON.stringify(v).replace(/[\u0080-\uffff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);

/** POST a chat request as `agent` (default demo-agent). Returns status, headers and parsed JSON body. */
export async function chat(tg: TestGateway, content: string | unknown[], o: { agent?: string; model?: string; headers?: Record<string, string>; tools?: unknown[]; echo?: unknown } = {}) {
  const messages = typeof content === "string" ? [{ role: "user", content }] : content;
  const headers: Record<string, string> = { "content-type": "application/json", authorization: `Bearer ${tg.keyFor(o.agent ?? "demo-agent")}`, ...o.headers };
  if (o.echo !== undefined) headers["x-tollgate-echo"] = asciiJson(o.echo);
  const res = await fetch(`${tg.url}/v1/chat/completions`, {
    method: "POST", headers, body: JSON.stringify({ model: o.model ?? "llama3.2:3b", messages, ...(o.tools ? { tools: o.tools } : {}) }),
  });
  const text = await res.text();
  let body: unknown = null;
  try { body = JSON.parse(text); } catch { body = text; } // SSE or plain text bodies stay as text
  return { status: res.status, headers: res.headers, body, text };
}

export async function getRecord(tg: TestGateway, id: string | null) {
  const res = await fetch(`${tg.url}/admin/audit/${id}`, { headers: tg.admin });
  return (await res.json()) as import("@tollgate/policy").DecisionRecord;
}
