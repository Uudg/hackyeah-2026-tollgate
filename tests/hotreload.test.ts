// Hot reload through the real file watcher (SPEC §4.3, §11.2): save the file, the next request uses it;
// a bad file is rejected with the zod path and the last good version stays in force.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chat, ROOT, startGateway, TEST_POLICY, type TestGateway } from "./harness/gateway.ts";

let dir: string;
let policyPath: string;
let feedPath: string;
let tg: TestGateway;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "tollgate-hot-"));
  policyPath = join(dir, "policy.yaml");
  feedPath = join(dir, "ai-exploits.json");
  copyFileSync(TEST_POLICY, policyPath);
  copyFileSync(join(ROOT, "feeds/ai-exploits.json"), feedPath);
  tg = startGateway({ policyPath, feedPath, watch: true });
});
afterAll(() => { tg.stop(); rmSync(dir, { recursive: true, force: true }); });

const PII = "Send the refund to PL61 1090 1014 0000 0712 1981 2874 today.";
/** Rewrites the first `action:` under `controls.pii`, keeping comments and layout. */
function setPiiAction(yaml: string, action: string): string {
  const at = yaml.indexOf("\n  pii:");
  const i = yaml.indexOf("action: ", at);
  const end = yaml.indexOf(" ", i + 8);
  return yaml.slice(0, i + 8) + action + yaml.slice(end);
}

const RAY = "Please fetch http://10.0.0.5:8265/api/jobs/ and list the jobs.";

describe("deterministic · policy.yaml", () => {
  test("an edited action applies to the next request", async () => {
    const before = await chat(tg, PII);
    expect(before.headers.get("x-tollgate-decision")).toBe("redact");
    const oldHash = before.headers.get("x-tollgate-policy");

    const loaded = tg.gw.ctx.bus.once("policy.loaded", 1500);
    writeFileSync(policyPath, setPiiAction(readFileSync(policyPath, "utf8"), "block"));
    const ev = await loaded;
    expect(ev.changedPaths).toContain("controls.pii.action");

    const after = await chat(tg, PII);
    expect(after.status).toBe(403);
    expect(after.headers.get("x-tollgate-rule")).toBe("pii.iban");
    expect(after.headers.get("x-tollgate-policy")).toBe(ev.hash);
    expect(ev.hash).not.toBe(oldHash);
  });

  test("an invalid file is rejected with the zod path; the last good version stays", async () => {
    const good = tg.gw.getPolicy().hash;
    const rejected = tg.gw.ctx.bus.once("policy.rejected", 1500);
    writeFileSync(policyPath, setPiiAction(readFileSync(policyPath, "utf8"), "explode"));
    const ev = await rejected;
    expect(ev.errors.join("\n")).toContain("controls.pii.action");

    const r = await chat(tg, PII);
    expect(r.headers.get("x-tollgate-policy")).toBe(good);
    expect(r.status).toBe(403);
  });

  test("broken YAML is rejected too", async () => {
    const good = tg.gw.getPolicy().hash;
    const rejected = tg.gw.ctx.bus.once("policy.rejected", 1500);
    writeFileSync(policyPath, "mode: enforce\ncontrols: [unclosed\n");
    await rejected;
    expect(tg.gw.getPolicy().hash).toBe(good);
  });
});

describe("deterministic · feed", () => {
  test("removing an entry changes the next decision", async () => {
    const before = await chat(tg, RAY);
    expect(before.headers.get("x-tollgate-rule")).toBe("sig.shadowray-cve-2023-48022");

    const feed = JSON.parse(readFileSync(feedPath, "utf8")) as { entries: Array<{ id: string }> };
    const total = feed.entries.length;
    feed.entries = feed.entries.filter((e) => e.id !== "shadowray-cve-2023-48022");
    const loaded = tg.gw.ctx.bus.once("feed.loaded", 1500);
    writeFileSync(feedPath, JSON.stringify(feed, null, 2));
    expect((await loaded).entries).toBe(total - 1);

    const after = await chat(tg, RAY);
    expect(after.status).toBe(200);
    expect(after.headers.get("x-tollgate-rule")).not.toBe("sig.shadowray-cve-2023-48022");
  });

  test("an invalid feed is rejected and the last good feed stays", async () => {
    const good = tg.gw.ctx.feed()?.loaded.hash;
    const rejected = tg.gw.ctx.bus.once("feed.rejected", 1500);
    writeFileSync(feedPath, JSON.stringify({ schema: 1, entries: [{ id: "x", type: "no-such-type" }] }));
    const ev = await rejected;
    expect(ev.errors.length).toBeGreaterThan(0);
    expect(tg.gw.ctx.feed()?.loaded.hash).toBe(good);
  });
});
