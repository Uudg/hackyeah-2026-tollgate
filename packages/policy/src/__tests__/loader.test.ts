import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, renameSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createFileStore, parsePolicy, type Issue, type Store } from "../loader.ts";
import type { Policy } from "../schema/policy.ts";

const minimal = "version: 1\nmodels: { allow: [llama3.2:3b] }\nagents: { demo: { key: tg_demo_123 } }\n";
const waitFor = async (cond: () => boolean, ms = 2000) => {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error("timeout");
    await Bun.sleep(20);
  }
};

let store: Store<Policy> | null = null;
afterEach(() => store?.close());

describe("policy file store", () => {
  test("hot reload picks up a valid change", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tg-")), path = join(dir, "policy.yaml");
    writeFileSync(path, minimal);
    const loaded: string[] = [];
    store = createFileStore(path, parsePolicy, { onLoaded: (n) => loaded.push(n.version) });
    const v1 = store.current().version;
    writeFileSync(path, minimal + "mode: monitor\n");
    await waitFor(() => store!.current().value.mode === "monitor");
    expect(store.current().version).not.toBe(v1);
    expect(loaded.length).toBe(2);
  });

  test("garbage keeps the last good version and reports the path", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tg-")), path = join(dir, "policy.yaml");
    writeFileSync(path, minimal);
    let rejected: Issue[] | null = null;
    store = createFileStore(path, parsePolicy, { onRejected: (i) => (rejected = i) });
    const v1 = store.current().version;
    writeFileSync(path, minimal + "mode: banana\n");
    await waitFor(() => rejected !== null);
    expect(rejected![0]!.path).toBe("mode");
    expect(store.current().version).toBe(v1);
  });

  test("atomic save via rename is picked up", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tg-")), path = join(dir, "policy.yaml");
    writeFileSync(path, minimal);
    store = createFileStore(path, parsePolicy);
    writeFileSync(join(dir, ".policy.yaml.tmp"), minimal + "mode: monitor\n");
    renameSync(join(dir, ".policy.yaml.tmp"), path);
    await waitFor(() => store!.current().value.mode === "monitor");
  });

  test("invalid file at startup throws", () => {
    const dir = mkdtempSync(join(tmpdir(), "tg-")), path = join(dir, "policy.yaml");
    writeFileSync(path, "mode: banana\n");
    expect(() => createFileStore(path, parsePolicy)).toThrow();
  });
});
