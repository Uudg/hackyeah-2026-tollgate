import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, renameSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parsePolicyText, type Issue } from "../loader.ts";
import { createFileStore, type FileStore } from "../watch.ts";
import type { Policy } from "../schema.ts";

const minimal = "version: 1\nmodels: { allow: [llama3.2:3b] }\nagents: { demo: { key: tg_demo_0123456789abcdef } }\n";
const waitFor = async (cond: () => boolean, ms = 2000) => {
  const end = Date.now() + ms;
  while (!cond()) { if (Date.now() > end) throw new Error("timeout"); await Bun.sleep(20); }
};
const tmpPolicy = (text: string) => {
  const path = join(mkdtempSync(join(tmpdir(), "tg-")), "policy.yaml");
  writeFileSync(path, text);
  return path;
};

let store: FileStore<Policy> | null = null;
afterEach(() => store?.close());

describe("policy file store", () => {
  test("hot reload picks up a valid change and reports changed paths", async () => {
    const path = tmpPolicy(minimal);
    let changed: string[] = [];
    store = createFileStore(path, parsePolicyText, { onLoaded: (_n, _p, c) => (changed = c) });
    const h1 = store.current().hash;
    writeFileSync(path, minimal + "mode: monitor\n");
    await waitFor(() => store!.current().value.mode === "monitor");
    expect(store.current().hash).not.toBe(h1);
    expect(changed).toContain("mode");
  });

  test("comment-only edit keeps the same hash", async () => {
    const path = tmpPolicy(minimal);
    store = createFileStore(path, parsePolicyText);
    const h1 = store.current().hash;
    expect(store.apply("# a comment\n" + minimal).ok).toBe(true);
    expect(store.current().hash).toBe(h1);
  });

  test("garbage keeps the last good version and reports the path", async () => {
    const path = tmpPolicy(minimal);
    let rejected: Issue[] | null = null;
    store = createFileStore(path, parsePolicyText, { onRejected: (e) => (rejected = e) });
    const h1 = store.current().hash;
    writeFileSync(path, minimal + "mode: banana\n");
    await waitFor(() => rejected !== null);
    expect(rejected![0]!.path).toBe("mode");
    expect(store.current().hash).toBe(h1);
  });

  test("atomic save via rename is picked up", async () => {
    const path = tmpPolicy(minimal);
    store = createFileStore(path, parsePolicyText);
    writeFileSync(path + ".tmp", minimal + "mode: monitor\n");
    renameSync(path + ".tmp", path);
    await waitFor(() => store!.current().value.mode === "monitor");
  });

  test("invalid file at startup throws", () => {
    expect(() => createFileStore(tmpPolicy("mode: banana\n"), parsePolicyText)).toThrow();
  });
});
