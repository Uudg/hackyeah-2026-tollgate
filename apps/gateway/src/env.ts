// Repo root and the root .env. `bun run gateway` runs with cwd apps/gateway, and Bun only auto-loads .env from the
// cwd, so the root .env is loaded here (existing variables win) and relative paths resolve against the repo root.
import { existsSync, readFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";

export const ROOT = resolve(import.meta.dir, "../../..");

/** Minimal KEY=VALUE parser: comments, blank lines, optional quotes. Never overrides a variable already set. */
export function loadRootEnv(path = resolve(ROOT, ".env")): void {
  if (!existsSync(path)) return;
  for (const line of readFileSync(path, "utf8").split(/\r?\n/)) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (!m || line.trimStart().startsWith("#")) continue;
    const [, key, raw] = m as unknown as [string, string, string];
    const value = /^(["']).*\1$/.test(raw) ? raw.slice(1, -1) : raw.replace(/\s+#.*$/, "");
    if (process.env[key] === undefined) process.env[key] = value;
  }
}

/** Resolve a path from the environment against the repo root (not the cwd). */
export const fromRoot = (p: string) => (isAbsolute(p) ? p : resolve(ROOT, p));

loadRootEnv();
