import type { NextConfig } from "next";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

// One .env at the repo root serves the gateway and the dashboard (NEXT_PUBLIC_GATEWAY_URL, NEXT_PUBLIC_ADMIN_TOKEN).
// Next only reads .env files from apps/dashboard; variables already set (or in a local .env) win.
const rootEnv = resolve(__dirname, "../../.env");
if (existsSync(rootEnv)) {
  for (const line of readFileSync(rootEnv, "utf8").split(/\r?\n/)) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (!m || line.trimStart().startsWith("#")) continue;
    const raw = m[2] ?? "";
    const value = /^(["']).*\1$/.test(raw) ? raw.slice(1, -1) : raw.replace(/\s+#.*$/, "");
    if (process.env[m[1]!] === undefined) process.env[m[1]!] = value;
  }
}

const nextConfig: NextConfig = {
  // @tollgate/policy ships TypeScript source (zod schemas only); compile it with the app.
  transpilePackages: ["@tollgate/policy"],
  // The dashboard is opened as localhost:3000 or 127.0.0.1:3000.
  allowedDevOrigins: ["127.0.0.1"],
};

export default nextConfig;
