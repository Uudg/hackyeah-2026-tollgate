// Gateway entry: options from the environment, refuse to start without ADMIN_TOKEN, serve on TOLLGATE_PORT.
import "./env.ts"; // loads the root .env before options are read
import { createGateway } from "./app.ts";
import { optionsFromEnv } from "./config.ts";
import { log } from "./log.ts";

const opts = optionsFromEnv();
if (opts.adminToken === null && process.env.TOLLGATE_INSECURE_ADMIN !== "1") {
  console.error("ADMIN_TOKEN is not set. Set it in .env (openssl rand -hex 16), or TOLLGATE_INSECURE_ADMIN=1 for a local demo.");
  process.exit(1);
}

let gateway;
try {
  gateway = createGateway(opts);
} catch (err) {
  // An invalid policy at startup is fatal: there is no last good version yet (SPEC §4.3).
  console.error((err as Error).message);
  process.exit(1);
}

const port = Number(process.env.TOLLGATE_PORT ?? 8787);
const server = Bun.serve({ port, fetch: gateway.app.fetch, idleTimeout: 0 });
const p = gateway.getPolicy();
log("info", "tollgate gateway listening", {
  url: `http://localhost:${server.port}`, policy: p.hash, mode: p.value.mode,
  semanticProvider: opts.semanticProvider, upstream: opts.upstream, adminAuth: opts.adminToken ? "token" : "insecure",
});

const shutdown = () => { gateway.close(); server.stop(); process.exit(0); };
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
