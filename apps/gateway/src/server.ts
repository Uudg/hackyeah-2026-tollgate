import { Hono } from "hono";

const port = Number(process.env.TOLLGATE_PORT ?? 8787);
const app = new Hono();
app.get("/healthz", (c) => c.json({ ok: true }));

Bun.serve({ port, fetch: app.fetch });
console.log(JSON.stringify({ level: "info", msg: `tollgate gateway :${port}` }));
