// GET /admin/events: Server-Sent Events (SPEC §8). Heartbeat comment every telemetry.sse_heartbeat_ms;
// Last-Event-ID replays up to 200 newer decision events from SQLite.
import type { Ctx } from "../../context.ts";
import { rowToRecord } from "../../pipeline/record.ts";
import type { BusEvent } from "../../events.ts";

export function sseRoute(ctx: Ctx, req: Request, lastEventId: string | null): Response {
  const enc = new TextEncoder();
  let off: (() => void) | null = null;
  let heartbeat: ReturnType<typeof setInterval> | null = null;
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      const send = (e: { event: string; id: string; data: unknown }) => {
        try { controller.enqueue(enc.encode(`event: ${e.event}\nid: ${e.id}\ndata: ${JSON.stringify(e.data)}\n\n`)); }
        catch { cleanup(); } // client went away mid-write: stop sending
      };
      const cleanup = () => {
        off?.(); off = null;
        if (heartbeat) clearInterval(heartbeat);
        heartbeat = null;
      };
      controller.enqueue(enc.encode(": connected\n\n"));
      if (lastEventId) {
        const rows = ctx.db.query("SELECT * FROM events WHERE id > ? ORDER BY id ASC LIMIT 200").all(lastEventId);
        for (const r of rows) { const rec = rowToRecord(r); send({ event: "decision", id: rec.id, data: rec }); }
      }
      off = ctx.bus.on((e: BusEvent) => send(e));
      heartbeat = setInterval(() => {
        try { controller.enqueue(enc.encode(": ping\n\n")); } catch { cleanup(); }
      }, ctx.policy().value.telemetry.sse_heartbeat_ms);
      req.signal.addEventListener("abort", () => { cleanup(); try { controller.close(); } catch { /* already closed */ } });
    },
    cancel() {
      off?.();
      if (heartbeat) clearInterval(heartbeat);
    },
  });
  return new Response(stream, { headers: { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" } });
}
