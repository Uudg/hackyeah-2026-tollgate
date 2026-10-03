// Typed in-process event bus. /admin/events fans it out as SSE (SPEC §8).
import type { EventName, TollgateEvents } from "@tollgate/policy";
import { newId } from "./ids.ts";

export interface BusEvent<K extends EventName = EventName> { event: K; id: string; data: TollgateEvents[K] }
type Listener = (e: BusEvent) => void;

export class EventBus {
  private listeners = new Set<Listener>();

  emit<K extends EventName>(event: K, data: TollgateEvents[K], id: string = newId()): void {
    const e = { event, id, data } as BusEvent;
    for (const l of this.listeners) {
      try { l(e); }
      catch (err) { console.error(JSON.stringify({ level: "error", msg: "event listener failed", event, error: String(err) })); }
    }
  }

  on(l: Listener): () => void {
    this.listeners.add(l);
    return () => this.listeners.delete(l);
  }

  /** Resolves with the next event of this name (tests). */
  once<K extends EventName>(event: K, timeoutMs = 2000): Promise<TollgateEvents[K]> {
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => { off(); reject(new Error(`timeout waiting for ${event}`)); }, timeoutMs);
      const off = this.on((e) => { if (e.event === event) { clearTimeout(t); off(); resolve(e.data as TollgateEvents[K]); } });
    });
  }
}
