// Append-only, hash-chained audit log (SPEC §9). One in-process queue: hashes are computed in call order,
// lines are written in batches off the request path, fsync every 100 ms or 50 lines.
import { closeSync, existsSync, fsyncSync, openSync, readFileSync, renameSync, statSync, truncateSync, writeSync } from "node:fs";
import { join } from "node:path";
import type { DecisionRecord } from "@tollgate/policy";
import { GENESIS, lineHash, type AuditLine } from "./chain.ts";

export class AuditWriter {
  readonly path: string;
  private fd: number;
  private seq = 0;
  private prev = GENESIS;
  private queue: string[] = [];
  private unsynced = 0;
  private lastSync = Date.now();
  private scheduled = false;
  private syncTimer: ReturnType<typeof setInterval>;

  constructor(dataDir: string, private maxBytes: number) {
    this.path = join(dataDir, "audit.jsonl");
    this.resume();
    this.fd = openSync(this.path, "a");
    this.syncTimer = setInterval(() => this.sync(), 100);
  }

  /** Read the last line to continue seq and prev_hash; drop a truncated last line left by a crash. */
  private resume() {
    if (!existsSync(this.path)) return;
    const text = readFileSync(this.path, "utf8");
    if (!text) return;
    let end = text.length;
    if (!text.endsWith("\n")) {
      end = text.lastIndexOf("\n") + 1;
      truncateSync(this.path, Buffer.byteLength(text.slice(0, end)));
      console.log(JSON.stringify({ level: "warn", msg: "audit: dropped a truncated last line", path: this.path }));
    }
    const lines = text.slice(0, end).trimEnd().split("\n");
    const last = lines[lines.length - 1];
    if (!last) return;
    const parsed = JSON.parse(last) as AuditLine;
    this.seq = parsed.seq;
    this.prev = parsed.hash;
  }

  /** Assigns seq and hash now (deterministic order); the disk write happens on the next tick. */
  append(record: DecisionRecord): AuditLine {
    this.seq += 1;
    const hash = lineHash(this.prev, record);
    const line: AuditLine = { seq: this.seq, prev_hash: this.prev, hash, record: record as unknown as Record<string, unknown> };
    this.prev = hash;
    this.queue.push(JSON.stringify(line) + "\n");
    if (!this.scheduled) { this.scheduled = true; setImmediate(() => this.flush()); }
    return line;
  }

  flush(): void {
    this.scheduled = false;
    if (this.queue.length === 0) return;
    const batch = this.queue.join("");
    this.unsynced += this.queue.length;
    this.queue = [];
    writeSync(this.fd, batch);
    if (this.unsynced >= 50) this.sync();
    this.rotateIfNeeded();
  }

  private sync() {
    if (this.unsynced === 0) return;
    fsyncSync(this.fd);
    this.unsynced = 0;
    this.lastSync = Date.now();
  }

  /** Rename to audit-<ts>.jsonl; the chain continues in the new file from the last hash. */
  private rotateIfNeeded() {
    if (statSync(this.path).size < this.maxBytes) return;
    this.sync();
    closeSync(this.fd);
    renameSync(this.path, join(this.path, "..", `audit-${new Date().toISOString().replace(/[:.]/g, "-")}.jsonl`));
    this.fd = openSync(this.path, "a");
  }

  head(): { seq: number; hash: string } { return { seq: this.seq, hash: this.prev }; }

  close(): void {
    this.flush();
    this.sync();
    clearInterval(this.syncTimer);
    closeSync(this.fd);
  }
}
