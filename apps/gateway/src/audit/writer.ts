// Append-only, hash-chained audit log (SPEC §9). One in-process queue: hashes are computed in call order,
// lines are written in batches off the request path, fsync every 100 ms or 50 lines.
import { closeSync, existsSync, fsyncSync, openSync, readFileSync, renameSync, statSync, truncateSync, writeSync } from "node:fs";
import { dirname, join } from "node:path";
import type { DecisionRecord } from "@tollgate/policy";
import { brokenName, GENESIS, lineHash, parseHead, rotatedFiles, rotatedName, type AuditLine } from "./chain.ts";
import { log } from "../log.ts";

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

  /**
   * Continue seq and prev_hash from the last line. A truncated last line (crash mid-write) is dropped. A complete
   * last line that is not an audit record (hand-edited file) cannot be continued: the file is moved aside as
   * audit-<ts>.broken.jsonl and a new chain starts at genesis, so the gateway still starts. An empty or missing
   * file continues from the newest rotated file, so the chain spans rotations and restarts.
   */
  private resume() {
    const text = existsSync(this.path) ? readFileSync(this.path, "utf8") : "";
    let end = text.length;
    if (text && !text.endsWith("\n")) {
      end = text.lastIndexOf("\n") + 1;
      truncateSync(this.path, Buffer.byteLength(text.slice(0, end)));
      log("warn", "audit: dropped a truncated last line", { path: this.path });
    }
    const last = text.slice(0, end).trimEnd().split("\n").at(-1);
    if (last) {
      const head = parseHead(last);
      if (head.ok) { this.seq = head.seq; this.prev = head.hash; return; }
      const moved = join(dirname(this.path), brokenName());
      renameSync(this.path, moved);
      log("warn", "audit: last line is not an audit record; moved the file aside and started a new chain at genesis", { path: this.path, movedTo: moved, reason: head.reason });
      return;
    }
    const newest = rotatedFiles(dirname(this.path)).at(-1);
    if (!newest) return;
    const prevLast = readFileSync(join(dirname(this.path), newest), "utf8").trimEnd().split("\n").at(-1);
    const head = prevLast ? parseHead(prevLast) : null;
    if (head?.ok) { this.seq = head.seq; this.prev = head.hash; }
    else log("warn", "audit: newest rotated file has no readable last line; starting a new chain at genesis", { file: newest, reason: head?.reason ?? "empty" });
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
    // The seq in the name keeps names unique (two rotations in one millisecond) and in chain order.
    renameSync(this.path, join(dirname(this.path), rotatedName(this.seq)));
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
