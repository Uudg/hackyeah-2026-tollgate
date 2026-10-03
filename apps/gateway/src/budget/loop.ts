// Loop breaker (SPEC §5.4): the same request from the same agent too often inside a window = a stuck agent.
import { sha256 } from "@tollgate/policy/loader";
import type { Db } from "../db/client.ts";

export function requestHash(agentId: string, model: string, normalizedLastUser: string, toolNames: string[]): string {
  const text = normalizedLastUser.toLowerCase().replace(/\s+/g, " ").trim();
  return sha256(`${agentId}|${model}|${text}|${sha256(JSON.stringify(toolNames))}`);
}

export class LoopBreaker {
  constructor(private db: Db) {}

  /** Count earlier identical requests inside the window, then record this one. */
  check(agentId: string, hash: string, windowMs: number): number {
    const now = Date.now();
    const { n } = this.db.query("SELECT COUNT(*) AS n FROM request_hashes WHERE agent_id = ? AND hash = ? AND ts > ?").get(agentId, hash, now - windowMs) as { n: number };
    this.db.query("DELETE FROM request_hashes WHERE agent_id = ? AND ts <= ?").run(agentId, now - windowMs);
    this.db.query("INSERT INTO request_hashes (agent_id, hash, ts) VALUES (?, ?, ?)").run(agentId, hash, now);
    return n;
  }
}
