// Canary store (SPEC §13): generated canaries live in SQLite, static ones come from policy.canaries.tokens.
import { generateCanary, type CanaryKind, type CanaryToken } from "@tollgate/controls";
import type { Policy } from "@tollgate/policy";
import type { Db } from "./db/client.ts";
import { newId } from "./ids.ts";

export interface CanaryRow {
  id: string; token: string; kind: string; label: string | null; created_ts: string; planted_in: string | null;
  tripped_count: number; last_tripped_ts: string | null;
}

const AUTO_KINDS: CanaryKind[] = ["aws_key", "api_key", "record"];

function guessKind(token: string): string {
  if (/^(AKIA|ASIA)/.test(token)) return "aws_key";
  if (/^CANARY-RECORD-/.test(token)) return "record";
  if (/^[A-Z]{2}\d{2}/.test(token)) return "iban";
  return "api_key";
}

export class CanaryStore {
  private cache: CanaryToken[] | null = null;
  constructor(private db: Db, private policy: () => Policy) {}

  /** Generate policy.canaries.auto_generate canaries if the table is empty (first start). */
  ensureGenerated(): void {
    const n = (this.db.query("SELECT COUNT(*) AS n FROM canaries").get() as { n: number }).n;
    if (n > 0) return;
    for (let i = 0; i < this.policy().canaries.auto_generate; i++) this.create(AUTO_KINDS[i % AUTO_KINDS.length]!, `auto ${i + 1}`, null);
  }

  create(kind: CanaryKind, label: string | null, plantedIn: string | null): CanaryRow {
    const id = newId();
    const row: CanaryRow = { id, token: generateCanary(kind, id), kind, label, created_ts: new Date().toISOString(), planted_in: plantedIn, tripped_count: 0, last_tripped_ts: null };
    this.db.query("INSERT INTO canaries (id, token, kind, label, created_ts, planted_in) VALUES (?, ?, ?, ?, ?, ?)")
      .run(row.id, row.token, row.kind, row.label, row.created_ts, row.planted_in);
    this.cache = null;
    return row;
  }

  delete(id: string): boolean {
    const r = this.db.query("DELETE FROM canaries WHERE id = ?").run(id);
    this.cache = null;
    return r.changes > 0;
  }

  rows(): CanaryRow[] {
    const stored = this.db.query("SELECT * FROM canaries ORDER BY created_ts").all() as CanaryRow[];
    const statics = this.policy().canaries.tokens.map((token, i): CanaryRow => ({
      id: `static-${i + 1}`, token, kind: guessKind(token), label: "policy.canaries.tokens", created_ts: "", planted_in: "policy", tripped_count: 0, last_tripped_ts: null,
    }));
    return [...stored, ...statics];
  }

  /** Tokens to scan for: database rows plus the current policy's static tokens. */
  tokens(): CanaryToken[] {
    const statics = this.policy().canaries.tokens.map((token, i) => ({ id: `static-${i + 1}`, token, kind: guessKind(token), label: "policy.canaries.tokens" }));
    this.cache ??= (this.db.query("SELECT id, token, kind, label FROM canaries").all() as CanaryToken[]);
    return [...this.cache, ...statics];
  }

  trip(id: string): void {
    this.db.query("UPDATE canaries SET tripped_count = tripped_count + 1, last_tripped_ts = ? WHERE id = ?").run(new Date().toISOString(), id);
  }

  /** The aws_key and api_key canaries the playground plants into a system prompt. */
  plantable(): { aws: string | null; api: string | null } {
    const rows = this.db.query("SELECT kind, token FROM canaries ORDER BY created_ts").all() as Array<{ kind: string; token: string }>;
    return { aws: rows.find((r) => r.kind === "aws_key")?.token ?? null, api: rows.find((r) => r.kind === "api_key")?.token ?? null };
  }
}
