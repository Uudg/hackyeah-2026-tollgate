// bun:sqlite connection, WAL mode, schema from schema.sql, plus the one migration older data dirs need.
import { Database } from "bun:sqlite";
import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

export type Db = Database;

const SCHEMA = readFileSync(new URL("./schema.sql", import.meta.url), "utf8");

export function openDb(dataDir: string): Db {
  mkdirSync(dataDir, { recursive: true });
  const db = new Database(join(dataDir, "tollgate.db"), { create: true });
  db.exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = 2000;");
  db.exec(SCHEMA);
  migrateKilledSessions(db);
  return db;
}

/**
 * killed_sessions used to be keyed by session_id alone. CREATE TABLE IF NOT EXISTS does not change an existing
 * table, so an old one is renamed, recreated from schema.sql with the (agent_id, session_id) key, and copied over.
 */
function migrateKilledSessions(db: Db): void {
  const row = db.query("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'killed_sessions'").get() as { sql: string } | null;
  if (!row || /PRIMARY KEY\s*\(\s*agent_id\s*,\s*session_id\s*\)/i.test(row.sql)) return;
  db.transaction(() => {
    db.exec("ALTER TABLE killed_sessions RENAME TO killed_sessions_v1");
    db.exec(SCHEMA);
    db.exec(`INSERT OR IGNORE INTO killed_sessions (agent_id, session_id, ts, reason, event_id)
      SELECT agent_id, session_id, ts, reason, event_id FROM killed_sessions_v1`);
    db.exec("DROP TABLE killed_sessions_v1");
  })();
}
