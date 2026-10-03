// bun:sqlite connection, WAL mode, schema from schema.sql.
import { Database } from "bun:sqlite";
import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

export type Db = Database;

export function openDb(dataDir: string): Db {
  mkdirSync(dataDir, { recursive: true });
  const db = new Database(join(dataDir, "tollgate.db"), { create: true });
  db.exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = 2000;");
  db.exec(readFileSync(new URL("./schema.sql", import.meta.url), "utf8"));
  return db;
}
