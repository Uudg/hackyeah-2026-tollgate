-- SQLite schema (SPEC §5.1). WAL mode. Queryable state only; the audit log is ./data/audit.jsonl.
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY, ts TEXT NOT NULL, agent_id TEXT NOT NULL, session_id TEXT NOT NULL,
  model TEXT, direction TEXT, decision TEXT NOT NULL, enforced INTEGER NOT NULL, tier INTEGER,
  rule_id TEXT, control_id TEXT, owasp TEXT, policy_version TEXT NOT NULL, feed_version TEXT,
  latency_total_ms REAL, latency_json TEXT, tokens_in INTEGER, tokens_out INTEGER, cost_usd REAL,
  compute_seconds REAL, http_status INTEGER, excerpt_redacted TEXT, hits_json TEXT, details_json TEXT
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_agent_ts ON events(agent_id, ts);
CREATE INDEX IF NOT EXISTS events_decision ON events(decision);

CREATE TABLE IF NOT EXISTS usage_windows (
  agent_id TEXT NOT NULL, kind TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  requests INTEGER NOT NULL DEFAULT 0, tokens_in INTEGER NOT NULL DEFAULT 0, tokens_out INTEGER NOT NULL DEFAULT 0,
  usd REAL NOT NULL DEFAULT 0, compute_ms INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (agent_id, kind, window_start)
);

CREATE TABLE IF NOT EXISTS request_hashes (
  agent_id TEXT NOT NULL, hash TEXT NOT NULL, ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS request_hashes_idx ON request_hashes(agent_id, hash, ts);

-- Keyed per agent: X-Session-Id is chosen by the client, so one agent must not be able to kill another's session.
-- Data dirs created before this key are migrated by openDb() (db/client.ts).
CREATE TABLE IF NOT EXISTS killed_sessions (
  agent_id TEXT NOT NULL, session_id TEXT NOT NULL, ts TEXT NOT NULL, reason TEXT NOT NULL, event_id TEXT,
  PRIMARY KEY (agent_id, session_id)
);

CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY, ts TEXT NOT NULL, agent_id TEXT NOT NULL, session_id TEXT NOT NULL, event_id TEXT,
  tool_name TEXT NOT NULL, arguments_json TEXT NOT NULL, status TEXT NOT NULL,
  resolved_ts TEXT, resolved_by TEXT, note TEXT
);

CREATE TABLE IF NOT EXISTS canaries (
  id TEXT PRIMARY KEY, token TEXT NOT NULL UNIQUE, kind TEXT NOT NULL,
  label TEXT, created_ts TEXT NOT NULL, planted_in TEXT, tripped_count INTEGER NOT NULL DEFAULT 0, last_tripped_ts TEXT
);

CREATE TABLE IF NOT EXISTS policy_versions (
  hash TEXT PRIMARY KEY, declared_version INTEGER, loaded_ts TEXT NOT NULL, changed_paths TEXT, raw_yaml TEXT
);

CREATE TABLE IF NOT EXISTS redteam_runs (
  id TEXT PRIMARY KEY, started_ts TEXT NOT NULL, finished_ts TEXT, status TEXT NOT NULL,
  policy_version TEXT NOT NULL, attempts INTEGER DEFAULT 0, bypasses INTEGER DEFAULT 0, config_json TEXT
);
CREATE TABLE IF NOT EXISTS redteam_results (
  id TEXT PRIMARY KEY, run_id TEXT NOT NULL, seed_id TEXT NOT NULL, control_id TEXT NOT NULL, owasp TEXT,
  mutators TEXT NOT NULL, input TEXT NOT NULL, decision TEXT NOT NULL, rule_id TEXT, tier INTEGER,
  bypass INTEGER NOT NULL, generated_case_path TEXT, ts TEXT NOT NULL
);
