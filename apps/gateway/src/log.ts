// Structured JSON logs to stdout. Never log raw message content.
type Level = "debug" | "info" | "warn" | "error";
let quiet = process.env.TOLLGATE_LOG === "silent";

export function setQuiet(q: boolean) { quiet = q; }

export function log(level: Level, msg: string, fields: Record<string, unknown> = {}) {
  if (quiet && level !== "error") return;
  console.log(JSON.stringify({ ts: new Date().toISOString(), level, msg, ...fields }));
}
