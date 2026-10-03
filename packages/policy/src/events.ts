// Event names and payloads on /admin/events (SPEC §8). TypeScript only; the dashboard imports these types.
import type { DecisionRecord } from "./decision.ts";
import type { Issue } from "./loader.ts";

export interface TollgateEvents {
  "decision": DecisionRecord;
  "policy.loaded": { version: number; hash: string; prevHash: string | null; ts: string; changedPaths: string[] };
  "policy.rejected": { hash: string; ts: string; errors: string[]; issues: Issue[] };
  "feed.loaded": { version: string; entries: number; enabledEntries: number; source: string; ts: string };
  "feed.rejected": { ts: string; errors: string[]; source: string };
  "feed.version_match": { entryId: string; component: string; version: string; cve: string | null };
  "pricing.loaded": { hash: string; ts: string; models: number };
  "budget.exceeded": { agentId: string; ruleId: string; used: number; limit: number };
  "approval.pending": { id: string; agentId: string; toolName: string; arguments: unknown; expiresAt: string };
  "approval.resolved": { id: string; status: "approved" | "denied" | "expired" };
  "session.killed": { sessionId: string; agentId: string; reason: string; eventId: string };
  "circuit.state": { host: string; state: "closed" | "open" | "half_open" };
  "redteam.progress": { runId: string; attempts: number; bypasses: number; current: string };
  "redteam.bypass": { runId: string; resultId: string; controlId: string; mutators: string[]; casePath: string };
  "redteam.done": { runId: string; attempts: number; bypasses: number; status: "done" | "aborted" };
  "canary.tripped": { canaryId: string; kind: string; agentId: string; sessionId: string; eventId: string; direction: string };
  "metrics.tick": Record<string, unknown>;
}
export type EventName = keyof TollgateEvents;
export type TollgateEvent = { [K in EventName]: { event: K; id: string; data: TollgateEvents[K] } }[EventName];
