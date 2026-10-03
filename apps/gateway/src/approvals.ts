// Human approval queue for tool calls (SPEC §7.5 step 4). The waiting request holds a promise; POST
// /admin/approvals/:id resolves it. Unanswered approvals expire as a block.
import type { Db } from "./db/client.ts";
import type { EventBus } from "./events.ts";
import { newId } from "./ids.ts";

export type ApprovalStatus = "pending" | "approved" | "denied" | "expired";

export interface Approval {
  id: string; ts: string; agentId: string; sessionId: string; eventId: string | null; toolName: string;
  arguments: unknown; status: ApprovalStatus; resolvedTs: string | null; resolvedBy: string | null; note: string | null;
}

interface Row { id: string; ts: string; agent_id: string; session_id: string; event_id: string | null; tool_name: string; arguments_json: string; status: ApprovalStatus; resolved_ts: string | null; resolved_by: string | null; note: string | null }

const toApproval = (r: Row): Approval => ({
  id: r.id, ts: r.ts, agentId: r.agent_id, sessionId: r.session_id, eventId: r.event_id, toolName: r.tool_name,
  arguments: JSON.parse(r.arguments_json), status: r.status, resolvedTs: r.resolved_ts, resolvedBy: r.resolved_by, note: r.note,
});

export class Approvals {
  private waiting = new Map<string, (s: Exclude<ApprovalStatus, "pending">) => void>();
  constructor(private db: Db, private bus: EventBus) {}

  /** Insert a pending approval and wait for a decision or the timeout. */
  async request(p: { agentId: string; sessionId: string; eventId: string; toolName: string; args: unknown; timeoutMs: number }): Promise<{ id: string; status: Exclude<ApprovalStatus, "pending"> }> {
    const id = newId();
    const ts = new Date().toISOString();
    this.db.query("INSERT INTO approvals (id, ts, agent_id, session_id, event_id, tool_name, arguments_json, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')")
      .run(id, ts, p.agentId, p.sessionId, p.eventId, p.toolName, JSON.stringify(p.args ?? {}));
    this.bus.emit("approval.pending", { id, agentId: p.agentId, toolName: p.toolName, arguments: p.args, expiresAt: new Date(Date.now() + p.timeoutMs).toISOString() });
    const status = await new Promise<Exclude<ApprovalStatus, "pending">>((resolve) => {
      const timer = setTimeout(() => { this.waiting.delete(id); resolve("expired"); }, p.timeoutMs);
      this.waiting.set(id, (s) => { clearTimeout(timer); this.waiting.delete(id); resolve(s); });
    });
    if (status === "expired") {
      this.db.query("UPDATE approvals SET status = 'expired', resolved_ts = ? WHERE id = ? AND status = 'pending'").run(new Date().toISOString(), id);
      this.bus.emit("approval.resolved", { id, status });
    }
    return { id, status };
  }

  resolve(id: string, decision: "approve" | "deny", note: string | null, by = "admin"): Approval | null {
    const status: ApprovalStatus = decision === "approve" ? "approved" : "denied";
    const r = this.db.query("UPDATE approvals SET status = ?, resolved_ts = ?, resolved_by = ?, note = ? WHERE id = ? AND status = 'pending'")
      .run(status, new Date().toISOString(), by, note, id);
    if (r.changes === 0) return null;
    this.waiting.get(id)?.(status);
    this.bus.emit("approval.resolved", { id, status });
    return this.get(id);
  }

  get(id: string): Approval | null {
    const r = this.db.query("SELECT * FROM approvals WHERE id = ?").get(id) as Row | null;
    return r ? toApproval(r) : null;
  }

  list(status?: string): Approval[] {
    const rows = (status
      ? this.db.query("SELECT * FROM approvals WHERE status = ? ORDER BY ts DESC LIMIT 200").all(status)
      : this.db.query("SELECT * FROM approvals ORDER BY ts DESC LIMIT 200").all()) as Row[];
    return rows.map(toApproval);
  }
}
