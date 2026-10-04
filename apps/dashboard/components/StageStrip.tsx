"use client";
// Per-stage verdict strip: auth -> budget -> tier 0 -> tier 1 -> tier 2 -> upstream -> output.
// Built only from the DecisionRecord (latencyMs, hits, details). Hits carry no stage field, so stageOf() maps rule ids to stages.
import type { DecisionRecord, Hit } from "@tollgate/policy";
import { SEVERITY } from "@tollgate/policy";
import { STAGES, type Decision, type Stage } from "@/lib/contract";
import { fmtMsUnit } from "@/lib/format";
import { DecisionBadge, cn } from "./ui";

const LABEL: Record<Stage, string> = { auth: "Auth", budget: "Budget", tier0: "Tier 0", tier1: "Tier 1", tier2: "Tier 2", upstream: "Upstream", output: "Output" };
const OUTPUT_ONLY = /^(canaries\.in_output|canaries\.in_tool_call|link_exfil\.|sysprompt\.|tool_calls\.(schema|denied$|approval))/;

export function stageOf(h: Hit, rec: DecisionRecord): Stage {
  const hinted = h.details?.stage;
  if (typeof hinted === "string" && (STAGES as readonly string[]).includes(hinted)) return hinted as Stage;
  const id = h.ruleId;
  if (/^(auth\.|session\.)/.test(id) || id.startsWith("models.")) return "auth";
  if (id.startsWith("budget.")) return "budget";
  if (id === "upstream.error") return "upstream";
  if (id.startsWith("content_safety.") || id === "inject.classifier" || id === "semantic.unavailable") return "tier1";
  if (id === "inject.judge" || id === "semantic.judge_unavailable") return "tier2";
  if (OUTPUT_ONLY.test(id)) return "output";
  if (rec.direction !== "request" && (h.span?.field.startsWith("choices") || h.span?.field.startsWith("tool_calls") || id === rec.ruleId)) return "output";
  return "tier0";
}

/** "timed out" when the semantic hit's reason is a timeout ("timeout after 6000 ms"), otherwise "unavailable". */
function unavailableLine(hits: Hit[], ruleId: string): string {
  const reason = hits.find((h) => h.ruleId === ruleId)?.details?.reason;
  return typeof reason === "string" && reason.startsWith("timeout") ? "timed out" : "unavailable";
}

/** The time shown in a stage cell: "-" for a stage that did not run, never "undefined" or a doubled unit. */
export function stageTime(c: Pick<Cell, "ran" | "ms">): string {
  return c.ran && Number.isFinite(c.ms) ? fmtMsUnit(c.ms) : "";
}

interface Cell { stage: Stage; ms: number; ran: boolean; hits: Hit[]; top: Decision | null; lines: string[] }

export function buildCells(rec: DecisionRecord): Cell[] {
  const t1 = rec.details.tier1 as Record<string, unknown> | string | undefined;
  const t2 = rec.details.tier2 as Record<string, unknown> | string | undefined;
  return STAGES.map((stage) => {
    const hits = rec.hits.filter((h) => stageOf(h, rec) === stage);
    const ms = rec.latencyMs[stage] ?? 0;
    const ran = ms > 0 || hits.length > 0;
    let top: Decision | null = null;
    for (const h of hits) if (h.action !== "allow" && (!top || SEVERITY[h.action] > SEVERITY[top])) top = h.action;
    const lines: string[] = [];
    if (stage === "auth") lines.push(rec.agentId);
    if (stage === "tier0" || stage === "output" || stage === "budget") for (const h of hits.slice(0, 3)) lines.push(h.ruleId);
    if (stage === "tier1") {
      if (rec.details.semantic === "off") lines.push("semantic off");
      else if (t1 === "unavailable") lines.push(unavailableLine(hits, "semantic.unavailable"));
      else if (t1 && typeof t1 === "object") {
        if (typeof t1.score === "number") lines.push(`score ${t1.score}`);
        const cats = t1.categories as string[] | undefined;
        if (cats?.length) lines.push(cats.join(","));
        if (typeof t1.model === "string") lines.push(t1.model);
      }
      for (const h of hits.slice(0, 2)) lines.push(h.ruleId);
    }
    if (stage === "tier2") {
      // A judge that failed or timed out is recorded as the string "unavailable", not an object.
      if (t2 === "unavailable") lines.push(unavailableLine(hits, "semantic.judge_unavailable"));
      else if (t2 && typeof t2 === "object") {
        const verdict = [t2.verdict, t2.confidence].filter((v) => typeof v === "string" || typeof v === "number").join(" ");
        if (verdict) lines.push(verdict);
        if (typeof t2.reason === "string") lines.push(t2.reason.length > 70 ? `${t2.reason.slice(0, 68)}…` : t2.reason);
      }
      for (const h of hits.slice(0, 1)) lines.push(h.ruleId);
    }
    if (stage === "upstream" && ran) {
      lines.push(rec.model);
      if (rec.tokensIn || rec.tokensOut) lines.push(`${rec.tokensIn} in / ${rec.tokensOut} out`);
      if (typeof rec.details.stream === "string") lines.push(`stream ${rec.details.stream}`);
    }
    return { stage, ms, ran, hits, top, lines };
  });
}

export function StageStrip({ record }: { record: DecisionRecord }) {
  const cells = buildCells(record);
  const dry = record.details.dryRun === true;
  return (
    <div>
      <ol className="grid grid-cols-2 gap-1.5 sm:grid-cols-4 lg:grid-cols-7">
        {cells.map((c, i) => {
          const state = c.top ? <DecisionBadge decision={c.top} enforced={record.enforced} /> : c.hits.length ? <span className="text-[11px] text-mute">noted</span> : c.ran ? <span className="text-[11px] text-mute">pass</span> : <span className="text-[11px] text-faint">{dry && (c.stage === "upstream" || c.stage === "output") ? "dry run" : "skipped"}</span>;
          return (
            <li key={c.stage} className={cn("min-h-[74px] rounded border px-2 py-1.5", c.ran ? "border-line-strong bg-panel" : "border-line bg-[#f7f8f9]")}>
              <div className="flex items-center justify-between gap-1">
                <span className={cn("text-[11px] font-medium", c.ran ? "text-ink" : "text-faint")}>{i + 1}. {LABEL[c.stage]}</span>
                <span className="mono whitespace-nowrap text-[11px] text-mute">{stageTime(c)}</span>
              </div>
              <div className="mt-1">{state}</div>
              {c.lines.length > 0 && <ul className="mono mt-1 space-y-px text-[10.5px] leading-[1.35] text-mute">{c.lines.map((l, k) => <li key={k} className="break-words">{l}</li>)}</ul>}
            </li>
          );
        })}
      </ol>
    </div>
  );
}
