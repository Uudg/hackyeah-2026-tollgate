"use client";
import Link from "next/link";
import type { DecisionRecord } from "@tollgate/policy";
import { api } from "@/lib/gateway";
import { useAsync } from "@/lib/hooks";
import { downloadText, fmtDateTime, fmtMsUnit, pretty } from "@/lib/format";
import { Chip, DecisionBadge, ErrorNote, JsonBlock, KV, Loading, PageHeader, Panel } from "./ui";
import { StageBar } from "./charts";
import { StageStrip } from "./StageStrip";

export function testCaseYaml(r: DecisionRecord): string {
  const q = (s: string) => JSON.stringify(s); // a JSON string is a valid YAML double-quoted scalar
  const lines = [
    `- id: ${q(`from-audit-${r.id.toLowerCase()}`).slice(1, -1)}`,
    `  control: ${r.controlId ?? "policy"}`,
    `  owasp: [${r.owasp.join(", ")}]`,
    `  tags: [deterministic, from-audit]`,
    `  agent: ${r.agentId}`,
    `  model: ${q(r.model)}`,
  ];
  if (r.direction === "request") {
    lines.push(`  input: ${q(r.excerptRedacted ?? "")}   # replace with the full original input: the audit log keeps only a redacted excerpt`);
  } else {
    lines.push(`  input: "Summarise the document."`);
    lines.push(`  mock_upstream:   # direction ${r.direction}: put the model output that triggered the rule here`);
    lines.push(`    content: ${q(r.excerptRedacted ?? "")}`);
  }
  lines.push("  expect:", `    decision: ${r.decision}`);
  if (r.ruleId) lines.push(`    rule: ${r.ruleId}`);
  if (r.tier !== null) lines.push(`    tier: ${r.tier}`);
  lines.push(`    direction: ${r.direction}`, `    status: ${r.httpStatus}`, `    enforced: ${r.enforced}`);
  return `${lines.join("\n")}\n`;
}

export default function EventDetail({ id }: { id: string }) {
  const req = useAsync(() => api.auditOne(id), [id]);
  const r = req.data;
  return (
    <>
      <PageHeader title="Event" sub={<span className="mono">{id}</span>}
        actions={<>
          <Link className="btn" href="/security">Back to events</Link>
          {r && <button className="btn btn-primary" onClick={() => downloadText(`${r.id}.yaml`, testCaseYaml(r), "text/yaml")}>Add as test case</button>}
        </>} />
      {req.loading && !r && <Loading />}
      {req.error && <ErrorNote onRetry={req.reload}>{req.error}</ErrorNote>}
      {r && (
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
          <div className="space-y-3 lg:col-span-2">
            <Panel title="Verdict" actions={<DecisionBadge decision={r.decision} enforced={r.enforced} />}>
              <dl>
                <KV k="Rule" mono>{r.ruleId ?? "no rule (clean)"}</KV>
                <KV k="Control">{r.controlId ?? "-"}</KV>
                <KV k="OWASP"><span className="flex flex-wrap gap-1">{r.owasp.length ? r.owasp.map((o) => <Chip key={o}>{o}</Chip>) : "-"}</span></KV>
                <KV k="Tier">{r.tier === null ? "decided outside the cascade" : r.tier}</KV>
                <KV k="Direction">{r.direction}</KV>
                <KV k="Enforced">{r.enforced ? "yes" : "no, monitor mode (would have been applied)"}</KV>
                <KV k="HTTP status">{r.httpStatus}</KV>
                {r.excerptRedacted && <KV k="Excerpt" mono>{r.excerptRedacted}</KV>}
              </dl>
            </Panel>

            <Panel title="Stages"><StageStrip record={r} /></Panel>
            <Panel title="Latency by stage"><StageBar latency={r.latencyMs} /></Panel>

            <Panel title={`Hits (${r.hits.length})`} bodyClass="p-0">
              {r.hits.length === 0 ? <div className="px-3 py-4 text-[12px] text-mute">No control matched this request.</div> : (
                <ul className="divide-y divide-line">
                  {r.hits.map((h, i) => (
                    <li key={i} className="px-3 py-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="mono text-[12px] font-medium">{h.ruleId}</span>
                        <DecisionBadge decision={h.action} enforced={r.enforced} />
                        <span className="text-[11px] text-mute">{h.controlId}</span>
                        {h.owasp.map((o) => <Chip key={o}>{o}</Chip>)}
                      </div>
                      {h.span && <div className="mono mt-1 text-[11px] text-mute">{h.span.field} [{h.span.start}:{h.span.end}]</div>}
                      {h.excerptRedacted && <div className="mono mt-1 break-words rounded border border-line bg-[#f7f8f9] px-2 py-1 text-[11.5px]">{h.excerptRedacted}</div>}
                      {h.details && <details className="mt-1"><summary className="cursor-pointer text-[11px] text-mute">details</summary><JsonBlock value={h.details} max={160} /></details>}
                    </li>
                  ))}
                </ul>
              )}
            </Panel>

            {(r.details.tier1 !== undefined || r.details.tier2 !== undefined) && (
              <Panel title="Semantic details (raw)">
                {r.details.tier1 !== undefined && <><div className="label">Tier 1 classifier</div><JsonBlock value={r.details.tier1} max={180} /></>}
                {r.details.tier2 !== undefined && <><div className="label mt-2">Tier 2 judge</div><JsonBlock value={r.details.tier2} max={180} /></>}
              </Panel>
            )}
            <Panel title="Other details"><JsonBlock value={Object.fromEntries(Object.entries(r.details).filter(([k]) => k !== "tier1" && k !== "tier2"))} max={260} /></Panel>
          </div>

          <div className="space-y-3">
            <Panel title="Context">
              <dl>
                <KV k="Time">{fmtDateTime(r.ts)}</KV>
                <KV k="Agent">{r.agentId}</KV>
                <KV k="Session" mono>{r.sessionId}</KV>
                <KV k="Model" mono>{r.model}</KV>
                <KV k="Tokens">{r.tokensIn} in / {r.tokensOut} out</KV>
                <KV k="Cost">${r.costUsd.toFixed(6)}</KV>
                <KV k="Compute">{r.computeSeconds.toFixed(3)} s</KV>
                <KV k="Total latency">{fmtMsUnit(r.latencyMs.total)}</KV>
              </dl>
            </Panel>
            <Panel title="Policy and feed">
              <dl>
                <KV k="Policy" mono><Link className="text-accent underline" href={`/policy#${r.policyVersion}`}>{r.policyVersion}</Link></KV>
                <KV k="Declared version">v{r.policyDeclaredVersion}</KV>
                <KV k="Feed" mono>{r.feedVersion ?? "-"}</KV>
              </dl>
              <p className="mt-2 text-[11px] text-mute">The policy link opens the version timeline at the hash this decision was made under.</p>
            </Panel>
            <Panel title="Raw record"><details><summary className="cursor-pointer text-[12px] text-mute">Show JSON</summary><JsonBlock value={pretty(r)} max={360} /></details></Panel>
          </div>
        </div>
      )}
    </>
  );
}
