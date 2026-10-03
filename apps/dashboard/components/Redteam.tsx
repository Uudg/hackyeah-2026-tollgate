"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import { GatewayError, type RedteamConfig } from "@/lib/contract";
import { api } from "@/lib/gateway";
import { errMsg, fmtDateTime, fmtPct, fmtTime, relTime } from "@/lib/format";
import { useAsync, useNow } from "@/lib/hooks";
import { useLive } from "./Live";
import { DecisionBadge, Empty, ErrorNote, Loading, PageHeader, Panel, ScrollX, Toggle, cn } from "./ui";

// Seed controls come from SPEC §12.1; mutators from §12.2. The two model-backed mutators need include_model_mutators.
const CONTROLS = ["prompt_injection", "content_safety", "secrets", "pii", "link_exfil", "sysprompt", "tool_calls", "signatures"];
const MODEL_MUTATORS = ["translate", "paraphrase"];
const MUTATORS = ["base64", "hex", "url_encode", "leetspeak", "homoglyph", "zero_width", "case_shuffle", "roleplay_wrap", "markdown_wrap", "json_wrap", "payload_split", "prefix_padding", "multi_turn"];

export default function Redteam() {
  const { hub } = useLive();
  const now = useNow(1000);
  const status = useAsync(() => api.redteamStatus(), []);
  const runs = useAsync(() => api.redteamRuns(), []);
  const [live, setLive] = useState<{ runId: string; attempts: number; bypasses: number; current: string } | null>(null);
  const [cases, setCases] = useState<string[]>([]);
  const [err, setErr] = useState<string | null>(null);
  // The gateway answers 501 until the Red Team Loop (M7) exists: that is a state, not a failure.
  const [unavailable, setUnavailable] = useState(false);
  const [busy, setBusy] = useState(false);
  const lastReload = useRef(0);

  const [control, setControl] = useState("");
  const [seeds, setSeeds] = useState("");
  const [mutators, setMutators] = useState<string[]>(MUTATORS);
  const [depth, setDepth] = useState<1 | 2>(2);
  const [maxAttempts, setMaxAttempts] = useState(500);
  const [maxMinutes, setMaxMinutes] = useState("");
  const [concurrency, setConcurrency] = useState(4);
  const [withModel, setWithModel] = useState(false);

  const { reload: reloadStatus } = status;
  const { reload: reloadRuns } = runs;
  useEffect(() => {
    const offs = [
      hub.on("redteam.progress", (e) => {
        setLive(e);
        if (Date.now() - lastReload.current > 1000) { lastReload.current = Date.now(); reloadStatus(); reloadRuns(); }
      }),
      hub.on("redteam.bypass", (e) => { if (e.casePath) setCases((c) => (c.includes(e.casePath) ? c : [e.casePath, ...c])); }),
      hub.on("redteam.done", () => { setLive(null); reloadStatus(); reloadRuns(); }),
    ];
    return () => offs.forEach((f) => f());
  }, [hub, reloadStatus, reloadRuns]);

  const run = status.data?.run ?? null;
  const running = run?.status === "running";
  const attempts = live && run && live.runId === run.id ? live.attempts : run?.attempts ?? 0;
  const bypasses = live && run && live.runId === run.id ? live.bypasses : run?.bypasses ?? 0;
  const max = run?.config?.max_attempts ?? maxAttempts;
  const caseFiles = useMemo(() => {
    const fromResults = (status.data?.recent ?? []).map((r) => r.generatedCasePath).filter((p): p is string => !!p);
    return [...new Set([...cases, ...fromResults])];
  }, [cases, status.data]);

  async function start() {
    setBusy(true); setErr(null);
    const cfg: RedteamConfig = {
      ...(control ? { control } : {}),
      ...(seeds.trim() ? { seeds: seeds.split(/[\s,]+/).filter(Boolean) } : {}),
      mutators: [...mutators, ...(withModel ? MODEL_MUTATORS : [])],
      max_depth: depth, max_attempts: maxAttempts, concurrency, include_model_mutators: withModel, agent: "redteam",
      ...(maxMinutes ? { max_minutes: Number(maxMinutes) } : {}),
    };
    try { await api.redteamStart(cfg); setCases([]); reloadStatus(); reloadRuns(); } catch (e) {
      if (e instanceof GatewayError && e.status === 501) setUnavailable(true); else setErr(errMsg(e));
    }
    setBusy(false);
  }
  async function abort() {
    setBusy(true); setErr(null);
    try { await api.redteamAbort(); reloadStatus(); reloadRuns(); } catch (e) {
      if (e instanceof GatewayError && e.status === 501) setUnavailable(true); else setErr(errMsg(e));
    }
    setBusy(false);
  }

  const toggleMut = (m: string) => setMutators((xs) => (xs.includes(m) ? xs.filter((x) => x !== m) : [...xs, m]));

  return (
    <>
      <PageHeader title="Red team" sub="Mutates attack seeds, sends them through the gateway and records every bypass as a failing regression test." />
      {err && <div className="mb-3"><ErrorNote>{err}</ErrorNote></div>}
      {unavailable && (
        <div className="mb-3 rounded-md border border-line-strong bg-panel px-3 py-2 text-[12px]" role="status">
          <b>Red Team Loop not available yet.</b> <span className="text-mute">This gateway answered 501: the fuzzer is not built in this version. Past results show up here once it is.</span>
        </div>
      )}

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
        <Panel title="Run" className="lg:col-span-1">
          <div className="grid grid-cols-2 gap-2">
            <div className="col-span-2"><label className="label" htmlFor="rt-control">Control (seeds for this control only)</label>
              <select id="rt-control" className="field w-full" value={control} onChange={(e) => setControl(e.target.value)}><option value="">All controls</option>{CONTROLS.map((c) => <option key={c}>{c}</option>)}</select></div>
            <div className="col-span-2"><label className="label" htmlFor="rt-seeds">Seed ids (optional, comma separated)</label>
              <input id="rt-seeds" className="field w-full" placeholder="seed-override-001, seed-pii-001" value={seeds} onChange={(e) => setSeeds(e.target.value)} /></div>
            <div><label className="label" htmlFor="rt-depth">Mutator depth</label>
              <select id="rt-depth" className="field w-full" value={depth} onChange={(e) => setDepth(Number(e.target.value) as 1 | 2)}><option value={1}>1 (each alone)</option><option value={2}>2 (pairs)</option></select></div>
            <div><label className="label" htmlFor="rt-att">Max attempts</label>
              <input id="rt-att" type="number" min={1} className="field w-full" value={maxAttempts} onChange={(e) => setMaxAttempts(Math.max(1, Number(e.target.value) || 1))} /></div>
            <div><label className="label" htmlFor="rt-min">Max minutes</label>
              <input id="rt-min" type="number" min={1} className="field w-full" placeholder="none" value={maxMinutes} onChange={(e) => setMaxMinutes(e.target.value)} /></div>
            <div><label className="label" htmlFor="rt-conc">Concurrency</label>
              <input id="rt-conc" type="number" min={1} max={16} className="field w-full" value={concurrency} onChange={(e) => setConcurrency(Math.max(1, Number(e.target.value) || 1))} /></div>
          </div>
          <fieldset className="mt-3">
            <legend className="label">Mutators ({mutators.length} of {MUTATORS.length})</legend>
            <div className="grid grid-cols-2 gap-x-2 gap-y-1">
              {MUTATORS.map((m) => (
                <label key={m} className="flex items-center gap-1.5 py-0.5 text-[12px] max-md:min-h-10"><input type="checkbox" className="accent-[var(--accent)] max-md:h-5 max-md:w-5" checked={mutators.includes(m)} onChange={() => toggleMut(m)} /><span className="mono">{m}</span></label>
              ))}
            </div>
            <div className="mt-2"><Toggle checked={withModel} onChange={setWithModel} label="Include model-backed mutators" hint="translate, paraphrase: need Ollama" /></div>
          </fieldset>
          <div className="mt-3 flex gap-2">
            <button className="btn btn-primary" onClick={start} disabled={busy || running || mutators.length === 0}>Start run</button>
            <button className="btn" onClick={abort} disabled={busy || !running}>Abort</button>
          </div>
        </Panel>

        <div className="space-y-3 lg:col-span-2">
          <Panel title="Current run">
            {status.error && <ErrorNote onRetry={status.reload}>{status.error}</ErrorNote>}
            {!run ? (status.loading ? <Loading /> : <Empty>No run yet. Start one on the left, or run <span className="mono">bun run redteam</span>.</Empty>) : (
              <>
                <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1 text-[12px]">
                  <span className="mono font-medium">{run.id.slice(0, 12)}</span>
                  <span className={cn("rounded px-1.5 py-px text-[11px]", running ? "bg-ink text-white" : "bg-[#eceef1] text-mute")}>{run.status}</span>
                  <span className="text-mute">started {relTime(run.startedTs, now)}</span>
                  <span className="mono text-mute">policy {run.policyVersion}</span>
                </div>
                <div className="mt-2 h-2 w-full rounded-full bg-[#eceef1]" role="progressbar" aria-valuenow={attempts} aria-valuemin={0} aria-valuemax={max}>
                  <div className="h-full rounded-full bg-accent transition-[width]" style={{ width: `${Math.min(100, (attempts / Math.max(1, max)) * 100)}%` }} />
                </div>
                <div className="mt-1.5 flex flex-wrap gap-x-5 gap-y-1 text-[12px]">
                  <span><b>{attempts}</b> <span className="text-mute">of {max} attempts</span></span>
                  <span><b>{bypasses}</b> <span className="text-mute">bypasses</span></span>
                  <span><b>{fmtPct(attempts ? bypasses / attempts : null, 1)}</b> <span className="text-mute">bypass rate</span></span>
                  {running && live?.current && <span className="mono truncate text-mute">{live.current}</span>}
                </div>
              </>
            )}
          </Panel>

          <Panel title="Bypass rate per control" bodyClass="p-0">
            <ScrollX>
              <table className="tbl">
                <thead><tr><th>Control</th><th className="num">Attempts</th><th className="num">Bypasses</th><th className="num">Rate</th><th style={{ width: "34%" }} /></tr></thead>
                <tbody>
                  {(status.data?.byControl ?? []).map((c) => (
                    <tr key={c.controlId}>
                      <td className="mono">{c.controlId}</td><td className="num">{c.attempts}</td><td className="num">{c.bypasses}</td>
                      <td className="num">{fmtPct(c.bypassRate, 1)}</td>
                      <td><div className="h-1.5 w-full rounded-full bg-[#eceef1]"><div className="h-full rounded-full bg-ink" style={{ width: `${Math.min(100, (c.bypassRate ?? 0) * 100 * 4)}%` }} /></div></td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {(status.data?.byControl.length ?? 0) === 0 && <Empty>No attempts recorded.</Empty>}
            </ScrollX>
            <p className="border-t border-line px-3 py-1.5 text-[11px] text-mute">Bar length is the rate scaled 4x so small rates stay visible. A control with no attempts shows —.</p>
          </Panel>
        </div>
      </div>

      <div className="mt-3 grid grid-cols-1 gap-3 lg:grid-cols-3">
        <Panel className="lg:col-span-2" title="Recent results" bodyClass="p-0">
          {(status.data?.recent.length ?? 0) === 0 ? <Empty>No results yet.</Empty> : (
            <ScrollX className="max-h-[360px] overflow-y-auto">
              <table className="tbl">
                <thead><tr><th>Time</th><th>Control</th><th>Seed</th><th>Mutators</th><th>Decision</th><th>Rule</th><th>Bypass</th></tr></thead>
                <tbody>
                  {status.data!.recent.map((r) => (
                    <tr key={r.id}>
                      <td className="mono text-mute">{fmtTime(r.ts)}</td><td className="mono">{r.controlId}</td><td className="mono">{r.seedId}</td>
                      <td className="mono text-mute">{r.mutators.join(" + ")}</td>
                      <td><DecisionBadge decision={r.decision} /></td><td className="mono">{r.ruleId ?? "-"}</td>
                      <td>{r.bypass ? <b>bypass</b> : <span className="text-faint">held</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </ScrollX>
          )}
        </Panel>

        <div className="space-y-3">
          <Panel title={`Generated case files (${caseFiles.length})`} bodyClass="p-0">
            {caseFiles.length === 0 ? <Empty>No bypasses yet.</Empty> : (
              <ul className="mono max-h-[200px] divide-y divide-line overflow-auto text-[11px]">{caseFiles.map((p) => <li key={p} className="break-all px-3 py-1.5">{p}</li>)}</ul>
            )}
          </Panel>
          <Panel title="Re-run the suite">
            <p className="text-[12px] text-mute">Generated cases live under <span className="mono">tests/cases/generated/</span> and fail until a control or the policy is fixed. After a fix:</p>
            <pre className="mono mt-1.5 overflow-auto rounded border border-line bg-[#f7f8f9] p-2 text-[11px]">{`bun test\nbun run redteam --control prompt_injection --minutes 10`}</pre>
          </Panel>
        </div>
      </div>

      <Panel className="mt-3" title="Run history" bodyClass="p-0">
        {(runs.data?.length ?? 0) === 0 ? <Empty>No runs.</Empty> : (
          <ScrollX>
            <table className="tbl">
              <thead><tr><th>Run</th><th>Started</th><th>Status</th><th>Policy</th><th className="num">Attempts</th><th className="num">Bypasses</th><th className="num">Rate</th></tr></thead>
              <tbody>
                {runs.data!.map((r) => (
                  <tr key={r.id}><td className="mono">{r.id.slice(0, 12)}</td><td>{fmtDateTime(r.startedTs)}</td><td>{r.status}</td><td className="mono text-mute">{r.policyVersion}</td>
                    <td className="num">{r.attempts}</td><td className="num">{r.bypasses}</td><td className="num">{fmtPct(r.attempts ? r.bypasses / r.attempts : null, 1)}</td></tr>
                ))}
              </tbody>
            </table>
          </ScrollX>
        )}
      </Panel>
    </>
  );
}
