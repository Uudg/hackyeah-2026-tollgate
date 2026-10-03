"use client";
import { Fragment, useEffect, useMemo, useState } from "react";
import type { Decision, ValidateResult } from "@/lib/contract";
import { api } from "@/lib/gateway";
import { STATIC_COVERAGE } from "@/lib/coverage";
import { errMsg, fmtDateTime, relTime } from "@/lib/format";
import { useAsync, useNow } from "@/lib/hooks";
import { useLive } from "./Live";
import { Chip, DecisionBadge, Empty, ErrorNote, JsonBlock, Loading, PageHeader, Panel, ScrollX, Tabs, cn } from "./ui";

type Save = { state: "idle" } | { state: "saving" } | { state: "queued" } | { state: "loaded"; text: string } | { state: "rejected"; errors: string[] } | { state: "error"; text: string };

function YamlView({ text }: { text: string }) {
  const lines = text.split("\n");
  return (
    <div className="rounded border border-line bg-[#f7f8f9]">
    <ScrollX className="mono max-h-[560px] overflow-y-auto text-[11.5px] leading-[1.55]" tone="page">
      <table className="w-full border-collapse">
        <tbody>
          {lines.map((l, i) => {
            const m = /^(\s*(?:- )?)([A-Za-z0-9_.\-"*:]+?:)(.*?)(\s+#.*)?$/.exec(l);
            const comment = /^\s*#/.test(l);
            return (
              <tr key={i}>
                <td className="select-none border-r border-line px-2 text-right text-faint" style={{ width: 1 }}>{i + 1}</td>
                <td className="whitespace-pre px-2">
                  {comment ? <span className="text-faint">{l}</span> : m ? <>{m[1]}<span className="font-semibold">{m[2]}</span>{m[3]}<span className="text-faint">{m[4]}</span></> : l}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </ScrollX>
    </div>
  );
}

const SKIP = new Set(["enabled", "action"]);
function options(c: Record<string, unknown>): string {
  return Object.entries(c).filter(([k]) => !SKIP.has(k)).map(([k, v]) => `${k}=${Array.isArray(v) ? `[${v.slice(0, 4).join(", ")}${v.length > 4 ? ", …" : ""}]` : String(v)}`).join("  ");
}

export default function PolicyView() {
  const { policy, hub, refreshPolicy } = useLive();
  const now = useNow(30000);
  const raw = useAsync(() => api.policyRaw(), []);
  const feed = useAsync(() => api.feed(), []);
  const cov = useAsync(() => api.coverage(), []);
  const [tab, setTab] = useState<"view" | "edit">("view");
  const [draft, setDraft] = useState("");
  const [dirty, setDirty] = useState(false);
  const [validation, setValidation] = useState<ValidateResult | null>(null);
  const [busy, setBusy] = useState<"validate" | "save" | null>(null);
  const [save, setSave] = useState<Save>({ state: "idle" });
  const [selected, setSelected] = useState<string | null>(null);
  const [openEntry, setOpenEntry] = useState<string | null>(null);

  const { reload: reloadRaw } = raw;
  const { reload: reloadFeed } = feed;

  // Keep the editor in sync with the file while the user has no unsaved edits.
  // eslint-disable-next-line react-hooks/set-state-in-effect
  useEffect(() => { if (!dirty) setDraft(raw.data ?? ""); }, [raw.data, dirty]);

  useEffect(() => {
    const offs = [
      hub.on("policy.loaded", (e) => { reloadRaw(); setSave((s) => (s.state === "queued" || s.state === "saving" ? { state: "loaded", text: `Loaded v${e.version} · ${e.hash}${e.changedPaths.length ? `, changed: ${e.changedPaths.slice(0, 4).join(", ")}` : ""}` } : s)); setDirty(false); }),
      hub.on("policy.rejected", (e) => setSave((s) => (s.state === "queued" || s.state === "saving" ? { state: "rejected", errors: e.errors } : s))),
      hub.on("feed.loaded", () => reloadFeed()),
    ];
    return () => offs.forEach((f) => f());
  }, [hub, reloadRaw, reloadFeed]);

  const history = useMemo(() => [...(policy?.history ?? [])].sort((a, b) => (a.loadedTs < b.loadedTs ? 1 : -1)), [policy]);
  useEffect(() => {
    const h = window.location.hash.slice(1);
    if (h && history.some((x) => x.hash === h)) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setSelected(h);
      setTimeout(() => document.getElementById(`ver-${h}`)?.scrollIntoView({ block: "center" }), 50);
    }
  }, [history]);

  async function validate() {
    setBusy("validate");
    try { setValidation(await api.validatePolicy(draft)); } catch (e) { setValidation({ ok: false, errors: [errMsg(e)] }); }
    setBusy(null);
  }
  async function doSave() {
    setBusy("save");
    setSave({ state: "saving" });
    try { await api.savePolicy(draft); setSave({ state: "queued" }); refreshPolicy(); } catch (e) { setSave({ state: "error", text: errMsg(e) }); }
    setBusy(null);
  }

  if (!policy) return <Loading what="Loading policy" />;
  const controls = Object.entries(policy.policy.controls) as [string, Record<string, unknown> & { enabled: boolean; action: Decision }][];
  // OWASP ids per control come from the gateway's coverage map; the static copy is only a stand-in until that answers.
  const coverage = new Map((cov.data?.controls ?? STATIC_COVERAGE).map((c) => [c.controlId, c]));
  const matches = feed.data?.versionMatches ?? [];

  return (
    <>
      <PageHeader title="Policy" sub={<>Current <span className="mono">v{policy.version} · {policy.hash} · {policy.policy.mode}</span>, loaded {relTime(policy.loadedAt, now)} from <span className="mono">{policy.path}</span>. File edits and saves here hot-reload without a restart.</>} />

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
        <Panel title="Version timeline" bodyClass="p-0" className="lg:col-span-1">
          <ol className="max-h-[560px] overflow-y-auto">
            {history.map((h, i) => {
              const open = selected === h.hash;
              return (
                <li key={h.hash} id={`ver-${h.hash}`} className={cn("border-b border-line", open && "bg-accent-soft")}>
                  <button className="flex w-full items-center justify-between gap-2 px-3 py-2 text-left" onClick={() => setSelected(open ? null : h.hash)} aria-expanded={open}>
                    <span>
                      <span className="mono text-[12px] font-medium">{h.declaredVersion !== null ? `v${h.declaredVersion}` : "v?"} · {h.hash}</span>
                      {h.hash === policy.hash && i === 0 && <span className="ml-2 rounded bg-ink px-1.5 py-px text-[10px] text-white">current</span>}
                      <span className="block text-[11px] text-mute">{fmtDateTime(h.loadedTs)} · {relTime(h.loadedTs, now)}</span>
                    </span>
                    <span className="text-[11px] text-mute">{h.changedPaths.length} {h.changedPaths.length === 1 ? "key" : "keys"}</span>
                  </button>
                  {open && (
                    <ul className="mono space-y-0.5 px-3 pb-2 text-[11px] text-mute">
                      {h.changedPaths.length ? h.changedPaths.map((p) => <li key={p}>{p}</li>) : <li>no changed keys recorded</li>}
                    </ul>
                  )}
                </li>
              );
            })}
            {history.length === 0 && <Empty>No history yet.</Empty>}
          </ol>
        </Panel>

        <Panel className="lg:col-span-2" title="policy.yaml" actions={<Tabs tabs={[{ id: "view", label: "Current" }, { id: "edit", label: "Edit" }]} value={tab} onChange={setTab} />}>
          {raw.error && <ErrorNote onRetry={raw.reload}>{raw.error}</ErrorNote>}
          {tab === "view" ? (raw.data !== undefined ? <YamlView text={raw.data} /> : <Loading />) : (
            <div>
              <label className="label" htmlFor="yaml-editor">Edit the YAML, then Validate (nothing is written) or Save (written to the policy file, then hot-reloaded)</label>
              <textarea id="yaml-editor" spellCheck={false} className="field mono h-[420px] w-full resize-y whitespace-pre text-[11.5px]" value={draft}
                onChange={(e) => { setDraft(e.target.value); setDirty(true); setValidation(null); }} />
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <button className="btn" onClick={validate} disabled={busy !== null}>{busy === "validate" ? "Validating…" : "Validate"}</button>
                <button className="btn btn-primary" onClick={doSave} disabled={busy !== null}>{busy === "save" ? "Saving…" : "Save"}</button>
                <button className="btn" onClick={() => { setDraft(raw.data ?? ""); setDirty(false); setValidation(null); setSave({ state: "idle" }); }} disabled={!dirty}>Revert</button>
                {dirty && <span className="text-[11px] text-mute">unsaved changes</span>}
              </div>
              {validation && (
                <div className={cn("mt-2 rounded border px-2.5 py-2 text-[12px]", validation.ok ? "border-line bg-[#f7f8f9]" : "border-block/40 bg-block-bg text-block")} role="status">
                  {validation.ok ? "Valid: the policy parses and passes the schema." : (
                    <>
                      <div className="font-semibold">{validation.errors.length} problem{validation.errors.length === 1 ? "" : "s"}</div>
                      <ul className="mono mt-1 space-y-0.5 text-[11px]">{validation.errors.map((e, i) => <li key={i}>{e}</li>)}</ul>
                    </>
                  )}
                </div>
              )}
              {save.state !== "idle" && (
                <div className={cn("mt-2 rounded border px-2.5 py-2 text-[12px]", save.state === "rejected" || save.state === "error" ? "border-block/40 bg-block-bg text-block" : "border-line bg-[#f7f8f9]")} role="status">
                  {save.state === "saving" && "Saving…"}
                  {save.state === "queued" && "Saved. Waiting for the gateway to reload it…"}
                  {save.state === "loaded" && save.text}
                  {save.state === "error" && save.text}
                  {save.state === "rejected" && <><div className="font-semibold">Rejected by the gateway, last good policy kept</div><ul className="mono mt-1 space-y-0.5 text-[11px]">{save.errors.map((e, i) => <li key={i}>{e}</li>)}</ul></>}
                </div>
              )}
            </div>
          )}
        </Panel>
      </div>

      <Panel className="mt-3" title="Controls" bodyClass="p-0">
        <ScrollX>
          <table className="tbl">
            <thead><tr><th>Control</th><th>Enabled</th><th>Action</th><th>Options</th><th>OWASP</th></tr></thead>
            <tbody>
              {controls.map(([id, c]) => (
                <tr key={id} className={cn(!c.enabled && "text-faint")}>
                  <td className="mono font-medium">{id}</td>
                  <td>{c.enabled ? "on" : "off"}</td>
                  <td><DecisionBadge decision={c.action} /></td>
                  <td className="mono max-w-[520px] truncate text-mute" title={options(c)}>{options(c)}</td>
                  <td><span className="flex gap-1">{(coverage.get(id)?.owasp ?? []).map((o) => <Chip key={o}>{o}</Chip>)}</span></td>
                </tr>
              ))}
              <tr>
                <td className="mono font-medium">semantic</td><td>{policy.policy.semantic.enabled ? "on" : "off"}</td><td className="text-faint">-</td>
                <td className="mono max-w-[520px] truncate text-mute">{`fail_mode=${policy.policy.semantic.fail_mode}  classifier=${policy.policy.semantic.classifier_model}  judge=${policy.policy.semantic.judge_model}  band=[${policy.policy.semantic.uncertain_band.join(", ")}]`}</td>
                <td><span className="flex gap-1"><Chip>LLM01</Chip></span></td>
              </tr>
            </tbody>
          </table>
        </ScrollX>
      </Panel>

      <Panel className="mt-3" title="Attack signature feed"
        actions={<button className="btn" onClick={async () => { try { await api.reloadFeed(); reloadFeed(); } catch { /* shown by the toast on feed.rejected; a transport error is shown below */ reloadFeed(); } }}>Reload feed</button>}
        bodyClass="p-0">
        {feed.error && <div className="p-3"><ErrorNote onRetry={feed.reload}>{feed.error}</ErrorNote></div>}
        {!feed.data ? (feed.loading ? <Loading /> : null) : (
          <>
            <div className="mono flex flex-wrap gap-x-4 gap-y-1 border-b border-line px-3 py-2 text-[11.5px] text-mute">
              <span>{feed.data.hash}</span><span>{feed.data.source}</span><span>loaded {relTime(feed.data.loadedAt, now)}</span>
              <span>{feed.data.entries.length} entries, {feed.data.entries.filter((e) => e.enabled).length} enabled</span>
            </div>
            {matches.length > 0 && (
              <div className="border-b border-line bg-[#f7f8f9] px-3 py-2 text-[12px]">
                <div className="font-semibold">Vulnerable component detected (posture score -15)</div>
                <ul className="mono mt-0.5 text-[11px]">{matches.map((m) => <li key={m.entryId}>{m.component} {m.version} matches {m.entryId}{m.cve ? ` (${m.cve})` : ""}</li>)}</ul>
              </div>
            )}
            <ScrollX className="max-h-[480px] overflow-y-auto">
              <table className="tbl">
                <thead><tr><th>Entry</th><th>Type</th><th>Scope</th><th>Severity</th><th>Action</th><th>Enabled</th><th>CVE</th></tr></thead>
                <tbody>
                  {feed.data.entries.map((e) => {
                    const open = openEntry === e.id;
                    return (
                      <Fragment key={e.id}>
                        <tr className={cn("cursor-pointer", !e.enabled && "text-faint")} onClick={() => setOpenEntry(open ? null : e.id)}>
                          <td className="max-w-[420px] truncate" title={e.title}><span className="mono">sig.{e.id}</span></td>
                          <td>{e.type}</td>
                          <td><span className="flex gap-1">{e.scope.map((s) => <Chip key={s}>{s}</Chip>)}</span></td>
                          <td className={e.severity === "critical" ? "font-semibold" : undefined}>{e.severity}</td>
                          <td>{e.action ? <DecisionBadge decision={e.action} /> : <span className="text-mute">policy default</span>}</td>
                          <td>{e.enabled ? "on" : "off"}</td>
                          <td className="mono">{e.cve ?? "-"}</td>
                        </tr>
                        {open && (
                          <tr><td colSpan={7} className="!whitespace-normal bg-[#f7f8f9]">
                            <div className="space-y-1.5 py-1">
                              <div className="font-medium">{e.title}</div>
                              {e.description && <p className="text-mute">{e.description}</p>}
                              <div className="flex flex-wrap gap-1">{e.owasp.map((o) => <Chip key={o}>{o}</Chip>)}</div>
                              <ul className="text-[11px]">{e.references.map((u) => <li key={u}><a className="text-accent underline break-all" href={u} target="_blank" rel="noreferrer">{u}</a></li>)}</ul>
                              <JsonBlock value={e.pattern} max={140} />
                            </div>
                          </td></tr>
                        )}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </ScrollX>
          </>
        )}
      </Panel>
    </>
  );
}
