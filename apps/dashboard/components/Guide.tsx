"use client";
// First-visit guide: dims the page, outlines one header link at a time and explains the page behind it.
// Targets are elements with data-guide="<id>" in the header. Opens once per browser (localStorage), and again from
// the "Guide" button in the header. Esc or "Skip guide" closes it; arrow keys step through.
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";

export interface GuideStep { id: string; title: string; text: string }

export const GUIDE_STEPS: GuideStep[] = [
  { id: "/", title: "Overview", text: "Posture score, requests and blocks in the last 5 minutes, spend per agent and latency per stage. Start here for the big picture." },
  { id: "/security", title: "Security", text: "Every decision the gateway made, filterable by agent, rule, tier and OWASP id. Open an event for redacted excerpts, export JSONL or CSV, or verify the audit chain." },
  { id: "/policy", title: "Policy", text: "The live policy.yaml: version history, a validating editor, the controls with their OWASP mapping and the attack signature feed. A saved edit applies to the next request." },
  { id: "/redteam", title: "Red team", text: "Run the fuzzer against the live policy. Shows progress, the bypass rate per control and the test case written for each bypass." },
  { id: "/coverage", title: "Coverage", text: "The OWASP LLM and agentic Top 10 matrix: which control covers each risk, whether it is on, its action and its bypass rate." },
  { id: "/approvals", title: "Approvals", text: "Tool calls waiting for a human. Approve or deny before the countdown ends; the number on the tab is how many are pending." },
  { id: "/playground", title: "Playground", text: "Send a message through the real pipeline as any agent and read the verdict stage by stage. The example attacks are here." },
  { id: "guide", title: "Guide", text: "Open this guide again any time from here." },
];

const STORAGE_KEY = "tg.guide.seen.v1";
const CARD_W = 320;
const GAP = 10;
const PAD = 4;

function seen(): boolean {
  try { return window.localStorage.getItem(STORAGE_KEY) === "1"; } catch { return true; } // storage blocked: never auto-open
}
function markSeen() {
  try { window.localStorage.setItem(STORAGE_KEY, "1"); } catch { /* storage blocked: the guide may open again next visit */ }
}

interface Box { top: number; left: number; width: number; height: number }

/** Where the card goes: below the target, centred on it, kept 16 px inside the viewport. */
export function placeCard(target: Box, viewportW: number, cardW = CARD_W): { top: number; left: number; width: number } {
  const width = Math.min(cardW, viewportW - 32);
  const centred = target.left + target.width / 2 - width / 2;
  return { top: target.top + target.height + GAP, left: Math.max(16, Math.min(centred, viewportW - width - 16)), width };
}

/** Guide state for the header: `open` starts at step 0; it also opens by itself on the first visit. */
export function useGuide() {
  const [step, setStep] = useState<number | null>(null);
  useEffect(() => {
    if (seen()) return;
    const t = setTimeout(() => setStep(0), 400); // after the first paint, so the header is laid out
    return () => clearTimeout(t);
  }, []);
  const open = useCallback(() => setStep(0), []);
  const close = useCallback(() => { markSeen(); setStep(null); }, []);
  return { step, setStep, open, close };
}

export function Guide({ step, setStep, close }: { step: number | null; setStep: (n: number) => void; close: () => void }) {
  // The measured target, tagged with its step id so a step whose target is missing never shows the previous outline.
  const [measured, setMeasured] = useState<{ id: string; box: Box } | null>(null);
  const [vw, setVw] = useState(0);
  const nextRef = useRef<HTMLButtonElement>(null);
  const cardRef = useRef<HTMLDivElement>(null);
  const current = step === null ? null : GUIDE_STEPS[step];

  // Measure the target; follow it when the page or the scrollable nav scrolls, or the window resizes.
  useLayoutEffect(() => {
    if (!current) return;
    const el = document.querySelector<HTMLElement>(`[data-guide="${current.id}"]`);
    if (!el) return;
    el.scrollIntoView({ block: "nearest", inline: "center" });
    const measure = () => {
      const r = el.getBoundingClientRect();
      setMeasured({ id: current.id, box: { top: r.top - PAD, left: r.left - PAD, width: r.width + PAD * 2, height: r.height + PAD * 2 } });
      setVw(window.innerWidth);
    };
    measure();
    window.addEventListener("resize", measure);
    document.addEventListener("scroll", measure, true);
    return () => { window.removeEventListener("resize", measure); document.removeEventListener("scroll", measure, true); };
  }, [current]);

  // Focus the main button of each step; give focus back to where it was when the guide closes.
  const opener = useRef<Element | null>(null);
  useEffect(() => {
    if (step === null) return;
    if (!opener.current) opener.current = document.activeElement;
    nextRef.current?.focus();
  }, [step]);
  useEffect(() => {
    if (step !== null) return;
    if (opener.current instanceof HTMLElement) opener.current.focus();
    opener.current = null;
  }, [step]);

  if (step === null || !current) return null;
  const last = step === GUIDE_STEPS.length - 1;
  const next = () => (last ? close() : setStep(step + 1));
  const back = () => step > 0 && setStep(step - 1);
  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") { e.preventDefault(); close(); }
    else if (e.key === "ArrowRight") { e.preventDefault(); next(); }
    else if (e.key === "ArrowLeft") { e.preventDefault(); back(); }
    else if (e.key === "Tab") {
      // Keep focus inside the card while it is open.
      const f = cardRef.current?.querySelectorAll<HTMLElement>("button");
      if (!f?.length) return;
      const first = f[0]!, end = f[f.length - 1]!;
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); end.focus(); }
      else if (!e.shiftKey && document.activeElement === end) { e.preventDefault(); first.focus(); }
    }
  };
  const box = measured?.id === current.id ? measured.box : null;
  const pos = box ? placeCard(box, vw || window.innerWidth) : null;

  return (
    <div className="fixed inset-0 z-[60]" onKeyDown={onKey}>
      {/* The dimmed page with a hole over the target; clicks on the page are held while the guide is open. */}
      {box ? (
        <div aria-hidden="true" className="pointer-events-none fixed rounded-md outline outline-2 outline-offset-0 outline-accent motion-safe:transition-all motion-safe:duration-150"
          style={{ top: box.top, left: box.left, width: box.width, height: box.height, boxShadow: "0 0 0 9999px rgba(27,30,35,0.45)" }} />
      ) : <div aria-hidden="true" className="fixed inset-0 bg-[rgba(27,30,35,0.45)]" />}
      <div ref={cardRef} role="dialog" aria-modal="true" aria-labelledby="tg-guide-title" aria-describedby="tg-guide-text"
        className="fixed rounded-md border border-line-strong bg-panel p-3 shadow-md motion-safe:transition-[top,left] motion-safe:duration-150"
        style={pos ? { top: pos.top, left: pos.left, width: pos.width } : { top: "30%", left: "50%", width: CARD_W, transform: "translateX(-50%)" }}>
        <div className="label mb-0.5 text-[11px] text-mute">{step + 1} of {GUIDE_STEPS.length}</div>
        <h2 id="tg-guide-title" className="text-[13px] font-semibold text-ink">{current.title}</h2>
        <p id="tg-guide-text" className="mt-1 text-[12px] leading-[1.45] text-ink">{current.text}</p>
        <div className="mt-3 flex items-center gap-2">
          <button type="button" className="text-[12px] text-mute underline-offset-2 hover:text-ink hover:underline" onClick={close}>Skip guide</button>
          <span className="flex-1" />
          {step > 0 && <button type="button" className="btn" onClick={back}>Back</button>}
          <button ref={nextRef} type="button" className="btn btn-primary" onClick={next}>{last ? "Done" : "Next"}</button>
        </div>
      </div>
    </div>
  );
}
