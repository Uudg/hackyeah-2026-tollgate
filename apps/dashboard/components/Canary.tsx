"use client";
// The canary from design/mascot: a bird on the toll gate that acts out the latest decision. Decorative only.
// States are classes on the root (is-idle | is-allow | is-redact | is-block | is-kill); the CSS is in globals.css.
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import type { Decision } from "@/lib/contract";
import { cn } from "./ui";

export type CanaryState = "idle" | "allow" | "redact" | "block" | "kill";

export function canaryState(decision: Decision): CanaryState {
  return decision === "kill_session" ? "kill" : decision;
}

/**
 * Reacts to a new decision (a new `key`), then goes back to idle after 1.5 s. Passes through idle for two frames
 * first, so the same decision twice in a row still replays its animation.
 */
export function useCanaryReaction(key: string | null | undefined, decision: Decision | null | undefined): CanaryState {
  const [state, setState] = useState<CanaryState>("idle");
  useEffect(() => {
    if (!key || !decision) return;
    let raf = 0;
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setState("idle");
    raf = requestAnimationFrame(() => { raf = requestAnimationFrame(() => setState(canaryState(decision))); });
    const t = setTimeout(() => setState("idle"), 1500);
    return () => { cancelAnimationFrame(raf); clearTimeout(t); };
  }, [key, decision]);
  return state;
}

/** Coming back from kill, the bird is put back on the post with no animation for one frame (design/mascot/README.md). */
function useNoAnimAfterKill(state: CanaryState) {
  const ref = useRef<SVGSVGElement>(null);
  const prev = useRef<CanaryState>(state);
  useLayoutEffect(() => {
    const el = ref.current;
    const wasKill = prev.current === "kill" && state !== "kill";
    prev.current = state;
    if (!el || !wasKill) return;
    el.classList.add("no-anim");
    // Flush styles now, so the jump back happens with transitions off; remove the class after the next painted frame.
    void el.getBoundingClientRect();
    let raf = requestAnimationFrame(() => { raf = requestAnimationFrame(() => el.classList.remove("no-anim")); });
    return () => { cancelAnimationFrame(raf); el.classList.remove("no-anim"); };
  }, [state]);
  return ref;
}

export function Canary({ state, className }: { state: CanaryState; className?: string }) {
  const ref = useNoAnimAfterKill(state);
  return (
    <svg ref={ref} className={cn("tg-canary", `is-${state}`, className)} viewBox="-24 0 144 120" aria-hidden="true" focusable="false">
      <g className="arm">
        <rect x="34" y="79" width="80" height="10" rx="5" fill="var(--ink)" />
        <g fill="var(--panel)"><polygon points="58,79 64,79 60,89 54,89" /><polygon points="78,79 84,79 80,89 74,89" /><polygon points="98,79 104,79 100,89 94,89" /></g>
      </g>
      <rect x="24" y="63" width="14" height="51" rx="4" fill="var(--ink)" />
      <g className="bird">
        <BirdBody />
        <Face />
      </g>
    </svg>
  );
}

/** The head only (design/logo/canary-head.svg) for the header: the face changes with the decision, nothing moves. */
export function CanaryHead({ state, className }: { state: CanaryState; className?: string }) {
  return (
    <svg className={cn("tg-head", `is-${state}`, className)} viewBox="6 29 50 37" aria-hidden="true" focusable="false">
      <BirdBody />
      <Face />
    </svg>
  );
}

function BirdBody() {
  return (
    <>
      <polygon points="17,52 8,47 9,57" fill="var(--canary-shade)" />
      <rect x="16" y="31" width="30" height="33" rx="10" fill="var(--canary)" />
      <path d="M16 44 H28 A5 5 0 0 1 28 54 H16 Z" fill="var(--canary-shade)" />
      <polygon points="46,41 53.5,44.5 46,48" fill="var(--canary-beak)" />
    </>
  );
}

function Face() {
  return (
    <>
      <circle className="e-open" cx="38.5" cy="41" r="2.4" fill="var(--ink)" />
      <path className="e-happy" d="M35.9 42 q2.6 -3.4 5.2 0" stroke="var(--ink)" strokeWidth="1.8" fill="none" strokeLinecap="round" />
      <g className="e-x" stroke="var(--ink)" strokeWidth="1.7" strokeLinecap="round"><line x1="36.3" y1="38.8" x2="40.7" y2="43.2" /><line x1="40.7" y1="38.8" x2="36.3" y2="43.2" /></g>
      <line className="brow" x1="34.5" y1="35.4" x2="42" y2="37.4" stroke="var(--ink)" strokeWidth="2" strokeLinecap="round" />
      <rect className="bar" x="29" y="37.5" width="17" height="7" fill="var(--ink)" />
    </>
  );
}
