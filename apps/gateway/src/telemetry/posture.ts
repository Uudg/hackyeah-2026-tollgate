// Posture score (SPEC §10.1), 0–100, with every term returned so the dashboard tile can explain itself.
import type { Ctx } from "../context.ts";

const CONTROLS = ["pii", "secrets", "unicode", "decode", "prompt_injection", "content_safety", "canaries", "link_exfil", "sysprompt", "tool_calls", "signatures"] as const;

export function posture(ctx: Ctx) {
  const p = ctx.policy().value;
  const enabled = CONTROLS.filter((c) => p.controls[c].enabled).length;
  const coverage = (enabled / CONTROLS.length) * 35;
  const mode = p.mode === "enforce" ? 15 : 5;
  const reachable = ctx.semantic.name === "mock" || ctx.state.classifierReachable === true;
  const semantic = p.semantic.enabled && ctx.semantic.name !== "off" ? (reachable ? 15 : 5) : 0;
  const refreshMs = (() => { const m = /^(\d+)(ms|s|m|h|d)$/.exec(p.controls.signatures.refresh); return Number(m?.[1] ?? 60) * ({ ms: 1, s: 1e3, m: 6e4, h: 3.6e6, d: 8.64e7 }[(m?.[2] ?? "s") as "s"]); })();
  const feedAge = ctx.state.feedLoadedAt === null ? null : Date.now() - ctx.state.feedLoadedAt;
  // A watched file is current by construction; only a polled URL can go stale.
  const fileFeed = !/^https?:/.test(ctx.feed()?.source ?? "");
  const feed = ctx.feed() ? (fileFeed || (feedAge !== null && feedAge < 2 * refreshMs) ? 10 : 5) : 0;
  const resilience = (1 - (ctx.state.latestBypassRate ?? 0)) * 15;
  const audit = ctx.state.lastVerify?.ok ? 10 : 0;
  const circuitOpen = ctx.circuit.states().some((s) => s.state === "open");
  const penalties = (ctx.state.versionMatches.length ? 15 : 0) + (circuitOpen ? 5 : 0) + (p.semantic.fail_mode === "open" && p.semantic.enabled && !reachable ? 5 : 0);
  const score = Math.max(0, Math.min(100, Math.round(coverage + mode + semantic + feed + resilience + audit - penalties)));
  const r = (n: number) => Math.round(n * 10) / 10;
  return { score, breakdown: { coverage: r(coverage), mode, semantic, feed, resilience: r(resilience), audit, penalties } };
}
