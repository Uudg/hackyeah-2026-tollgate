"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import { CanaryHead, useCanaryReaction } from "./Canary";
import { Guide, useGuide } from "./Guide";
import { LiveProvider, useLive } from "./Live";
import { ScrollX, cn } from "./ui";

const NAV = [
  { href: "/", label: "Overview" },
  { href: "/security", label: "Security" },
  { href: "/policy", label: "Policy" },
  { href: "/redteam", label: "Red team" },
  { href: "/coverage", label: "Coverage" },
  { href: "/approvals", label: "Approvals" },
  { href: "/playground", label: "Playground" },
];

function PolicyBadge() {
  const { policy, policyRejected, policyFlash } = useLive();
  if (!policy) return <span className="inline-flex h-6 items-center rounded border border-line-strong px-2 text-[11px] leading-none text-faint">policy …</span>;
  return (
    <Link
      href="/policy"
      key={policyFlash}
      title={policyRejected ? `Last edit rejected:\n${policyRejected.errors.slice(0, 4).join("\n")}` : `Loaded ${policy.loadedAt}`}
      className={cn(
        "mono relative before:absolute before:inset-x-0 before:-inset-y-2 before:content-[''] md:before:hidden inline-flex h-6 shrink-0 items-center gap-1 whitespace-nowrap rounded border px-2 text-[11px] leading-none",
        policyRejected ? "border-block/40 bg-block-bg text-block" : "border-line-strong bg-panel text-ink",
        policyFlash > 0 && !policyRejected && "flash",
      )}
    >
      <span>v{policy.version}</span><span className="text-faint">·</span><span>{policy.hash}</span><span className={cn("text-faint", policy.policy.mode !== "monitor" && "max-sm:hidden")}>·</span>
      <span className={cn(policy.policy.mode === "monitor" ? "font-semibold" : "max-sm:hidden")}>{policy.policy.mode}</span>
      {policyRejected && <span className="font-sans font-semibold">· edit rejected</span>}
    </Link>
  );
}

function ConnBadge() {
  const { conn, status } = useLive();
  if (conn.mode === "mock") {
    return (
      <span title={conn.reason ?? "mock data"} className="inline-flex h-6 shrink-0 items-center gap-1.5 whitespace-nowrap rounded border border-ink bg-ink px-2 text-[11px] font-medium leading-none text-white">
        <span className="h-1.5 w-1.5 rounded-full bg-white" />mock data
      </span>
    );
  }
  const label = status === "open" ? "live" : status === "connecting" ? "connecting" : "reconnecting";
  return (
    <span className="inline-flex h-6 shrink-0 items-center gap-1.5 whitespace-nowrap rounded border border-line-strong bg-panel px-2 text-[11px] leading-none text-ink" title={`event stream: ${status}`}>
      <span className={cn("h-1.5 w-1.5 rounded-full", status === "open" ? "bg-ink" : "bg-faint")} />{label}
    </span>
  );
}

function Toasts() {
  const { toasts, dismissToast } = useLive();
  return (
    <div className="pointer-events-none fixed inset-x-3 bottom-3 z-50 flex flex-col items-end gap-1.5 sm:inset-x-auto sm:right-4 sm:bottom-4 sm:gap-2" aria-live="polite">
      {toasts.map((t) => (
        <div key={t.id} role={t.kind === "error" ? "alert" : "status"}
          className={cn("slide-in pointer-events-auto w-full max-w-sm rounded-md border bg-panel py-1.5 pl-3 pr-1 text-[12px] shadow-md sm:w-[360px] sm:py-2",
            t.kind === "error" ? "border-block/40 border-l-[3px] border-l-block" : "border-line-strong border-l-[3px] border-l-accent")}>
          <div className="flex items-center justify-between gap-1">
            <div className={cn("min-w-0 truncate font-semibold sm:whitespace-normal", t.kind === "error" && "text-block")}>{t.title}</div>
            <button className="-my-1 flex h-10 w-10 shrink-0 items-center justify-center text-[18px] leading-none text-faint hover:text-ink sm:h-6 sm:w-6 sm:text-[15px]" aria-label="Dismiss" onClick={() => dismissToast(t.id)}>×</button>
          </div>
          {t.lines && t.lines.length > 0 && (
            <ul className={cn("mono mt-0.5 hidden space-y-0.5 pr-2 text-[11px] sm:block", t.kind === "error" ? "text-block" : "text-mute")}>
              {t.lines.filter(Boolean).map((l, i) => <li key={i} className="break-words">{l}</li>)}
            </ul>
          )}
          {t.href && <Link className="mt-1 hidden text-[11px] text-accent underline sm:inline-block" href={t.href} onClick={() => dismissToast(t.id)}>{t.hrefLabel ?? "Open"}</Link>}
        </div>
      ))}
    </div>
  );
}

/** Canary head + wordmark. The face mirrors the latest decision, then goes back to idle. */
function Logo() {
  const { decisions } = useLive();
  const latest = decisions[0];
  const state = useCanaryReaction(latest?.id, latest?.decision);
  return (
    <Link href="/" className="relative inline-flex items-center gap-1.5 text-[14px] font-semibold lowercase tracking-tight before:absolute before:-inset-x-1 before:-inset-y-2.5 before:content-[''] md:before:hidden">
      <CanaryHead state={state} className="h-5 w-auto shrink-0" />
      <span>tollgate</span>
    </Link>
  );
}

function TopBar() {
  const path = usePathname();
  const { pendingApprovals } = useLive();
  const active = (href: string) => (href === "/" ? path === "/" : path === href || path.startsWith(`${href}/`));
  const guide = useGuide();
  return (
    <>
    <header className="sticky top-0 z-40 border-b border-line-strong bg-panel">
      <div className="mx-auto flex max-w-[1440px] flex-wrap items-center gap-x-4 gap-y-0 px-4 py-1.5 max-md:pb-0">
        <Logo />
        <div className="order-3 -mx-4 w-[calc(100%+2rem)] md:order-none md:mx-0 md:w-auto">
        <ScrollX>
        <nav className="flex gap-0.5 px-3 md:px-0" aria-label="Primary">
          {NAV.map((n) => (
            <Link key={n.href} href={n.href} data-guide={n.href} aria-current={active(n.href) ? "page" : undefined}
              className={cn("inline-flex shrink-0 items-center rounded px-2.5 py-1 text-[12px] max-md:min-h-10 max-md:px-3.5 max-md:text-[13px]", active(n.href) ? "bg-accent-soft font-medium text-accent" : "text-mute hover:bg-[#f0f1f3] hover:text-ink")}>
              {n.label}
              {n.href === "/approvals" && pendingApprovals > 0 && (
                <span className="ml-1.5 rounded-full bg-ink px-1.5 text-[10px] font-medium text-white">{pendingApprovals}</span>
              )}
            </Link>
          ))}
        </nav>
        </ScrollX>
        </div>
        <div className="ml-auto flex items-center gap-2">
          <PolicyBadge /><ConnBadge />
          <button type="button" data-guide="guide" onClick={guide.open} aria-label="Open the guide" title="Open the guide"
            className="relative inline-flex h-6 shrink-0 items-center whitespace-nowrap rounded border border-line-strong bg-panel px-2 text-[11px] leading-none text-ink before:absolute before:-inset-x-1 before:-inset-y-2 before:content-[''] hover:bg-[#f0f1f3] md:before:hidden">
            <span className="sm:hidden">?</span><span className="max-sm:hidden">Guide</span>
          </button>
        </div>
      </div>
    </header>
    <Guide step={guide.step} setStep={guide.setStep} close={guide.close} />
    </>
  );
}

export default function Shell({ children }: { children: ReactNode }) {
  return (
    <LiveProvider>
      <TopBar />
      <main className="mx-auto w-full max-w-[1440px] flex-1 px-4 py-4">{children}</main>
      <Toasts />
    </LiveProvider>
  );
}
