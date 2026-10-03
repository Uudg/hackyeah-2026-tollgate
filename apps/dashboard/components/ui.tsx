"use client";
import { useEffect, useRef, useState, type ReactNode } from "react";
import type { Decision } from "@/lib/contract";

export const cn = (...xs: (string | false | null | undefined)[]) => xs.filter(Boolean).join(" ");

const DECISION_STYLE: Record<Decision, string> = {
  allow: "bg-allow-bg text-allow border-allow/30",
  redact: "bg-redact-bg text-redact border-redact/30",
  block: "bg-block-bg text-block border-block/30",
  kill_session: "bg-kill-bg text-kill border-kill/30",
};

/** The only coloured element in the console. In monitor mode the badge reads "would block" with a dashed border. */
export function DecisionBadge({ decision, enforced = true }: { decision: Decision; enforced?: boolean }) {
  const would = !enforced && decision !== "allow";
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-[3px] border px-1.5 py-px text-[11px] font-medium leading-4",
        DECISION_STYLE[decision],
        would && "border-dashed bg-transparent",
      )}
      title={would ? "Monitor mode: recorded, not enforced" : undefined}
    >
      {would ? `would ${decision === "kill_session" ? "kill" : decision}` : decision === "kill_session" ? "kill session" : decision}
    </span>
  );
}

/**
 * Horizontal scroller with a fade and an arrow on every edge that has more content, so a clipped table is visibly scrollable.
 * `className` goes to the scrolling element (for example a max height).
 */
export function ScrollX({ children, className, tone = "panel" }: { children: ReactNode; className?: string; tone?: "panel" | "page" }) {
  const ref = useRef<HTMLDivElement>(null);
  const [edge, setEdge] = useState({ l: false, r: false });
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const update = () => setEdge({ l: el.scrollLeft > 4, r: el.scrollLeft + el.clientWidth < el.scrollWidth - 4 });
    el.addEventListener("scroll", update, { passive: true });
    // ResizeObserver reports once when it starts observing, so the first measurement needs no direct call.
    const ro = new ResizeObserver(update);
    ro.observe(el);
    for (const child of Array.from(el.children)) ro.observe(child);
    return () => { el.removeEventListener("scroll", update); ro.disconnect(); };
  }, []);
  const from = tone === "panel" ? "from-panel via-panel/80" : "from-[#f4f5f6] via-[#f4f5f6]/80";
  return (
    <div className="relative min-w-0">
      <div ref={ref} className={cn("scroll-x", className)}>{children}</div>
      {edge.l && <span aria-hidden className={cn("pointer-events-none absolute inset-y-0 left-0 flex w-8 items-center bg-gradient-to-r to-transparent pl-1 text-[16px] leading-none text-mute", from)}>‹</span>}
      {edge.r && <span aria-hidden className={cn("pointer-events-none absolute inset-y-0 right-0 flex w-8 items-center justify-end bg-gradient-to-l to-transparent pr-1 text-[16px] leading-none text-mute", from)}>›</span>}
    </div>
  );
}

export function Chip({ children, title }: { children: ReactNode; title?: string }) {
  return <span title={title} className="inline-block rounded-[3px] bg-[#eceef1] px-1.5 py-px text-[11px] leading-4 text-mute">{children}</span>;
}

export function Panel({ title, actions, children, className, bodyClass, id }: {
  title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; bodyClass?: string; id?: string;
}) {
  return (
    <section id={id} className={cn("min-w-0 rounded-md border border-line bg-panel", className)}>
      {(title || actions) && (
        <header className="flex min-h-9 flex-wrap items-center justify-between gap-2 border-b border-line px-3 py-1.5">
          <h2 className="text-[12px] font-semibold text-ink">{title}</h2>
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={cn("p-3", bodyClass)}>{children}</div>
    </section>
  );
}

export function PageHeader({ title, sub, actions }: { title: string; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-3 flex flex-wrap items-end justify-between gap-2">
      <div>
        <h1 className="text-[16px] font-semibold tracking-tight">{title}</h1>
        {sub && <p className="mt-0.5 text-[12px] text-mute">{sub}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Tile({ label, value, sub, title, children }: { label: string; value: ReactNode; sub?: ReactNode; title?: string; children?: ReactNode }) {
  return (
    <div className="group relative rounded-md border border-line bg-panel px-3 py-2.5" title={title} tabIndex={children ? 0 : undefined}>
      <div className="text-[11px] text-mute">{label}</div>
      <div className="mt-0.5 text-[22px] font-semibold leading-7 tracking-tight">{value}</div>
      {sub && <div className="mt-0.5 text-[11px] text-mute">{sub}</div>}
      {children && (
        <div className="invisible absolute left-0 top-full z-20 mt-1 w-64 rounded-md border border-line-strong bg-panel p-2.5 text-[11px] opacity-0 shadow-sm transition-opacity group-hover:visible group-hover:opacity-100 group-focus:visible group-focus:opacity-100">
          {children}
        </div>
      )}
    </div>
  );
}

export function Toggle({ checked, onChange, label, hint, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; hint?: string; disabled?: boolean }) {
  return (
    <label className={cn("flex cursor-pointer items-start gap-2 py-1 text-[12px] max-md:min-h-10 max-md:items-center", disabled && "cursor-not-allowed opacity-50")} title={hint}>
      <input type="checkbox" className="mt-0.5 h-3.5 w-3.5 shrink-0 accent-[var(--accent)] max-md:mt-0 max-md:h-5 max-md:w-5" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <span>{label}{hint && <span className="block text-[11px] text-mute">{hint}</span>}</span>
    </label>
  );
}

export function Loading({ what = "Loading" }: { what?: string }) {
  return <div className="px-3 py-6 text-center text-[12px] text-mute">{what}…</div>;
}
export function Empty({ children }: { children: ReactNode }) {
  return <div className="px-3 py-6 text-center text-[12px] text-mute">{children}</div>;
}
export function ErrorNote({ children, onRetry }: { children: ReactNode; onRetry?: () => void }) {
  return (
    <div className="flex items-start justify-between gap-3 rounded-md border border-block/30 bg-block-bg px-3 py-2 text-[12px] text-block">
      <span className="min-w-0 break-words">{children}</span>
      {onRetry && <button className="btn shrink-0" onClick={onRetry}>Retry</button>}
    </div>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: string }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div role="tablist" className="flex gap-0.5 rounded-md border border-line-strong bg-[#eceef1] p-0.5">
      {tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={value === t.id} onClick={() => onChange(t.id)}
          className={cn("rounded px-2.5 py-0.5 text-[12px] max-md:min-h-10 max-md:px-4", value === t.id ? "bg-panel font-medium text-ink shadow-[0_0_0_1px_var(--line)]" : "text-mute hover:text-ink")}>
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function KV({ k, children, mono }: { k: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="grid grid-cols-[110px_1fr] gap-2 py-0.5 text-[12px]">
      <dt className="text-mute">{k}</dt>
      <dd className={cn("min-w-0 break-words", mono && "mono")}>{children}</dd>
    </div>
  );
}

export function JsonBlock({ value, max = 280 }: { value: unknown; max?: number }) {
  return (
    <pre className="mono overflow-auto rounded border border-line bg-[#f7f8f9] p-2 text-[11px] leading-[1.5]" style={{ maxHeight: max }}>
      {typeof value === "string" ? value : JSON.stringify(value, null, 2)}
    </pre>
  );
}
