"use client";
// Hand-written SVG charts. No chart library. Colour is used only for decision series; everything else is grey or the accent.
import { fmtMs, fmtMsUnit } from "@/lib/format";
import type { StageLatency } from "@tollgate/policy";

export const DECISION_FILL = { allow: "#1d7a48", redact: "#c08a14", block: "#b3261e", kill_session: "#6a3fa3" } as const;
export const STAGE_FILL: Record<string, string> = {
  auth: "#c9cdd3", budget: "#aeb4bd", tier0: "#858d99", tier1: "#3f4fc4", tier2: "#8a95e0", upstream: "#3a4049", output: "#a4abb5",
};

const niceMax = (v: number) => {
  if (v <= 4) return 4;
  const p = 10 ** Math.floor(Math.log10(v));
  const n = v / p;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p;
};

export interface Bucket { label: string; segs: { key: keyof typeof DECISION_FILL; value: number }[] }

export function StackedBars({ data, height = 150 }: { data: Bucket[]; height?: number }) {
  const W = 640, padL = 28, padB = 18, padT = 6;
  const H = height;
  const totals = data.map((d) => d.segs.reduce((a, s) => a + s.value, 0));
  const max = niceMax(Math.max(1, ...totals));
  const plotH = H - padB - padT;
  const bw = (W - padL) / Math.max(1, data.length);
  const y = (v: number) => padT + plotH - (v / max) * plotH;
  const ticks = [0, max / 2, max];
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="block h-auto w-full" role="img" aria-label="Non-allow decisions per minute, stacked by decision">
      {ticks.map((t) => (
        <g key={t}>
          <line x1={padL} x2={W} y1={y(t)} y2={y(t)} stroke="#e1e4e8" strokeWidth={1} />
          <text x={padL - 4} y={y(t) + 3} textAnchor="end" fontSize={9} fill="#8d939c">{Math.round(t)}</text>
        </g>
      ))}
      {data.map((d, i) => {
        let acc = 0;
        return (
          <g key={i}>
            <title>{`${d.label}: ${totals[i]}`}</title>
            {d.segs.map((s) => {
              if (s.value <= 0) return null;
              const y0 = y(acc + s.value), h = y(acc) - y0;
              acc += s.value;
              return <rect key={s.key} x={padL + i * bw + 0.6} y={y0} width={Math.max(1, bw - 1.2)} height={h} fill={DECISION_FILL[s.key]} />;
            })}
          </g>
        );
      })}
      <text x={padL} y={H - 4} fontSize={9} fill="#8d939c">{data[0]?.label}</text>
      <text x={W} y={H - 4} fontSize={9} fill="#8d939c" textAnchor="end">{data[data.length - 1]?.label}</text>
    </svg>
  );
}

export function HBars({ rows, format = (n: number) => String(n) }: { rows: { label: string; value: number; sub?: string }[]; format?: (n: number) => string }) {
  const W = 480, labelW = 112, valueW = 70, rowH = 22;
  const max = Math.max(1e-9, ...rows.map((r) => r.value));
  const H = Math.max(rowH, rows.length * rowH);
  const barW = W - labelW - valueW;
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="block h-auto w-full" role="img">
      {rows.map((r, i) => (
        <g key={r.label} transform={`translate(0 ${i * rowH})`}>
          <text x={0} y={14} fontSize={11} fill="#1b1e23">{r.label.length > 17 ? `${r.label.slice(0, 16)}…` : r.label}</text>
          <rect x={labelW} y={5} width={barW} height={11} fill="#eceef1" rx={2} />
          <rect x={labelW} y={5} width={Math.max(1.5, (r.value / max) * barW)} height={11} fill="#3f4fc4" rx={2} />
          <text x={W} y={14} fontSize={11} fill="#1b1e23" textAnchor="end">{format(r.value)}</text>
        </g>
      ))}
    </svg>
  );
}

/** p50 and p95 per stage on a log scale (stages differ by four orders of magnitude). */
export function LatencyBars({ rows }: { rows: { stage: string; p50: number; p95: number }[] }) {
  const W = 480, labelW = 58, valueW = 96, rowH = 30;
  const f = (v: number) => Math.log10(1 + v * 10);
  const max = Math.max(1, ...rows.map((r) => f(r.p95)));
  const barW = W - labelW - valueW;
  const H = rows.length * rowH;
  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H}`} className="block h-auto w-full" role="img" aria-label="Latency p50 and p95 per stage, log scale">
        {rows.map((r, i) => (
          <g key={r.stage} transform={`translate(0 ${i * rowH})`}>
            <text x={0} y={16} fontSize={11} fill="#1b1e23">{r.stage}</text>
            <rect x={labelW} y={4} width={Math.max(1.5, (f(r.p50) / max) * barW)} height={9} fill="#3f4fc4" rx={2} />
            <rect x={labelW} y={15} width={Math.max(1.5, (f(r.p95) / max) * barW)} height={9} fill="#9aa3ae" rx={2} />
            <text x={W} y={12} fontSize={10} fill="#1b1e23" textAnchor="end">{fmtMs(r.p50)}</text>
            <text x={W} y={23} fontSize={10} fill="#646b75" textAnchor="end">{fmtMs(r.p95)}</text>
          </g>
        ))}
      </svg>
      <div className="mt-1 flex gap-3 text-[11px] text-mute">
        <span><i className="mr-1 inline-block h-2 w-3 rounded-sm bg-accent align-middle" />p50</span>
        <span><i className="mr-1 inline-block h-2 w-3 rounded-sm bg-[#9aa3ae] align-middle" />p95</span>
        <span>log scale, ms</span>
      </div>
    </div>
  );
}

/** One record's per-stage latency as a single stacked bar plus a legend row. */
export function StageBar({ latency }: { latency: StageLatency }) {
  const stages = ["auth", "budget", "tier0", "tier1", "tier2", "upstream", "output"] as const;
  const total = Math.max(1e-6, stages.reduce((a, s) => a + latency[s], 0));
  let x = 0;
  const W = 600;
  return (
    <div>
      <svg viewBox={`0 0 ${W} 16`} preserveAspectRatio="none" className="block h-4 w-full" role="img" aria-label="Latency by stage">
        <rect x={0} y={0} width={W} height={16} fill="#eceef1" rx={2} />
        {stages.map((s) => {
          const w = (latency[s] / total) * W;
          const el = w > 0 ? <rect key={s} x={x} y={0} width={Math.max(1.5, w)} height={16} fill={STAGE_FILL[s]}><title>{`${s}: ${fmtMsUnit(latency[s])}`}</title></rect> : null;
          x += w;
          return el;
        })}
      </svg>
      <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1 text-[11px]">
        {stages.map((s) => (
          <span key={s} className={latency[s] > 0 ? "text-ink" : "text-faint"}>
            <i className="mr-1 inline-block h-2 w-2 rounded-sm align-middle" style={{ background: STAGE_FILL[s] }} />
            {s} {fmtMs(latency[s])}
          </span>
        ))}
        <span className="font-medium">total {fmtMsUnit(latency.total)}</span>
      </div>
    </div>
  );
}

export function RatioBar({ ratio, warn = 0.8 }: { ratio: number; warn?: number }) {
  const r = Math.max(0, Math.min(1, ratio));
  return (
    <div className="h-1.5 w-full rounded-full bg-[#eceef1]" role="meter" aria-valuenow={Math.round(ratio * 100)} aria-valuemin={0} aria-valuemax={100}>
      <div className="h-full rounded-full" style={{ width: `${Math.max(1, r * 100)}%`, background: ratio >= warn ? "#1b1e23" : "#3f4fc4" }} />
    </div>
  );
}
