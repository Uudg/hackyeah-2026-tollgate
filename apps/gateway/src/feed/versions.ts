// version-range entries (SPEC §6.3): GET {OLLAMA_URL}/api/version at startup and on every feed/policy reload.
import { z } from "zod";
import { versionInRange } from "@tollgate/controls";
import type { Ctx, VersionMatch } from "../context.ts";

const VersionBody = z.object({ version: z.string() });

export async function checkVersions(ctx: Ctx): Promise<void> {
  let version: string;
  try {
    const res = await fetch(`${ctx.opts.ollamaUrl}/api/version`, { signal: AbortSignal.timeout(1500) });
    version = VersionBody.parse(await res.json()).version;
  } catch {
    ctx.state.ollamaVersion = null; // Ollama unreachable: nothing to compare, reported as unknown on /healthz
    return;
  }
  ctx.state.ollamaVersion = version;
  const matches: VersionMatch[] = [];
  for (const c of ctx.feed()?.compiled.entries ?? []) {
    const e = c.entry;
    if (e.type !== "version-range" || e.pattern.component !== "ollama") continue;
    if (versionInRange(version, e.pattern)) matches.push({ entryId: e.id, component: "ollama", version, cve: e.cve });
  }
  const before = new Set(ctx.state.versionMatches.map((m) => m.entryId));
  ctx.state.versionMatches = matches;
  for (const m of matches) if (!before.has(m.entryId)) ctx.bus.emit("feed.version_match", m);
}
