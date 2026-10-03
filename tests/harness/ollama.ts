// Probes Ollama once (1 s timeout) and caches the model list (SPEC §11.2).
let cached: Promise<string[] | null> | null = null;

export function ollamaModels(url = "http://127.0.0.1:11434"): Promise<string[] | null> {
  cached ??= (async () => {
    try {
      const res = await fetch(`${url}/api/tags`, { signal: AbortSignal.timeout(1000) });
      const body = (await res.json()) as { models?: Array<{ name: string }> };
      return (body.models ?? []).map((m) => m.name);
    } catch {
      return null; // Ollama is not running: model-backed cases skip
    }
  })();
  return cached;
}

/** Missing models among `requires`, or the whole list when Ollama is down. */
export async function missingModels(requires: string[]): Promise<string[]> {
  const have = await ollamaModels();
  if (have === null) return requires.length ? requires : ["ollama"];
  return requires.filter((m) => !have.includes(m) && !have.includes(`${m}:latest`));
}

export const skipMessage = (models: string[]) => {
  const m = models.join(", ");
  return `SKIP (model-backed): needs Ollama at :11434 with ${m} — run \`ollama serve\` and \`ollama pull ${models[0] ?? m}\``;
};
