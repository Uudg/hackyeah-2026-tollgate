// Static copy of SPEC §10.2 (the gateway's /admin/coverage is the source of truth; this is the mock and the label source).
import type { CoverageRow } from "./contract";

export const CONTROL_LABELS: Record<string, string> = {
  prompt_injection: "Prompt injection (heuristics, classifier, judge)",
  decode: "Decode and rescan",
  unicode: "Invisible chars and homoglyphs",
  content_safety: "Content safety (Llama Guard)",
  pii: "PII redaction",
  secrets: "Secrets",
  models: "Model allowlist and registries",
  signatures: "Attack signature feed",
  link_exfil: "Link exfiltration",
  tool_calls: "Tool-call gating",
  sysprompt: "System-prompt leakage",
  canaries: "Canaries",
  auth: "Agent keys, scopes, session kill",
  budget: "Budgets, loop and circuit breakers",
};

type Static = Pick<CoverageRow, "controlId" | "tier" | "owasp">;
export const STATIC_COVERAGE: Static[] = [
  { controlId: "prompt_injection", tier: "0/1/2", owasp: ["LLM01", "ASI01", "ASI10"] },
  { controlId: "decode", tier: "0", owasp: ["LLM01", "ASI01", "ASI10"] },
  { controlId: "unicode", tier: "0", owasp: ["LLM01", "ASI01", "ASI10"] },
  { controlId: "content_safety", tier: "1", owasp: ["LLM01"] },
  { controlId: "pii", tier: "0", owasp: ["LLM02"] },
  { controlId: "secrets", tier: "0", owasp: ["LLM02"] },
  { controlId: "models", tier: "0", owasp: ["LLM03", "LLM04", "ASI04", "ASI05"] },
  { controlId: "signatures", tier: "0", owasp: ["LLM01", "LLM03", "LLM04", "ASI02", "ASI04", "ASI05"] },
  { controlId: "link_exfil", tier: "0 (output)", owasp: ["LLM02", "LLM05", "ASI01"] },
  { controlId: "tool_calls", tier: "0 (output)", owasp: ["LLM06", "ASI02", "ASI05"] },
  { controlId: "sysprompt", tier: "0 (output)", owasp: ["LLM07", "ASI06"] },
  { controlId: "canaries", tier: "0 (output)", owasp: ["LLM02", "LLM07", "ASI06"] },
  { controlId: "auth", tier: "0", owasp: ["ASI03", "ASI07"] },
  { controlId: "budget", tier: "0", owasp: ["LLM10", "ASI08"] },
];

export const NOT_COVERED = ["LLM08", "LLM09", "ASI09"];

/** Control ids shown in filters and the red-team form. */
export const CONTROL_IDS = STATIC_COVERAGE.map((c) => c.controlId);
