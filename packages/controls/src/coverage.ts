// Coverage map (SPEC §10.2): which control covers which OWASP LLM / Agentic id. Also rendered in the README.
export interface CoverageRow { controlId: string; parts: string; tier: string; owasp: string[]; policyKey: string | null }

export const COVERAGE: CoverageRow[] = [
  { controlId: "prompt_injection", parts: "heuristics, classifier, judge", tier: "0/1/2", owasp: ["LLM01", "ASI01", "ASI10"], policyKey: "controls.prompt_injection" },
  { controlId: "decode", parts: "decode-and-rescan", tier: "0", owasp: ["LLM01", "ASI01"], policyKey: "controls.decode" },
  { controlId: "unicode", parts: "invisible characters, homoglyphs", tier: "0", owasp: ["LLM01"], policyKey: "controls.unicode" },
  { controlId: "content_safety", parts: "Llama Guard categories", tier: "1", owasp: ["LLM01"], policyKey: "controls.content_safety" },
  { controlId: "pii", parts: "email, phone, IBAN, card, PESEL, IP", tier: "0", owasp: ["LLM02"], policyKey: "controls.pii" },
  { controlId: "secrets", parts: "key shapes, entropy, custom patterns", tier: "0", owasp: ["LLM02"], policyKey: "controls.secrets" },
  { controlId: "models", parts: "allowlist, registry deny", tier: "0", owasp: ["LLM03", "ASI04"], policyKey: null },
  { controlId: "signatures", parts: "regex, url-pattern, pickle, tool-description, version-range", tier: "0", owasp: ["LLM03", "LLM04", "LLM05", "ASI02", "ASI04", "ASI05"], policyKey: "controls.signatures" },
  { controlId: "link_exfil", parts: "markdown images, data-bearing links, data URIs", tier: "0 (output)", owasp: ["LLM05", "LLM02", "ASI01"], policyKey: "controls.link_exfil" },
  { controlId: "tool_calls", parts: "schema, allow/deny, approval queue", tier: "0 (output)", owasp: ["LLM06", "ASI02", "ASI05"], policyKey: "controls.tool_calls" },
  { controlId: "sysprompt", parts: "n-gram overlap", tier: "0 (output)", owasp: ["LLM07"], policyKey: "controls.sysprompt" },
  { controlId: "canaries", parts: "planted fake secrets", tier: "0", owasp: ["LLM02", "LLM07", "ASI06"], policyKey: "controls.canaries" },
  { controlId: "auth", parts: "per-agent keys, scopes, session kill, memory namespaces", tier: "0", owasp: ["ASI03", "ASI07"], policyKey: null },
  { controlId: "budget", parts: "tokens, USD, compute, loop breaker, circuit breaker, tool depth", tier: "0", owasp: ["LLM10", "ASI08"], policyKey: null },
];

export const NOT_COVERED = ["LLM08", "LLM09", "ASI09"] as const;
