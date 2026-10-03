// schema v1 — rule id → OWASP mapping. The single place OWASP ids are assigned.
// LLM = OWASP Top 10 for LLM Applications 2025; ASI = OWASP Top 10 for Agentic Applications 2026.
import type { OwaspId } from "./schema/common.ts";

export const OWASP_NAMES: Record<OwaspId, string> = {
  LLM01: "Prompt Injection", LLM02: "Sensitive Information Disclosure", LLM03: "Supply Chain",
  LLM04: "Data and Model Poisoning", LLM05: "Improper Output Handling", LLM06: "Excessive Agency",
  LLM07: "System Prompt Leakage", LLM08: "Vector and Embedding Weaknesses", LLM09: "Misinformation",
  LLM10: "Unbounded Consumption",
  ASI01: "Agent Goal Hijack", ASI02: "Tool Misuse and Exploitation", ASI03: "Identity and Privilege Abuse",
  ASI04: "Agentic Supply Chain Vulnerabilities", ASI05: "Unexpected Code Execution", ASI06: "Memory and Context Poisoning",
  ASI07: "Insecure Inter-Agent Communication", ASI08: "Cascading Failures", ASI09: "Human-Agent Trust Exploitation",
  ASI10: "Rogue Agents",
};

export const NOT_COVERED: OwaspId[] = ["LLM08", "LLM09", "ASI09"];

/** Every rule id the gateway can emit, except feed.<id> (OWASP comes from the feed entry). */
export const RULE_OWASP = {
  "auth.unknown_key": ["ASI03"],
  "auth.scope": ["ASI03"],
  "agent.locked": ["ASI03", "ASI10"],
  "model.not_allowed": ["LLM03", "ASI04"],
  "model.registry_denied": ["LLM03", "ASI04"],
  "pii.email": ["LLM02"], "pii.phone": ["LLM02"], "pii.iban": ["LLM02"],
  "pii.card": ["LLM02"], "pii.pesel": ["LLM02"], "pii.ssn": ["LLM02"],
  "secrets.aws_key": ["LLM02"], "secrets.gcp_key": ["LLM02"], "secrets.github_token": ["LLM02"],
  "secrets.slack_token": ["LLM02"], "secrets.openai_key": ["LLM02"], "secrets.private_key": ["LLM02"],
  "secrets.high_entropy": ["LLM02"],
  "unicode.invisible": ["LLM01"], "unicode.bidi": ["LLM01"], "unicode.homoglyph": ["LLM01"],
  "decode.rescan": ["LLM01"],
  "injection.soft": ["LLM01", "ASI01"],
  "tool.schema": ["LLM05", "LLM06", "ASI02"],
  "tool.allowlist": ["LLM06", "ASI02"],
  "tool.approval": ["LLM06", "ASI02"],
  "tool.internal_host": ["LLM06", "ASI02", "ASI05"],
  "tool.depth": ["LLM10", "ASI08"],
  "budget.tokens_per_hour": ["LLM10"], "budget.usd_per_day": ["LLM10"],
  "budget.compute_seconds_per_hour": ["LLM10"], "budget.loop": ["LLM10", "ASI08"],
  "upstream.circuit_open": ["LLM10", "ASI08"],
  "content_safety": ["LLM01"],
  "jailbreak.guardian": ["LLM01", "ASI01"],
  "judge.misaligned": ["LLM01", "ASI01", "ASI10"],
  "judge.injection": ["LLM01", "ASI01"],
  "semantic.timeout": [], "semantic.error": [],
  "output.pii": ["LLM02", "LLM05"], "output.secrets": ["LLM02", "LLM05"],
  "output.link_exfil": ["LLM05", "LLM02", "ASI01"],
  "output.system_prompt_leak": ["LLM07"],
  "output.tool_call": ["LLM05", "LLM06", "ASI02"],
  "canary.leak": ["LLM02", "LLM07", "ASI06"],
} as const satisfies Record<string, readonly OwaspId[]>;

export type KnownRuleId = keyof typeof RULE_OWASP;

/** Exact match first, then the longest dotted prefix ("content_safety.S9" → "content_safety"). */
export function owaspFor(ruleId: string): OwaspId[] {
  const table = RULE_OWASP as Record<string, readonly OwaspId[]>;
  for (let id = ruleId; id; id = id.includes(".") ? id.slice(0, id.lastIndexOf(".")) : "") {
    const hit = table[id];
    if (hit) return [...hit];
  }
  return [];
}
