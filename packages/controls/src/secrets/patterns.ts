// Known secret shapes (SPEC §7.1). Rule id secrets.<name>. Order matters: an earlier pattern claims its span.
export const SECRET_PATTERNS: Array<{ name: string; re: RegExp }> = [
  { name: "private_key", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----(?:[\s\S]*?-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----)?/g },
  { name: "aws_access_key", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { name: "aws_secret_key", re: /(?<=aws.{0,20}?(?:secret|key).{0,20}?)[A-Za-z0-9/+=]{40}\b/gi },
  { name: "github_token", re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/g },
  { name: "anthropic_key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
  { name: "openai_key", re: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}/g },
  { name: "google_api_key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: "slack_token", re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g },
  { name: "stripe_key", re: /\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b/g },
  { name: "jwt", re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
  { name: "bearer_header", re: /\b(?:Authorization:\s*)?Bearer\s+[A-Za-z0-9._~+/-]{20,}=*/gi },
  { name: "connection_string", re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@/]+:[^\s@]+@/gi },
];

/** policy.controls.secrets.patterns entries "name=regex" → rule id secrets.custom.<name>. */
export function customPatterns(patterns: readonly string[]): Array<{ name: string; re: RegExp }> {
  return patterns.map((p) => {
    const i = p.indexOf("=");
    return { name: `custom.${p.slice(0, i)}`, re: new RegExp(p.slice(i + 1), "g") };
  });
}
