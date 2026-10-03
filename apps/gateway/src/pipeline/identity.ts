// Stage 1: bearer key → agent identity, session, scopes, model allowlist (SPEC §2.2 stage 1).
import { timingSafeEqual } from "node:crypto";
import type { AgentPolicy, Policy } from "@tollgate/policy";
import { globMatch } from "@tollgate/controls";
import { sha256 } from "@tollgate/policy/loader";

export interface AgentIdentity { agentId: string; agent: AgentPolicy }

export type AuthResult = { ok: true; id: AgentIdentity } | { ok: false; ruleId: "auth.missing_key" | "auth.unknown_key" };

const sameKey = (a: string, b: string) => {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};

export function authenticate(header: string | null | undefined, policy: Policy): AuthResult {
  const m = /^Bearer\s+(\S+)\s*$/i.exec(header ?? "");
  if (!m) return { ok: false, ruleId: "auth.missing_key" };
  let found: AgentIdentity | null = null;
  // Compare against every key so the time taken does not depend on which agent matched.
  for (const [agentId, agent] of Object.entries(policy.agents)) if (sameKey(m[1]!, agent.key)) found = { agentId, agent };
  return found ? { ok: true, id: found } : { ok: false, ruleId: "auth.unknown_key" };
}

export function sessionIdFor(header: string | null | undefined, agentId: string, firstSystem: string): string {
  const h = header?.trim();
  return h ? h.slice(0, 128) : sha256(`${agentId}:${firstSystem}`).slice(0, 16);
}

/** Registry host of a model name like "evil.example.net/ns/llama3.2:3b", or null for plain Ollama names. */
export function registryHost(model: string): string | null {
  const parts = model.split("/");
  if (parts.length >= 3) return parts[0]!;
  if (parts.length === 2 && /[.:]/.test(parts[0]!)) return parts[0]!;
  return null;
}

export function modelCheck(model: string, policy: Policy, agent: AgentPolicy): "models.not_allowed" | "models.denied_registry" | null {
  const host = registryHost(model);
  if (host && policy.models.deny_registries.some((p) => globMatch(p, host))) return "models.denied_registry";
  if (!policy.models.allow.some((p) => globMatch(p, model))) return "models.not_allowed";
  if (agent.models && !agent.models.some((p) => globMatch(p, model))) return "models.not_allowed";
  return null;
}
