// Mock POST /admin/playground. A small rule engine that follows the CURRENT mock policy (action per control,
// enforce vs monitor), so editing the policy in /policy changes what the playground does, like the real gateway.
import { SEVERITY, type DecisionRecord, type Hit } from "@tollgate/policy";
import type { ChatMessage, Decision, PlaygroundRequest, PlaygroundResponse } from "./contract";
import { isSessionKilled, makeRecord, mockPolicy, mulberry32, pushRecord, MOCK_CANARY_TOKEN, type Scn } from "./mock";

type Direction = "request" | "response" | "tool_call";
interface Detector {
  control: string; rule: string; owasp: string[]; tier: 0 | 1 | 2; test: (text: string) => { excerpt: string; details?: Record<string, unknown> } | null;
}

const rng = mulberry32(Date.now() & 0xffffffff);

const luhn = (digits: string) => {
  let sum = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = Number(digits[i]);
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d; alt = !alt;
  }
  return sum % 10 === 0;
};
const mask = (text: string, m: RegExpExecArray, label: string) => {
  const a = Math.max(0, m.index - 24), b = Math.min(text.length, m.index + m[0].length + 24);
  return `${a > 0 ? "…" : ""}${text.slice(a, m.index)}[${label}]${text.slice(m.index + m[0].length, b)}${b < text.length ? "…" : ""}`;
};
const re = (rx: RegExp, label: string) => (text: string) => { const m = rx.exec(text); return m ? { excerpt: mask(text, m, label) } : null; };

const INJECT = [
  /ignore (all |any )?(previous|prior|above) (instructions|rules|prompts)/i,
  /disregard (your|the) (system prompt|instructions)/i,
  /you are now (DAN|in developer mode|unrestricted)/i,
  /reveal (your|the) (system prompt|instructions|configuration)/i,
  /print (your|the) (system prompt|initial prompt)/i,
];

function b64Inner(text: string): { excerpt: string; details: Record<string, unknown> } | null {
  for (const m of text.matchAll(/[A-Za-z0-9+/]{24,}={0,2}/g)) {
    let dec = "";
    try { dec = atob(m[0]); } catch { continue; }
    if (!/^[\x20-\x7e\n\t]+$/.test(dec)) continue;
    const i = INJECT.findIndex((x) => x.test(dec));
    if (i >= 0) return { excerpt: `Decode this: [base64 → "${dec.slice(0, 40)}…"]`, details: { innerRuleId: `inject.heuristic.${i + 1}`, innerControlId: "prompt_injection", encoding: "base64", depth: 1 } };
  }
  return null;
}

const REQUEST_DETECTORS: Detector[] = [
  { control: "decode", rule: "decode.rescan", owasp: ["LLM01", "ASI01"], tier: 0, test: b64Inner },
  { control: "secrets", rule: "secrets.aws_access_key", owasp: ["LLM02"], tier: 0, test: re(/\bAKIA[0-9A-Z]{16}\b/, "REDACTED:aws_access_key") },
  { control: "pii", rule: "pii.iban", owasp: ["LLM02"], tier: 0, test: re(/\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b/, "REDACTED:iban") },
  { control: "pii", rule: "pii.email", owasp: ["LLM02"], tier: 0, test: re(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i, "REDACTED:email") },
  {
    control: "pii", rule: "pii.card", owasp: ["LLM02"], tier: 0,
    test: (t) => { for (const m of t.matchAll(/\b(?:\d[ -]?){13,19}\b/g)) { if (luhn(m[0].replace(/\D/g, ""))) return { excerpt: mask(t, m as RegExpExecArray, "REDACTED:card") }; } return null; },
  },
  { control: "signatures", rule: "sig.shadowray-cve-2023-48022", owasp: ["ASI02", "ASI05", "ASI03"], tier: 0, test: re(/:8265\/api\/(jobs|version|cluster_status)/i, "ray jobs api") },
  ...INJECT.map((rx, i): Detector => ({ control: "prompt_injection", rule: `inject.heuristic.${i + 1}`, owasp: ["LLM01", "ASI01"], tier: 0, test: re(rx, "matched phrase") })),
  { control: "content_safety", rule: "content_safety.S9", owasp: ["LLM01"], tier: 1, test: re(/pipe bomb|nerve agent|build a bomb/i, "unsafe request") },
  { control: "prompt_injection", rule: "inject.classifier", owasp: ["LLM01", "ASI01"], tier: 1, test: re(/jailbreak|\bDAN\b/i, "jailbreak marker") },
  { control: "prompt_injection", rule: "inject.judge", owasp: ["LLM01", "ASI01", "ASI10"], tier: 2, test: (t) => (t.includes("TG-MOCK-UNCERTAIN") && t.includes("TG-MOCK-JUDGE-BLOCK") ? { excerpt: "…TG-MOCK-UNCERTAIN … TG-MOCK-JUDGE-BLOCK…" } : null) },
];

function hostAllowed(host: string, allow: string[]): boolean {
  return allow.some((d) => host === d || host.endsWith(`.${d}`));
}

function applyRedactions(text: string, hits: { rule: string }[]): string {
  let out = text;
  if (hits.some((h) => h.rule === "pii.iban")) out = out.replace(/\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b/g, "[REDACTED:iban]");
  if (hits.some((h) => h.rule === "pii.email")) out = out.replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[REDACTED:email]");
  if (hits.some((h) => h.rule === "pii.card")) out = out.replace(/\b(?:\d[ -]?){13,19}\b/g, (m) => (luhn(m.replace(/\D/g, "")) ? "[REDACTED:card]" : m));
  return out;
}

const errorBody = (code: string, message: string, type = "tollgate_blocked") => ({ error: { type, code, message } });

export function mockPlayground(req: PlaygroundRequest): PlaygroundResponse & { record: DecisionRecord } {
  const pol = mockPolicy();
  const policy = pol.policy;
  const monitor = policy.mode === "monitor";
  const sessionId = req.session_id ?? `pg${Math.floor(rng() * 1e12).toString(16).padStart(14, "0")}`;
  const lastUser: ChatMessage | undefined = [...req.messages].reverse().find((m) => m.role === "user");
  const system = req.messages.find((m) => m.role === "system")?.content ?? "";
  const canary = req.plant_canary ? MOCK_CANARY_TOKEN : null;

  const finish = (s: Scn, body: unknown, hitsExtra?: Hit[]): PlaygroundResponse & { record: DecisionRecord } => {
    const record = makeRecord(rng, { ...s, sessionId, agent: req.agentId, model: req.model, ...(hitsExtra ? { hits: hitsExtra } : {}) });
    record.details = { ...record.details, ...(req.dry_run ? { dryRun: true } : {}), ...(s.details ?? {}) };
    pushRecord(record);
    return {
      status: record.httpStatus,
      headers: {
        decision: record.decision, rule: record.ruleId ?? "-", tier: record.tier === null ? "-" : String(record.tier), policy: record.policyVersion, event: record.id,
        latency: Object.entries(record.latencyMs).map(([k, v]) => `${k}=${v}`).join(";"),
      },
      body, record,
    };
  };
  const blockScn = (rule: string, control: string, owasp: string[], status: number, reach: Scn["reach"], decision: Decision = "block", extra: Partial<Scn> = {}): Scn =>
    ({ decision, ruleId: rule, controlId: control, tier: null, owasp, status: monitor ? 200 : status, reach, enforced: !monitor, ...extra });

  // --- stage 1: auth / session / model ---
  if (!(req.agentId in policy.agents)) return finish(blockScn("auth.unknown_key", "auth", ["ASI03"], 401, "auth"), errorBody("auth.unknown_key", "Unknown agent key", "unauthorized"));
  if (isSessionKilled(sessionId)) return finish(blockScn("session.killed", "auth", ["ASI03"], 403, "auth"), errorBody("session.killed", "Session was terminated"));
  const allowed = [...(policy.agents[req.agentId]?.models ?? policy.models.allow)];
  const okModel = allowed.some((g) => new RegExp(`^${g.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`, "i").test(req.model));
  if (!okModel) return finish(blockScn("models.not_allowed", "models", ["LLM03", "ASI04"], 403, "auth", "block", { excerpt: `model ${req.model} is not allowed for ${req.agentId}` }), errorBody("models.not_allowed", `Model ${req.model} is not on the allowlist`));

  // --- stage 2: budget (only the tiny-budget agent trips in mock mode) ---
  if (req.agentId === "test-small-budget" && req.messages.length > 6) {
    return finish(blockScn("budget.tokens_per_hour", "budget", ["LLM10", "ASI08"], 429, "budget", "block", { details: { retry_after_s: 1740 } }), errorBody("budget.tokens_per_hour", "Token budget exceeded", "budget_exceeded"));
  }

  // --- stage 3-5: request detectors ---
  const texts = req.messages.filter((m) => m.role !== "system").map((m) => m.content);
  if (req.tools?.length && JSON.stringify(req.tools).match(/<\s*important\s*>/i)) texts.push("<important>");
  const reqHits: { det: Detector; excerpt: string; details?: Record<string, unknown>; action: Decision }[] = [];
  for (const det of REQUEST_DETECTORS) {
    const ctl = (policy.controls as Record<string, { enabled: boolean; action: Decision } | undefined>)[det.control];
    if (!ctl?.enabled) continue;
    if (!policy.semantic.enabled && det.tier > 0) continue;
    for (const t of texts) {
      const r = det.test(t);
      if (r) { reqHits.push({ det, excerpt: r.excerpt, details: r.details, action: ctl.action }); break; }
    }
  }
  if (req.tools?.length && JSON.stringify(req.tools).match(/<\s*important\s*>/i) && policy.controls.signatures.enabled) {
    reqHits.push({ det: { control: "signatures", rule: "sig.mcp-tool-poisoning-2025", owasp: ["LLM01", "LLM03", "ASI01", "ASI02", "ASI04"], tier: 0, test: () => null }, excerpt: "tools[0].function.description contains <important>", action: policy.controls.signatures.action });
  }
  if (reqHits.length) {
    const top = [...reqHits].sort((a, b) => SEVERITY[b.action] - SEVERITY[a.action])[0]!;
    const hits: Hit[] = reqHits.map((h) => ({ controlId: h.det.control, ruleId: h.det.rule, action: h.action, owasp: h.det.owasp, excerptRedacted: h.excerpt, ...(h.details ? { details: h.details } : {}) }));
    const reach: Scn["reach"] = top.det.tier === 2 ? "tier2" : top.det.tier === 1 ? "tier1" : "tier0";
    if (top.action === "block" || top.action === "kill_session") {
      const details: Record<string, unknown> = { ...(top.details ?? {}) };
      if (top.det.tier >= 1) details.tier1 = { score: top.det.tier === 2 ? 0.5 : 1, categories: top.det.rule === "content_safety.S9" ? ["S9"] : [], raw: top.det.rule === "content_safety.S9" ? "unsafe\nS9" : "unsafe", model: "mock", ms: 20 };
      if (top.det.tier === 2) details.tier2 = { verdict: "block", confidence: 0.9, category: "prompt_injection", reason: "mock judge: marker TG-MOCK-JUDGE-BLOCK", model: "mock", ms: 50 };
      const scn: Scn = { decision: top.action, ruleId: top.det.rule, controlId: top.det.control, tier: top.det.tier, owasp: top.det.owasp, excerpt: top.excerpt, reach, status: monitor ? 200 : 403, enforced: !monitor, details, hits };
      if (monitor) return passThrough(scn);
      return finish(scn, errorBody(top.det.rule, "Request blocked by policy"), hits);
    }
    // redact-only: continue with redacted text
    const redacted = applyRedactions(lastUser?.content ?? "", reqHits.map((h) => ({ rule: h.det.rule })));
    return respond({ decision: "redact", ruleId: top.det.rule, controlId: top.det.control, tier: 0, owasp: top.det.owasp, excerpt: top.excerpt, reach: "output", status: 200, enforced: !monitor, hits }, redacted);
  }
  return respond({ decision: "allow", ruleId: null, controlId: null, tier: null, owasp: [], reach: "output", enforced: true, details: policy.semantic.enabled ? { tier1: { score: 0, categories: [], raw: "safe", model: "mock", ms: 20 } } : { semantic: "off" } }, lastUser?.content ?? "");

  // ---------------------------------------------------------------------------------------------
  function passThrough(scn: Scn) {
    return respond({ ...scn, reach: "output" }, lastUser?.content ?? "");
  }

  /** Stage 6 + 7: upstream (echo or a leaky small model) and the output path. */
  function respond(base: Scn, userText: string): PlaygroundResponse & { record: DecisionRecord } {
    const direction: Direction = "request";
    if (req.dry_run) {
      const rec = finish({ ...base, reach: base.reach === "output" ? "tier1" : base.reach, details: { ...(base.details ?? {}), dryRun: true } }, null);
      return { ...rec, body: { tollgate: { decision: rec.record.decision, ruleId: rec.record.ruleId, tier: rec.record.tier, latencyMs: rec.record.latencyMs }, dry_run: true } };
    }
    const leaks = canary && /system prompt|config|settings|secret|aws|token|instructions|reveal/i.test(userText);
    let content = req.echo?.content?.trim() ? req.echo.content : leaks ? `Sure, here is my configuration. AWS_KEY=${canary}; SUPPORT_TOKEN=tgc_Tm9ib2R5V2lsbEd1ZXNzVGhpcw` : `OK: ${userText}`;
    const outHits: { rule: string; control: string; owasp: string[]; action: Decision; excerpt: string; details?: Record<string, unknown> }[] = [];
    const ctl = policy.controls;

    if (ctl.canaries.enabled && canary && content.includes(canary)) {
      outHits.push({ rule: "canaries.in_output", control: "canaries", owasp: ["LLM02", "LLM07", "ASI06"], action: ctl.canaries.action, excerpt: content.replace(canary, "[REDACTED:canary]").slice(0, 120), details: { canary: { id: "cn_01", kind: "aws_key", label: "playground system prompt" }, planted_in: "playground" } });
    }
    if (ctl.secrets.enabled) {
      const m = /\bAKIA[0-9A-Z]{16}\b/.exec(content);
      if (m && m[0] !== canary) outHits.push({ rule: "secrets.aws_access_key", control: "secrets", owasp: ["LLM02"], action: ctl.secrets.action === "allow" ? "allow" : "redact", excerpt: mask(content, m, "REDACTED:aws_access_key") });
    }
    if (ctl.link_exfil.enabled) {
      for (const m of content.matchAll(/!\[[^\]]*\]\((https?:\/\/[^)\s]+)\)/g)) {
        let host = "";
        try { host = new URL(m[1]!).host; } catch { continue; }
        if (!hostAllowed(host, ctl.link_exfil.allow_domains) && ctl.link_exfil.block_images) {
          outHits.push({ rule: "link_exfil.image_untrusted", control: "link_exfil", owasp: ["LLM05", "LLM02", "ASI01"], action: ctl.link_exfil.action, excerpt: `…[REDACTED:link]…`, details: { url: `${m[1]!.slice(0, 40)}...`, host } });
          break;
        }
      }
    }
    if (ctl.sysprompt.enabled && system.length >= 40 && content.includes(system.slice(0, 40))) {
      outHits.push({ rule: "sysprompt.leak", control: "sysprompt", owasp: ["LLM07"], action: ctl.sysprompt.action, excerpt: "[REDACTED:system_prompt]", details: { overlap: 0.5, longestRun: 20 } });
    }

    const all: Hit[] = [...(base.hits ?? []), ...outHits.map((h) => ({ controlId: h.control, ruleId: h.rule, action: h.action, owasp: h.owasp, excerptRedacted: h.excerpt, ...(h.details ? { details: h.details } : {}) }))];
    if (outHits.length) {
      const top = [...outHits].sort((a, b) => SEVERITY[b.action] - SEVERITY[a.action])[0]!;
      const worse = SEVERITY[top.action] > SEVERITY[base.decision];
      if (worse) {
        const kill = top.action === "kill_session";
        const blocked = top.action === "block" || kill;
        const scn: Scn = {
          decision: top.action, ruleId: top.rule, controlId: top.control, tier: 0, owasp: top.owasp, direction: "response", excerpt: top.excerpt,
          reach: "output", status: blocked && !monitor ? 403 : 200, enforced: !monitor, hits: all, details: { ...(top.details ?? {}), ...(kill ? { killReason: "canary:cn_01" } : {}) },
        };
        if (blocked && !monitor) {
          return finish(scn, errorBody(top.rule, kill ? "Session terminated: canary secret leaked" : "Response blocked by policy"));
        }
        if (!monitor) {
          content = content.replace(/!\[[^\]]*\]\(https?:\/\/[^)\s]+\)/g, "[REDACTED:link]").replace(/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED:aws_access_key]");
          if (top.rule === "sysprompt.leak") content = content.replace(system.slice(0, 40), "[REDACTED:system_prompt]");
        }
        return finish(scn, completion(content, req.model));
      }
    }
    return finish({ ...base, direction, hits: all.length ? all : base.hits, enforced: base.enforced }, completion(content, req.model));
  }
}

function completion(content: string, model: string) {
  return {
    id: `chatcmpl-mock${Math.floor(rng() * 1e6)}`, object: "chat.completion", model,
    choices: [{ index: 0, message: { role: "assistant", content }, finish_reason: "stop" }],
    usage: { prompt_tokens: Math.ceil(content.length / 4) + 20, completion_tokens: Math.ceil(content.length / 4), total_tokens: Math.ceil(content.length / 2) + 20 },
  };
}
