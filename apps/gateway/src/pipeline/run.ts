// The orchestrator for POST /v1/chat/completions (SPEC §2.2). Stages run in this order:
// parse → identity → budget pre-check → tier 0 → tier 1 → tier 2 → upstream → output → budget commit → record.
// The policy snapshot is captured once so a hot reload mid-request cannot mix versions.
import { limitsFor, parseDuration, SEVERITY, type DecisionRecord, type Direction, type Hit, type Policy, type StageLatency, type Tier } from "@tollgate/policy";
import { decodeVariants, normalize, type ScanEnv } from "@tollgate/controls";
import type { Ctx } from "../context.ts";
import { newId } from "../ids.ts";
import { ChatRequestSchema, estimateTokens, messageText, type ChatCompletion, type ChatMessage } from "../openai.ts";
import { costUsd, priceFor } from "../pricing.ts";
import { requestHash } from "../budget/loop.ts";
import { authenticate, modelCheck, sessionIdFor } from "./identity.ts";
import { runTier0 } from "./tier0.ts";
import { runSemantic, semanticSkipped } from "./semantic.ts";
import { runOutput } from "./output.ts";
import { decide, persist, tollgateHeaders, type Entry } from "./record.ts";
import { log } from "../log.ts";

export interface ChatRequestIn {
  body: unknown;
  header(name: string): string | null | undefined;
}

export interface ChatResponseOut {
  status: number;
  headers: Record<string, string>;
  /** JSON body, or a ready SSE stream for stream: true. */
  body: unknown;
  stream?: ReadableStream<Uint8Array>;
  record: DecisionRecord | null;
}

const BUDGET_OWASP = ["LLM10", "ASI08"];

export async function runChat(ctx: Ctx, req: ChatRequestIn): Promise<ChatResponseOut> {
  const t0 = performance.now();
  const snap = ctx.policy();
  const policy = snap.value;
  const feedSnap = ctx.feed();
  const id = newId();
  const lat: StageLatency = { auth: 0, budget: 0, tier0: 0, tier1: 0, tier2: 0, upstream: 0, output: 0, total: 0 };
  const entries: Entry[] = [];
  const details: Record<string, unknown> = { policyDeclaredVersion: policy.version };
  const enforceMode = policy.mode === "enforce";
  let agentId = "anonymous";
  let sessionId = "anonymous";
  let tokensIn = 0, tokensOut = 0, cost = 0, computeMs = 0;
  let enforced = enforceMode;

  // The model name is known before the body is validated, so a 401 for a bad key can still be recorded.
  const rawModel = (req.body as { model?: unknown } | null)?.model;
  let model = typeof rawModel === "string" ? rawModel.slice(0, 200) : "unknown";
  const add = (hits: Hit[], tier: Tier, direction: Direction) => { for (const hit of hits) entries.push({ hit, tier, direction }); };

  /** Build, persist and publish the record, then shape the HTTP response. */
  const finish = (status: number, makeBody: (r: DecisionRecord) => unknown, extra: { stream?: ChatCompletion; headers?: Record<string, string> } = {}): ChatResponseOut => {
    lat.total = performance.now() - t0;
    const deciding = decide(entries);
    const owasp = [...new Set(entries.flatMap((e) => e.hit.owasp))];
    const record: DecisionRecord = {
      id, ts: new Date().toISOString(), agentId, sessionId, model,
      direction: deciding?.direction ?? "request",
      decision: deciding?.hit.action ?? "allow",
      enforced, tier: deciding?.tier ?? null,
      ruleId: deciding?.hit.ruleId ?? null, controlId: deciding?.hit.controlId ?? null,
      owasp, hits: entries.map((e) => e.hit),
      policyVersion: snap.hash, policyDeclaredVersion: policy.version, feedVersion: feedSnap?.loaded.hash ?? null,
      latencyMs: lat, excerptRedacted: deciding?.hit.excerptRedacted?.slice(0, 200) ?? null,
      tokensIn, tokensOut, costUsd: Math.round(cost * 1e6) / 1e6, computeSeconds: Math.round(computeMs) / 1000,
      httpStatus: status, details,
    };
    persist(ctx, record);
    const headers = { ...tollgateHeaders(record), ...extra.headers };
    if (extra.stream) return { status, headers: { ...headers, "content-type": "text/event-stream" }, body: null, stream: toSse(extra.stream), record };
    return { status, headers, body: makeBody(record), record };
  };
  const blocked = (status: number, type: string, message: string) =>
    finish(status, (r) => ({ error: { type, code: r.ruleId, message, event_id: r.id } }));

  // Stage 1: identity.
  let ta = performance.now();
  const auth = authenticate(req.header("authorization"), policy);
  if (!auth.ok) {
    lat.auth = performance.now() - ta;
    enforced = true;
    add([{ controlId: "auth", ruleId: auth.ruleId, action: "block", owasp: ["ASI03"] }], null, "request");
    return finish(401, (r) => ({ error: { type: "unauthorized", code: r.ruleId, message: "missing or unknown agent key", event_id: r.id } }));
  }
  const { agent } = auth.id;
  agentId = auth.id.agentId;
  // Stage 0: parse, after auth so an unauthenticated caller learns nothing about the body. Invalid bodies get a 400 and no record.
  const parsed = ChatRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    const message = parsed.error.issues.slice(0, 3).map((i) => `${i.path.join(".") || "(body)"}: ${i.message}`).join("; ");
    return { status: 400, headers: {}, body: { error: { type: "invalid_request", message } }, record: null };
  }
  const body = parsed.data;
  model = body.model;
  const firstSystem = body.messages.find((m) => m.role === "system" || m.role === "developer");
  sessionId = sessionIdFor(req.header("x-session-id"), agentId, firstSystem ? messageText(firstSystem) : "");
  const killed = ctx.db.query("SELECT reason FROM killed_sessions WHERE agent_id = ? AND session_id = ?").get(agentId, sessionId) as { reason: string } | null;
  if (killed) {
    lat.auth = performance.now() - ta;
    enforced = true;
    add([{ controlId: "auth", ruleId: "session.killed", action: "block", owasp: ["ASI03"], details: { reason: killed.reason } }], null, "request");
    return blocked(403, "tollgate_blocked", "This session was terminated by Tollgate");
  }
  const usesTools = (body.tools?.length ?? 0) > 0 || body.messages.some((m) => (m.tool_calls?.length ?? 0) > 0);
  const missingScope = !agent.scopes.includes("chat") ? "chat" : usesTools && !agent.scopes.includes("tools") ? "tools" : null;
  if (missingScope) {
    lat.auth = performance.now() - ta;
    enforced = true;
    add([{ controlId: "auth", ruleId: "auth.scope", action: "block", owasp: ["ASI03"], details: { missingScope } }], null, "request");
    return blocked(403, "tollgate_blocked", `agent lacks the "${missingScope}" scope`);
  }
  const modelRule = modelCheck(model, policy, agent);
  lat.auth = performance.now() - ta;
  if (modelRule) {
    add([{ controlId: "models", ruleId: modelRule, action: "block", owasp: ["LLM03", "ASI04"], details: { model } }], null, "request");
    if (enforceMode) return blocked(403, "tollgate_blocked", `model "${model}" is not allowed for this agent`);
  }

  // Stage 2: budget pre-check. First failure wins.
  const tb = performance.now();
  const limits = limitsFor(policy, agentId);
  const budgetEnforced = enforceMode || policy.budgets.enforce_in_monitor;
  const totalChars = body.messages.reduce((n, m) => n + messageText(m).length, 0);
  const estIn = estimateTokens(totalChars);
  const maxTokens = body.max_tokens ?? body.max_completion_tokens ?? policy.budgets.default_max_tokens;
  // n completions can each use maxTokens.
  const reservedOut = maxTokens * (body.n ?? 1);
  const pricing = priceFor(ctx.pricing(), model);
  if (pricing.matched === null && !ctx.pricingMissing.has(model)) {
    ctx.pricingMissing.add(model);
    log("warn", "pricing.missing: using the default price", { model });
  }
  const estCost = costUsd(pricing.price, estIn, reservedOut);
  // Loop key: the last user or tool message (budget/loop.ts explains why tool results count).
  const lastInput = [...body.messages].reverse().find((m) => m.role === "user" || m.role === "tool");
  const toolNames = (body.tools ?? []).map((t) => String((t as { function?: { name?: unknown } } | null)?.function?.name ?? ""));
  let budgetFail: { hit: Hit; status: number; retryAfterS: number; type: string } | null = null;
  const depthHeader = Number(req.header("x-tollgate-depth") ?? 0) || 0;
  const depth = Math.max(body.messages.filter((m) => m.role === "tool").length, depthHeader);
  if (depth > limits.max_tool_depth) {
    budgetFail = { hit: { controlId: "budget", ruleId: "budget.max_tool_depth", action: "block", owasp: ["LLM06", "ASI08"], details: { depth, limit: limits.max_tool_depth } }, status: 429, retryAfterS: 1, type: "budget_exceeded" };
  }
  const lb = policy.budgets.loop_breaker;
  if (!budgetFail && lb.enabled) {
    const hash = requestHash(agentId, model, normalize(lastInput ? messageText(lastInput) : "").text, toolNames);
    const windowMs = parseDuration(lb.same_request_within);
    const count = ctx.loop.check(agentId, hash, windowMs);
    if (count >= lb.max_repeats) {
      const hit: Hit = { controlId: "budget", ruleId: "budget.loop_breaker", action: lb.action, owasp: BUDGET_OWASP, details: { repeats: count + 1, limit: lb.max_repeats } };
      if (SEVERITY[lb.action] >= SEVERITY.block) budgetFail = { hit, status: 429, retryAfterS: Math.ceil(windowMs / 1000), type: "budget_exceeded" };
      else add([hit], null, "request");
    }
  }
  const cb = policy.budgets.circuit_breaker;
  const host = ctx.upstream.host(policy);
  const circuitOpen = (retryAfterS: number) => ({ hit: { controlId: "budget", ruleId: "budget.circuit_open", action: "block" as const, owasp: BUDGET_OWASP, details: { host } }, status: 503, retryAfterS, type: "circuit_open" });
  if (!budgetFail && cb.enabled) {
    // Read-only here; the half-open probe slot is taken right before the upstream call (stage 6).
    const retry = ctx.circuit.check(host, parseDuration(cb.open_for));
    if (retry !== null) budgetFail = circuitOpen(retry);
  }
  if (!budgetFail) {
    const ex = ctx.ledger.precheck(agentId, limits, { tokensIn: estIn, maxTokens: reservedOut, costUsd: estCost });
    if (ex) {
      budgetFail = { hit: { controlId: "budget", ruleId: ex.ruleId, action: "block", owasp: BUDGET_OWASP, details: { used: ex.used, limit: ex.limit } }, status: 429, retryAfterS: ex.retryAfterS, type: "budget_exceeded" };
      ctx.bus.emit("budget.exceeded", { agentId, ruleId: ex.ruleId, used: ex.used, limit: ex.limit });
    }
  }
  lat.budget = performance.now() - tb;
  const budgetRefused = (f: NonNullable<typeof budgetFail>) =>
    finish(f.status, (r) => ({ error: { type: f.type, code: r.ruleId, message: `budget limit reached: ${r.ruleId}`, retry_after_s: f.retryAfterS, event_id: r.id } }), { headers: { "Retry-After": String(f.retryAfterS) } });
  if (budgetFail) {
    add([budgetFail.hit], null, "request");
    if (budgetEnforced) {
      enforced = true;
      ctx.ledger.commit(agentId, { requests: 1, tokens_in: 0, tokens_out: 0, usd: 0, compute_ms: 0 });
      return budgetRefused(budgetFail);
    }
  }

  // Stage 2b: reserve the estimate. No await since precheck() above, so the check and the booking are one step and
  // concurrent requests cannot all pass the same pre-check. Every exit below settles the reservation exactly once:
  // the success path with the upstream's usage, every other path (block, dry run, upstream error, exception) in
  // `finally` with one request and the compute it used.
  const reservation = ctx.ledger.reserve(agentId, { requests: 1, tokens_in: estIn, tokens_out: reservedOut, usd: estCost, compute_ms: 0 });
  let settled = false;
  // Set as soon as the upstream answered: an exception after that point (output path, approval wait) still books
  // what the upstream really used instead of zero.
  let spent: { tokens_in: number; tokens_out: number; usd: number } | undefined;
  const settle = (u: { tokens_in: number; tokens_out: number; usd: number } = spent ?? { tokens_in: 0, tokens_out: 0, usd: 0 }) => {
    if (settled) return;
    ctx.ledger.settle(agentId, reservation, { requests: 1, ...u, compute_ms: Math.round(computeMs) });
    settled = true;
  };

  try {
    // Stage 3: tier 0.
    const tt = performance.now();
    const env: ScanEnv = { policy, feed: feedSnap?.compiled ?? null, canaries: ctx.canaries.tokens(), ignore: [agent.key] };
    const t0r = runTier0(body.messages, body.tools, env);
    lat.tier0 = performance.now() - tt;
    add(t0r.hits, 0, "request");
    Object.assign(details, t0r.details);
    noteCanaries(ctx, t0r.hits, { agentId, sessionId, eventId: id, direction: "request", details });
    const stop = (from: number) => {
      const d = decide(entries.slice(from));
      return d && SEVERITY[d.hit.action] >= SEVERITY.block ? d : null;
    };
    const terminal = stop(0);
    if (terminal && enforceMode) {
      if (terminal.hit.action === "kill_session") killSession(ctx, terminal.hit, { agentId, sessionId, eventId: id });
      return blocked(403, "tollgate_blocked", blockMessage(terminal.hit));
    }
    const forwardMessages: ChatMessage[] = enforceMode ? t0r.redactedMessages : body.messages;
    const forwardTools = enforceMode ? t0r.keptTools : body.tools;

    // Stages 4–5: semantic tiers.
    const skip = semanticSkipped(policy, ctx.semantic);
    const target = [...body.messages].reverse().find((m) => m.role === "user" || m.role === "tool");
    const targetText = target ? normalize(messageText(target)).text : "";
    if (skip) details.semantic = skip;
    else if (targetText) {
      const history = body.messages
        .filter((m): m is ChatMessage & { role: "user" | "assistant" } => (m.role === "user" || m.role === "assistant") && m !== target)
        .map((m) => ({ role: m.role, content: messageText(m) }))
        .filter((m) => m.content);
      const before = entries.length;
      const s = await runSemantic(withDecoded(targetText, policy), policy, ctx.semantic, agent.description ?? "general assistant", history);
      lat.tier1 = s.tier1Ms;
      lat.tier2 = s.tier2Ms;
      computeMs += s.tier1Ms + s.tier2Ms;
      Object.assign(details, s.details);
      for (const h of s.hits) entries.push({ hit: h.hit, tier: h.tier, direction: "request" });
      const semTerminal = stop(before);
      if (semTerminal && enforceMode) return blocked(403, "tollgate_blocked", blockMessage(semTerminal.hit));
    }

    // Dry run: everything up to here ran; the upstream and the output path are skipped. It still counts as a request
    // and its tier-1/2 compute is booked (in `finally`), so dry runs are not a way around requests_per_minute.
    if (req.header("x-tollgate-dry-run") === "1" && agent.scopes.includes("dry_run")) {
      details.dryRun = true;
      return finish(200, (r) => ({ tollgate: { decision: r.decision, ruleId: r.ruleId, tier: r.tier, latencyMs: r.latencyMs }, dry_run: true }));
    }

    // Stage 6: upstream. In half-open exactly one request takes the probe slot; a second one in flight gets 503
    // (only where budgets are enforced; monitor mode records circuit_open in stage 2 and lets traffic through).
    if (cb.enabled && budgetEnforced) {
      const retry = ctx.circuit.claim(host, parseDuration(cb.open_for));
      if (retry !== null) {
        const f = circuitOpen(retry);
        add([f.hit], null, "request");
        enforced = true;
        return budgetRefused(f);
      }
    }
    const tu = performance.now();
    // A pricing.json alias (e.g. the shadow-priced demo-paid-model) is served by its upstream_model.
    const upstreamBody = { ...body, model: pricing.price.upstream_model ?? body.model, messages: forwardMessages, stream: false } as typeof body;
    if (forwardTools && forwardTools.length > 0) upstreamBody.tools = forwardTools; else delete upstreamBody.tools;
    // The reservation is also the cap: without a limit the upstream could generate far more than was reserved.
    // Only added when the caller sent neither field, so a client's max_completion_tokens is forwarded alone.
    if (upstreamBody.max_tokens === undefined && upstreamBody.max_completion_tokens === undefined) upstreamBody.max_tokens = maxTokens;
    let result: Awaited<ReturnType<typeof ctx.upstream.chat>>;
    try {
      result = await ctx.upstream.chat(upstreamBody, {
        policy, agentId, echo: ctx.upstream.name === "echo" ? (req.header("x-tollgate-echo") ?? null) : null, signal: AbortSignal.timeout(policy.upstream.timeout_ms),
      });
    } catch (err) {
      // An adapter that throws (e.g. a 200 with a body that is not JSON) is an upstream failure like any other:
      // recorded as upstream.error and counted by the breaker, so a half-open probe never stays claimed.
      result = { ok: false, status: 502, message: `upstream adapter error: ${(err as Error).message}` };
    }
    lat.upstream = performance.now() - tu;
    computeMs += lat.upstream;
    if (!result.ok) {
      // Only server-side trouble counts against the shared breaker; a 4xx (unknown model tag, bad request) is the
      // caller's problem and must not let one agent shut the upstream for every agent.
      const serverSide = result.status >= 500 || result.status === 429;
      if (cb.enabled) {
        if (serverSide) ctx.circuit.failure(host, cb.failure_threshold, parseDuration(cb.window));
        else ctx.circuit.success(host);
      }
      ctx.telemetry.counters.upstreamErrors.inc({ host });
      add([{ controlId: "upstream", ruleId: "upstream.error", action: "allow", owasp: [], details: { status: result.status, message: result.message.slice(0, 200) } }], null, "response");
      const status = result.status;
      return finish(502, (r) => ({ error: { type: "upstream_error", status, message: "the upstream model server failed", event_id: r.id } }));
    }
    if (cb.enabled) ctx.circuit.success(host);
    const completion = result.body;
    {
      const pIn = completion.usage?.prompt_tokens ?? estIn;
      const pOut = completion.usage?.completion_tokens ?? estimateTokens(JSON.stringify(completion.choices).length);
      spent = { tokens_in: pIn, tokens_out: pOut, usd: costUsd(pricing.price, pIn, pOut) };
    }

    // Stage 7: output path.
    const to = performance.now();
    const system = body.messages.filter((m) => m.role === "system" || m.role === "developer").map(messageText).join("\n");
    const out = await runOutput(completion, body.tools ?? [], system, env, enforceMode, {
      wait: (toolName, args, timeoutMs) => ctx.approvals.request({ agentId, sessionId, eventId: id, toolName, args, timeoutMs }),
    });
    lat.output = performance.now() - to;
    const beforeOut = entries.length;
    for (const h of out.hits) entries.push({ hit: h.hit, tier: 0, direction: h.direction });
    Object.assign(details, out.details);
    noteCanaries(ctx, out.hits.map((h) => h.hit), { agentId, sessionId, eventId: id, direction: "response", details });

    // Stage 8: budget commit with the upstream's usage (fallback: estimate), replacing the reservation.
    tokensIn = spent.tokens_in;
    tokensOut = spent.tokens_out;
    cost = spent.usd;
    settle(spent);

    const outTerminal = stop(beforeOut);
    if (outTerminal && enforceMode) {
      if (outTerminal.hit.action === "kill_session") killSession(ctx, outTerminal.hit, { agentId, sessionId, eventId: id });
      return blocked(403, "tollgate_blocked", blockMessage(outTerminal.hit));
    }
    const finalBody = enforceMode ? out.redacted : completion;
    if (body.stream) {
      details.stream = "buffered";
      return finish(200, () => null, { stream: finalBody });
    }
    return finish(200, () => finalBody);
  } finally {
    settle();
  }
}

/**
 * The classifier and the judge read the decoded forms too (url, base64, hex, leetspeak, joined fragments), so an
 * encoding that tier 0 can undo does not blind tier 1/2. Bounded: 3 variants, 2000 characters.
 */
function withDecoded(text: string, policy: Policy): string {
  const d = policy.controls.decode;
  if (!d.enabled || d.max_depth === 0) return text;
  const extra = decodeVariants(text, d.max_depth).variants.slice(0, 3).map((v) => `\n\n[decoded ${v.encoding}] ${v.text}`).join("");
  return extra ? text + extra.slice(0, 2000) : text;
}

function blockMessage(hit: Hit): string {
  if (hit.controlId === "canaries" && hit.action === "kill_session") return "Session terminated: canary secret leaked";
  return `Blocked by Tollgate rule ${hit.ruleId}`;
}

function killSession(ctx: Ctx, hit: Hit, p: { agentId: string; sessionId: string; eventId: string }) {
  const canary = (hit.details?.canary as { id?: string } | undefined)?.id;
  const reason = canary ? `canary:${canary}` : hit.ruleId;
  ctx.db.query("INSERT OR IGNORE INTO killed_sessions (agent_id, session_id, ts, reason, event_id) VALUES (?, ?, ?, ?, ?)")
    .run(p.agentId, p.sessionId, new Date().toISOString(), reason, p.eventId);
  ctx.telemetry.counters.sessionsKilled.inc({});
  ctx.bus.emit("session.killed", { sessionId: p.sessionId, agentId: p.agentId, reason, eventId: p.eventId });
}

/** Canary hits: bump the counter, emit canary.tripped, name the canary on the record. */
function noteCanaries(ctx: Ctx, hits: Hit[], p: { agentId: string; sessionId: string; eventId: string; direction: string; details: Record<string, unknown> }) {
  for (const h of hits) {
    const c = h.details?.canary as { id: string; kind: string; label: string | null } | undefined;
    if (!c) continue;
    ctx.canaries.trip(c.id);
    ctx.telemetry.counters.canaryTrips.inc({ kind: c.kind });
    p.details.canary = c;
    ctx.bus.emit("canary.tripped", { canaryId: c.id, kind: c.kind, agentId: p.agentId, sessionId: p.sessionId, eventId: p.eventId, direction: h.ruleId === "canaries.in_tool_call" ? "tool_call" : p.direction });
  }
}

/** Buffered streaming: the full (already scanned) completion re-emitted as OpenAI SSE chunks of 64 chars. */
function toSse(c: ChatCompletion): ReadableStream<Uint8Array> {
  const enc = new TextEncoder();
  const base = { id: c.id, object: "chat.completion.chunk", created: c.created, model: c.model };
  const lines: string[] = [];
  for (const ch of c.choices) {
    const content = ch.message.content ?? "";
    lines.push(JSON.stringify({ ...base, choices: [{ index: ch.index, delta: { role: "assistant", content: "" }, finish_reason: null }] }));
    for (let i = 0; i < content.length; i += 64) lines.push(JSON.stringify({ ...base, choices: [{ index: ch.index, delta: { content: content.slice(i, i + 64) }, finish_reason: null }] }));
    if (ch.message.tool_calls?.length) {
      lines.push(JSON.stringify({ ...base, choices: [{ index: ch.index, delta: { tool_calls: ch.message.tool_calls.map((t, k) => ({ index: k, ...t })) }, finish_reason: null }] }));
    }
    lines.push(JSON.stringify({ ...base, choices: [{ index: ch.index, delta: {}, finish_reason: ch.finish_reason }] }));
  }
  return new ReadableStream({
    start(controller) {
      for (const l of lines) controller.enqueue(enc.encode(`data: ${l}\n\n`));
      controller.enqueue(enc.encode("data: [DONE]\n\n"));
      controller.close();
    },
  });
}
