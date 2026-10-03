# Tollgate — Claude Code project memory


## No-models mode (current reality)

Ollama models may be absent for most of the build. Everything except the real Ollama adapter must work with `SEMANTIC_PROVIDER=mock` and `UPSTREAM=echo` (see HANDOFF.md §0). Never make a milestone, a test, or the dashboard depend on a model being present. Model-backed tests carry `requires: ollama` and skip with a visible message.

## What this is

Tollgate is an AI Control Layer for the Goldman Sachs partner task at HackYeah 2026: an OpenAI-compatible HTTP proxy that sits between any agent/app and its model or tools, and enforces a single `policy.yaml` with deterministic controls, local-model semantic controls, budgets, a historical-attack signature feed, a hash-chained audit log, a Next.js dashboard and a self-testing suite. Dan builds it solo on a MacBook Pro M1 Max in this repo; `HANDOFF.md` has the full brief, milestones and checkpoints — read it at the start of every session.

## Hackathon constraints that shape every decision

- Deadline: Sunday 4 Oct 2026. Hard target 11:00 CEST, hoped-for 23:00 CEST. Work started Saturday 3 Oct ~16:00. Submission goes on the HackTribe platform (title, team, description, ≤10-slide PDF, repo link).
- No paid APIs. No OpenAI, Anthropic, Copilot or any cloud model. Every model call goes to a local Ollama on `http://localhost:11434`.
- Judges will: (1) run `bun test` themselves on their own machine, (2) type ad-hoc attack prompts at the running gateway, (3) edit `policy.yaml` and `feeds/ai-exploits.json` live (change rules, remove controls, change thresholds) and expect the next request to reflect it without restart, (4) ask for performance telemetry, (5) review the architecture diagram, dashboards and audit logs.
- Scoring: guardrail robustness 30, architecture + performance 20, security reporting 20, test-suite completeness 15–20, implementability 10–15. Dashboard polish is not a criterion.
- Only the control layer is assessed. The demo agent is a prop.
- AI tool use is allowed but must be disclosed, and Dan must be able to explain every part of the code. Keep code readable; no magic.

## Stack and layout

Bun workspaces monorepo. TypeScript everywhere. Node-only APIs are avoided; use Bun APIs (`bun:sqlite`, `Bun.file`, `Bun.serve` via Hono).

```
hackyeah2026/
  CLAUDE.md               this file
  HANDOFF.md              brief, milestones, checkpoints, model/effort plan
  README.md               setup in 3 commands, architecture diagram, coverage map, AI-use disclosure
  package.json            workspaces + root scripts
  policy.yaml             THE control catalog (hot-reloaded)
  feeds/ai-exploits.json  historical-attack signature feed (file or URL source)
  data/                   runtime only, gitignored: audit.jsonl, tollgate.db
  apps/gateway/           Bun + Hono proxy, port 8787
    src/server.ts         routes: /v1/chat/completions, /v1/models, /admin/*, /metrics, /events (SSE), /audit/export
    src/pipeline/         tier0 → tier1 → tier2 → upstream → output scan
    src/budget/           SQLite budget ledger, loop breaker, circuit breaker
    src/audit/            hash-chained JSONL writer + exporter
    src/feed/             signature feed loader (file/URL, interval refresh)
    src/telemetry/        per-stage timers, p50/p95, /metrics
    src/redteam/          mutation engine + runner (bun run redteam)
    src/demo/             demo agent (tool-using loop) used by bun run demo and the playground
  apps/dashboard/         Next.js App Router, port 3000; reads gateway via HTTP + SSE
  packages/policy/        zod schemas + loader: policy.yaml, DecisionRecord, FeedEntry, TestCase. FROZEN after the plan.
  packages/controls/      pure functions, one file per control: input → ControlResult. No I/O, no Ollama.
  tests/
    cases/*.yaml          fixtures grouped by control (pii.yaml, secrets.yaml, injection.yaml, budget.yaml, ...)
    redteam/seeds/*.yaml  seed attacks for the fuzzer (garak/promptfoo-derived, attributed)
    runner.test.ts        bun test entry: loads fixtures, runs them against an in-process gateway
```

Fixed values — do not change without updating HANDOFF.md and README:

| Thing | Value |
|---|---|
| Gateway | `http://localhost:8787` |
| Dashboard | `http://localhost:3000` |
| Ollama | `http://localhost:11434` |
| Demo agent model | `llama3.2:3b` (fallback `qwen2.5:3b`) |
| Tier-1 classifier | `llama-guard3:1b`; optional `granite3-guardian:2b` |
| Tier-2 judge | same chat model as demo agent, strict JSON prompt |
| Policy file | `./policy.yaml` |
| Feed | `./feeds/ai-exploits.json` |
| Audit log | `./data/audit.jsonl` |
| SQLite | `./data/tollgate.db` |
| Agent auth | `Authorization: Bearer tg_<agent>_<random>`; keys map to agent id + scopes in policy |

## Commands

```
bun install            install all workspaces
bun run dev            gateway (watch) + dashboard concurrently
bun run gateway        gateway only
bun run dashboard      dashboard only
bun test               full suite; deterministic cases always run, model-backed cases skip with a message if Ollama/models are absent
bun run demo           scripted walkthrough through the live gateway: clean pass, PII redact, base64 injection block, canary kill, budget loop
bun run redteam        Red Team Loop against the live gateway; --minutes N, --control X; writes bypasses to tests/cases/redteam-found.yaml
bun run check          tsc --noEmit for every workspace + policy.yaml validation
```

## Coding rules

- TypeScript `strict: true`, `noUncheckedIndexedAccess: true`. No `any` outside test glue.
- Zod at every boundary: policy file, feed file, incoming request bodies, Ollama responses, test fixtures. Parse, don't cast.
- No silent catches. Every `catch` either rethrows, returns a typed failure that is logged with the rule id, or is a deliberate fail-open that is recorded as a `DecisionRecord` with `reason: "fail_open"`.
- Every decision is a `DecisionRecord` with: `rule_id`, `owasp` (array of LLM01–LLM10 / ASI01–ASI10), `policy_version` (sha256 of the loaded policy file, first 12 chars), `tier` (0 | 1 | 2 | output), `decision` (allow | redact | block | kill_session), `mode` (monitor | enforce), per-stage latency. No decision without all of these.
- Fail-closed is configurable: `semantic.on_timeout: allow | block` and `semantic.on_error: allow | block` in `policy.yaml`. Default `block` in enforce mode. Honour it everywhere Ollama is called.
- Never block on Ollama without a timeout. Use `AbortSignal.timeout(policy.semantic.timeout_ms)`. Record the timeout as its own stage latency.
- Deterministic tests are model-free. `packages/controls` has no network access and is tested in isolation. Model-backed tests carry `requires: ollama` in the fixture and skip with `SKIPPED: Ollama not reachable at :11434 or model X not pulled`.
- Hot reload: `fs.watch` on `policy.yaml` and the feed; parse with zod; on failure keep the last good version and emit a `policy_rejected` event with the zod error path. Never crash on a bad file.
- `monitor` mode evaluates everything, records what it would have done, and forwards unchanged. `enforce` acts. Both write identical `DecisionRecord`s so the dashboard can show "would block".
- Streaming: scan output chunks with a sliding buffer (keep the last 64 chars unflushed) so redaction works mid-stream. If this is not done by M3, disable streaming in the demo agent and say so in README.
- Log with structured JSON to stdout; the audit file is separate and append-only.
- Keep every control a pure function `(ctx: ControlContext) => ControlResult`. Pipeline order and actions come from policy, never hardcoded.

## Definition of done per milestone

A milestone is done when all of these hold:

1. `bun run check` passes.
2. `bun test` passes (deterministic always; model-backed if Ollama is up).
3. The acceptance check listed for that milestone in `HANDOFF.md` has been run and its output pasted into the commit message or the checkpoint message.
4. New controls have at least one positive (allow) and one negative (block/redact) fixture, tagged with control id and OWASP id.
5. `policy.yaml` documents every new key with a comment.
6. One commit per milestone minimum, conventional message, tagged `m<N>`.

## What NOT to do

- No cloud APIs of any kind, including "just for the judge model". If Ollama is down, the configured fail-open/fail-closed path runs — nothing else.
- No LLM Guard (archived July 2026). No LiteLLM enterprise features (budgets/guardrails are separately licensed) — write budgets and the pipeline ourselves.
- No Python sidecars in the critical path. Presidio / Prompt Guard 2 / ModelScan are references only, mentioned in README as optional.
- No cloud decision models (TypeSafe Jev etc.) in the core. At most an optional `semantic.provider: local | jev` switch, default `local`, not implemented unless everything else is done.
- No dashboard gold-plating before M4 is accepted. The dashboard gets built once, in M5, against the frozen event schema.
- No renaming of ports, file paths, package names or the decision/action vocabulary after the plan is accepted.
- No rewriting of `packages/policy` schemas by a subagent. Schema changes go through the main session only.
- No hand-edited `data/` files in git. `data/` is gitignored.
- No feature work during the hardening pass; fixes and tests only.

## Subagents in this repo

The shared schemas in `packages/policy` (policy.yaml zod schema, `DecisionRecord`, `FeedEntry`, `TestCase`) are frozen at the end of planning. Once they are frozen, these tracks have no shared files and can run in parallel as subagents:

| Track | Owns (write access) | Reads | Model |
|---|---|---|---|
| A. Gateway controls | `packages/controls`, `apps/gateway/src/pipeline`, `apps/gateway/src/budget` | `packages/policy` | Opus 5.5 high (main session) |
| B. Dashboard | `apps/dashboard` only | `packages/policy` types, `/events`, `/metrics` contract | Sonnet medium |
| C. Test fixtures | `tests/cases/*.yaml` only | `packages/policy` TestCase schema, control ids from the plan | Sonnet medium |
| D. Red-team seeds | `tests/redteam/seeds/*.yaml` only | mutation list in HANDOFF | Sonnet medium |

Rules: each subagent gets the track's folder list, the frozen schema file paths, and the control-id list from the plan. A subagent that needs a schema change stops and reports instead of editing `packages/policy`. The main session merges, runs `bun run check` and `bun test`, and commits. Do not run two subagents on the same folder.

## Plan mode and ultracode

- Start every new session in Plan mode: read `HANDOFF.md`, `git log --oneline -20`, the current `policy.yaml`, and the last checkpoint message, then write the plan for the next milestone before touching code.
- Use Plan mode again before M5 (dashboard) and before M7 (Red Team Loop), because both consume the frozen schemas and the plan must list the exact endpoints/types they depend on.
- Say `ultracode` only for the two exhaustive passes described in HANDOFF.md: the hardening pass after M8 (adversarial review of every control, extra fixtures for each finding, no new features) and the final README/diagram/slide review before submission. Do not use it for scaffolding.

## Disclosure rule

README must contain an "AI and third-party use" section listing: Claude Code (models used) for implementation; Ollama models `llama3.2:3b`, `llama-guard3:1b`, `granite3-guardian:2b` (if used) with their licences; attack seeds adapted from garak (Apache 2.0) and promptfoo (MIT); every npm dependency with licence. Update it whenever a dependency or model is added.
