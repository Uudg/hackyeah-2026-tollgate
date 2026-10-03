# Tollgate — Claude Code project memory

## No-models mode (current reality)

Ollama models may be absent for most of the build. Everything except the real Ollama adapter must work with `SEMANTIC_PROVIDER=mock` and `UPSTREAM=echo` (HANDOFF.md §0, SPEC.md §2.1). Never make a milestone, a test, or the dashboard depend on a model being present. Model-backed fixtures carry `tags: [model]` and `requires: [<model>]` and skip with a visible message.

## What this is

Tollgate is an AI Control Layer for the Goldman Sachs partner task at HackYeah 2026: an OpenAI-compatible HTTP proxy that sits between any agent/app and its model or tools, and enforces a single `policy.yaml` with deterministic controls, local-model semantic controls, budgets, a historical-attack signature feed, a hash-chained audit log, a Next.js dashboard and a self-testing suite. Dan builds it solo on a MacBook Pro M1 Max in this repo.

Reading order at the start of every session: this file (auto-loaded), `HANDOFF.md` (brief, milestones, checkpoints, model/effort), `docs/PLAN.md` (order of work, hours, cut list), `docs/SPEC.md` (the technical contract: every name, route, schema and rule id). When two documents disagree, `docs/SPEC.md` wins; when SPEC and `_context.md` disagree, `_context.md` wins and SPEC gets fixed. `docs/CHECKLIST.md` maps requirements to milestones, SPEC sections and test files.

## Hackathon constraints that shape every decision

- Deadline: Sunday 4 Oct 2026. Hard target 11:00 CEST (code freeze 10:00, submit by 10:30), hoped-for second submission by 23:00. Work started Saturday 3 Oct ~16:00. Submission goes on the HackTribe platform (title, team, description, ≤10-slide PDF, repo link).
- No paid APIs. No OpenAI, Anthropic, Copilot or any cloud model. Every model call goes to a local Ollama on `http://localhost:11434`.
- Judges will: (1) run `bun test` themselves on their own machine, (2) type ad-hoc attack prompts at the running gateway, (3) edit `policy.yaml` and `feeds/ai-exploits.json` live (change rules, remove controls, change thresholds) and expect the next request to reflect it without restart, (4) ask for performance telemetry, (5) review the architecture diagram, dashboards and audit logs.
- Scoring: guardrail robustness 30, architecture + performance 20, security reporting 20, test-suite completeness 15–20, implementability 10–15. Dashboard polish is not a criterion.
- Only the control layer is assessed. The demo agent is a prop.
- AI tool use is allowed but must be disclosed, and Dan must be able to explain every part of the code. Keep code readable; no magic.

## Stack and layout

Bun workspaces monorepo (`apps/*`, `packages/*`). TypeScript everywhere. Node-only APIs are avoided; use Bun APIs (`bun:sqlite`, `Bun.file`, `Bun.serve` via Hono). The dashboard runs under Node (`next dev`), never `bun --bun`.

```
hackyeah2026/
  CLAUDE.md               this file
  HANDOFF.md              brief, milestones, checkpoints, model/effort plan
  README.md               setup in 3 commands, architecture diagram, coverage map, AI-use disclosure
  docs/SPEC.md            the implementation contract (routes, schemas, rule ids, stage order, test format)
  docs/PLAN.md            hour-by-hour plan, cut list, subagent tracks, submission checklist
  docs/CHECKLIST.md       requirement → milestone → SPEC section → test file
  package.json            workspaces + root scripts
  policy.yaml             THE control catalog (hot-reloaded); policy.strict.yaml / policy.monitor.yaml are the presets
  pricing.json            per-model prices (hot-reloaded); local models at 0 USD
  feeds/ai-exploits.json  historical-attack signature feed (file or URL source)
  data/                   runtime only, gitignored: audit.jsonl, tollgate.db
  apps/gateway/           Bun + Hono proxy, port 8787 (module list: SPEC §1.4)
    src/server.ts         Bun.serve entry; routes: /v1/chat/completions, /v1/models, /healthz, /metrics, /admin/* (events SSE, policy, feed, audit, approvals, canaries, sessions, redteam, coverage, playground, scan)
    src/app.ts            createGateway(opts) → { app, setPolicy, getPolicy, close }  (used by tests)
    src/pipeline/         identity → budget → tier0 → tier1 → tier2 → upstream → output (SPEC §2)
    src/semantic/         SemanticProvider interface + adapters ollama | mock | off
    src/upstream/echo.ts  built-in echo upstream (UPSTREAM=echo and the test harness)
    src/budget/           SQLite ledger (windows), loop breaker, circuit breaker
    src/audit/            hash-chained JSONL writer + verify CLI
    src/feed/             signature feed loader (file/URL, interval refresh) + evaluators
    src/telemetry/        per-stage reservoirs, counters, /metrics text, posture score
    src/redteam/          seeds, mutators, runner, cli (bun run redteam)
    src/demo/agent.ts     demo tool-using agent (read_document, http_get, send_email) for bun run demo and the playground
    src/cli/              validate-policy.ts, validate-feed.ts
  apps/dashboard/         Next.js App Router, port 3000; reads the gateway via HTTP + SSE only, never imports gateway code
  packages/policy/        zod schemas + loader: policy.yaml, DecisionRecord, FeedEntry, TestCase. FROZEN after Checkpoint 1.
  packages/controls/      pure functions, one file per control: input → Hit[]. No I/O, no Ollama.
  tests/
    cases/*.yaml          fixtures grouped by control (pii, secrets, injection, models, budgets, feed, output, tool_calls, canaries, policy, audit)
    cases/generated/      failing fixtures written by the Red Team Loop (committed deliberately)
    redteam/seeds/*.yaml  seed attacks for the fuzzer (garak/promptfoo-derived, attributed)
    harness/              gateway.ts (in-process boot), yaml.ts, report.ts, ollama.ts
    runner.test.ts        bun test entry: loads fixtures, runs them against an in-process gateway
    policy.test.yaml      the policy the suite runs on (never ./policy.yaml)
```

Fixed values — do not change without updating HANDOFF.md, SPEC.md and README:

| Thing | Value |
|---|---|
| Gateway | `http://localhost:8787` |
| Dashboard | `http://localhost:3000` |
| Ollama | `http://localhost:11434` (`OLLAMA_URL`) |
| Demo agent model | `llama3.2:3b` (fallback `qwen2.5:3b`), `DEMO_MODEL` |
| Tier-1 classifier | `llama-guard3:1b` (`policy.semantic.classifier_model`); optional `granite3-guardian:2b` (`semantic.jailbreak_model`) |
| Tier-2 judge | `llama3.2:3b` (`policy.semantic.judge_model`), strict JSON verdict |
| Policy file | `./policy.yaml` (`TOLLGATE_POLICY`) |
| Feed | `./feeds/ai-exploits.json` (`TOLLGATE_FEED`) |
| Audit log | `./data/audit.jsonl` (`TOLLGATE_DATA_DIR`) |
| SQLite | `./data/tollgate.db` |
| Agent auth | `Authorization: Bearer tg_<agent>_<random>`; keys map to agent id + scopes in `policy.agents` |
| Admin auth | `Authorization: Bearer <ADMIN_TOKEN>` or `?token=` on `/admin/*` |
| Agents in policy.yaml | `demo-agent`, `research-bot`, `finance-agent`, `paid-demo`, `test-small-budget`, `redteam` (keys in the file) |

## Commands

```
bun install            install all workspaces
bun run dev            gateway (watch) + dashboard concurrently
bun run gateway        gateway only (alias dev:gateway)
bun run dashboard      dashboard only (alias dev:dashboard)
bun test               full suite; deterministic cases always run, model-backed cases skip with a message if Ollama/models are absent
bun run test:fast      deterministic cases only (--test-name-pattern deterministic)
bun run check          typecheck every workspace + policy.yaml validation (the gate for every commit)
bun run policy:check   validate a policy file; bun run feed:check validates the feed
bun run demo           scripted walkthrough through the live gateway: clean pass, PII redact, base64 injection block, canary kill, budget loop
bun run redteam        Red Team Loop against the live gateway; --minutes N, --control X, --depth 1|2; writes bypasses to tests/cases/generated/
bun run audit:verify   walk the hash chain of ./data/audit.jsonl
bun run bench          tier-0 overhead and throughput numbers for the README
./scripts/setup.sh     install bun/ollama if missing, start pulls, bun install, write .env;  ./scripts/doctor.sh  readiness table
```

## Coding rules

- TypeScript `strict: true`, `noUncheckedIndexedAccess: true`. No `any` outside test glue.
- Zod at every boundary: policy file, feed file, incoming request bodies, Ollama responses, test fixtures. Parse, don't cast.
- No silent catches. Every `catch` either rethrows, returns a typed failure that is logged with the rule id, or is a deliberate fail-open that is recorded as an allow-action hit with `ruleId: "semantic.unavailable"` / `"sig.feed_unavailable"` / `"upstream.error"`.
- Every decision is a `DecisionRecord` (SPEC §3) with: `ruleId`, `controlId`, `owasp` (array of LLM01–LLM10 / ASI01–ASI10), `policyVersion` (`p-` + 12 hex of the canonical parsed policy), `feedVersion`, `tier` (0 | 1 | 2 | null), `direction` (request | response | tool_call), `decision` (allow | redact | block | kill_session), `enforced` (false in monitor mode), `latencyMs` per stage. No decision without all of these.
- Rule ids are the ones in SPEC: `auth.*`, `session.killed`, `models.*`, `budget.*`, `unicode.*`, `decode.rescan`, `pii.<entity>`, `secrets.<name>`, `inject.heuristic.<n>` / `inject.classifier` / `inject.judge`, `content_safety.<Sx>`, `semantic.unavailable`, `sig.<feed-entry-id>`, `canaries.in_*`, `link_exfil.*`, `sysprompt.leak`, `tool_calls.*`, `upstream.error`. Do not invent new prefixes.
- Fail-closed is configurable: `semantic.fail_mode: open | closed` (default `open`; `policy.strict.yaml` uses `closed`) and `controls.signatures.fail_mode`. Honour it everywhere a model or the feed is called.
- Never block on Ollama without a timeout. Use `AbortSignal.timeout(policy.semantic.timeout_ms)` (judge: `judge_timeout_ms`). Record the timeout as its own stage latency.
- Deterministic tests are model-free. `packages/controls` has no network access and is tested in isolation. Model-backed fixtures carry `tags: [model]` and `requires: [<model tag>]` and skip with `SKIP (model-backed): needs Ollama at :11434 with <model> — run \`ollama serve\` and \`ollama pull <model>\``.
- Hot reload: `fs.watch` on the directory of `policy.yaml`, the feed and `pricing.json`; debounce 150 ms; parse with zod; on failure keep the last good version and emit `policy.rejected` / `feed.rejected` with the zod error path. Never crash on a bad file. Emit `policy.loaded` / `feed.loaded` with the hash and changed paths on success.
- `monitor` mode evaluates everything, records what it would have done (`enforced: false`), and forwards unchanged. `enforce` acts. Both write identical `DecisionRecord`s so the dashboard can show "would block".
- Streaming: baseline is buffered (upstream non-streamed, output path on the full completion, re-emitted as SSE chunks). Upgrade to the 64-char sliding buffer only if M3 finishes on time; otherwise stay buffered and say so in the README.
- Log with structured JSON to stdout, never raw message content; the audit file is separate and append-only.
- Keep every control a pure function over strings/objects and the relevant policy slice → `Hit[]`. Pipeline order and actions come from policy and SPEC §2, never hardcoded elsewhere.

## Definition of done per milestone

A milestone is done when all of these hold:

1. `bun run check` passes.
2. `bun test` passes (deterministic always; model-backed if Ollama is up; skips visible otherwise).
3. The acceptance check listed for that milestone in `HANDOFF.md` / `docs/PLAN.md` has been run and its output pasted into the commit message or the checkpoint message.
4. New controls have at least one positive (allow) and one negative (block/redact) fixture, tagged with control id and OWASP id.
5. `policy.yaml` documents every new key with a comment; `policy.strict.yaml` and `policy.monitor.yaml` still validate.
6. One commit per milestone minimum, conventional message, tagged `m<N>`.

## What NOT to do

- No cloud APIs of any kind, including "just for the judge model". If Ollama is down, the configured `fail_mode` path runs — nothing else.
- No LLM Guard (archived July 2026). No LiteLLM enterprise features (budgets/guardrails are separately licensed) — write budgets and the pipeline ourselves.
- No Python sidecars in the critical path. Presidio / Prompt Guard 2 / ModelScan are references only, mentioned in README as optional.
- No cloud decision models (TypeSafe Jev etc.) in the core. At most the `semantic.provider: local | jev` enum, default `local`, `jev` not implemented.
- No dashboard gold-plating before M4 is accepted. The dashboard gets built once, in M5, against the frozen schemas and the `/admin/*` contract in SPEC §8.
- No renaming of ports, file paths, package names, routes, event names or the rule-id / decision vocabulary after the plan is accepted.
- No rewriting of `packages/policy` schemas by a subagent. Schema changes go through the main session only.
- No hand-edited `data/` files in git. `data/` is gitignored.
- No feature work during the hardening pass; fixes and tests only.

## Subagents in this repo

The shared schemas in `packages/policy` (policy.yaml zod schema, `DecisionRecord`, `FeedEntry`, `TestCase`) are frozen at the end of planning. Once they are frozen, these tracks have no shared files and can run in parallel as subagents:

| Track | Owns (write access) | Reads | Model |
|---|---|---|---|
| A. Gateway controls | `packages/controls`, `apps/gateway/src/**`, `tests/harness`, `tests/*.test.ts` | `packages/policy` | Opus 5.5 high (main session) |
| B. Dashboard | `apps/dashboard` only | `packages/policy` types, SPEC §8 routes, §10 views, `/admin/events` payloads | Sonnet medium |
| C. Test fixtures | `tests/cases/*.yaml` only | SPEC §11.1 format, rule ids from SPEC, agents from `policy.yaml` | Sonnet medium |
| D. Red-team seeds | `tests/redteam/seeds/*.yaml` only | SPEC §12.1 seed format, §12.2 mutator list | Sonnet medium |
| E. Docs draft | `README.md`, `docs/SLIDES.md`, `docs/architecture.mmd` | everything, read-only | Sonnet medium |

Rules: each subagent gets the track's folder list, the frozen schema file paths, and the rule-id list from SPEC. A subagent that needs a schema change stops and reports instead of editing `packages/policy`. The main session merges, runs `bun run check` and `bun test`, and commits. Do not run two subagents on the same folder.

## Plan mode and ultracode

- Start every new session in Plan mode: read `HANDOFF.md`, `docs/PLAN.md`, `git log --oneline -20`, the current `policy.yaml`, and the last checkpoint message in `docs/CHECKPOINTS.md`, then write the plan for the next milestone before touching code.
- Use Plan mode again before M5 (dashboard) and before M7 (Red Team Loop), because both consume the frozen schemas and the plan must list the exact endpoints/types they depend on.
- Say `ultracode` only for the two exhaustive passes described in HANDOFF.md §7: the hardening pass after M8 (adversarial review of every control, extra fixtures for each finding, no new features) and the final README/diagram/slide review before submission. Do not use it for scaffolding.

## Disclosure rule

README must contain an "AI and third-party use" section listing: Claude Code (models used) for implementation; Ollama models `llama3.2:3b`, `llama-guard3:1b`, `granite3-guardian:2b` (if used) with their licences; attack seeds adapted from garak (Apache 2.0) and promptfoo (MIT); every npm dependency with licence. Update it whenever a dependency or model is added.
