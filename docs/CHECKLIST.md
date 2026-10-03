# CHECKLIST — traceability and the consistency fixes

Who reads this: Claude Code at Checkpoint 1 (to confirm nothing in the brief is unowned), at the final `ultracode` review (every claim must trace to a row here), and Dan before submitting. Source of truth order: `_context.md` → `docs/SPEC.md` → everything else.

## 1. Requirement → milestone → SPEC section → test file

The six formal requirements and four deliverables are from `HANDOFF.md` §2 (verbatim from the brief). "Test file" names the executable proof judges run with `bun test`; `*.yaml` are fixtures under `tests/cases/`, `*.test.ts` are the suite files under `tests/` (SPEC §11.2). Milestones are `docs/PLAN.md` §2.

| # | Requirement (brief) | Milestone(s) | SPEC section(s) | Test file(s) |
|---|---|---|---|---|
| R1 | Centralised policy engine: one config source for controls, sensitivity thresholds (block vs redact / adherence), allowed models, budgets | M1 (schema, loader, hot reload), M2 (per-control actions), presets shipped at M1 | §4 (schema, loader, hot reload), §4.1 presets, §2 stage 1 (model allowlist), §10.1 posture | `policy.yaml` (monitor mode, `enabled`, `action: allow`, entity lists, thresholds, per-agent models, budget limits), `models.yaml`, `policy-schema.test.ts` (presets parse, bad key/enum rejected), `hotreload.test.ts` (save → next request uses it, bad file → last good kept) |
| R2a | Deterministic controls: PII/secrets pattern matching, authentication and access checks | M1 (auth, scopes, model allowlist), M2 (normalise, decode, PII, secrets, heuristics, tool definitions) | §2 stages 1 and 3, §3a–3c, §7.1, §7.5 request side, §13 | `pii.yaml`, `secrets.yaml`, `injection.yaml` (deterministic cases), `models.yaml` (`auth.*`, `models.*`), `tool_calls.yaml`, `canaries.yaml`, `output.yaml` (response-path redaction), `packages/controls/src/__tests__/*` |
| R2b | Semantic controls: AI-based models securing the interaction | M3 (provider interface, mock/off adapters, tiers 1–2 logic), M3b (Ollama adapter) | §2.1 (SemanticProvider), §2 stages 4–5, §4.1 `semantic.*` | `semantic-mock.test.ts` (model-free: tier-1 block, tier-2 judge block, fail-open, fail-closed), `injection.yaml` cases tagged `[model]` (`content_safety.S9`, `inject.classifier`, `inject.judge`; skip cleanly without Ollama) |
| R3 | Budget and resource governance: resource access, compute time, token spend, for paid APIs and local models | M2 (ledger, loop breaker, circuit breaker, pricing) | §5 (tables, pricing, accounting, loop, depth, circuit), §2 stage 2 and 8, §4.1 `budgets.*` | `budgets.yaml` (tokens/h, req/min, usd/day on a priced model, local model at 0 USD, compute seconds, loop breaker, tool depth, depth header, monitor-mode advisory), `audit.yaml` (`audit-budget-429-is-recorded`), `policy.yaml` (`policy-budget-limit-from-policy`) |
| R4 | Historical attack mitigation: malicious code execution, unsafe deserialization, model-repository supply chain; signatures from an external feed | M4 (feed loader, evaluators, hot reload), M2 (matchers in `packages/controls`) | §6 (file format, entries, per-type evaluation), §3b, §2 stage 7 (response scope) | `feed.yaml` (Probllama digest, ShadowRay, EchoLeak, MCP tool poisoning, pickle opcode incl. nullifAI truncation, protocol-0 pickle, reverse shell, SSRF, prompt-leak phrases, jailbreak families, control disabled, entry action override), `hotreload.test.ts` (feed edit → `feed.loaded`, next decision changes), `bun run feed:check` |
| R5 | Security reporting and auditing: real-time metrics for management, exportable audit logs for security teams | M4 (audit writer, verify, export, telemetry, coverage), M5 (dashboard views) | §3 (DecisionRecord), §8 (`/admin/*`, `/metrics`), §9 (hash chain, export, verify), §10 (dashboard, posture, coverage map), §14 (telemetry) | `audit.yaml` (decision headers on allow/redact/block/401/429/response path, error body names the rule, record fetched by `X-Tollgate-Event`), `audit.test.ts` (chain verify, tamper → line number, export JSONL/CSV, `/admin/audit/:id`), `admin.test.ts` (`/admin/metrics`, `/admin/policy`, `/admin/feed`, `/admin/coverage`, `/healthz`, `/metrics` shapes, 401 without token, SSE `decision` event), `latency.test.ts` (per-stage numbers, overhead) |
| R6 | Self-testing suite: automated, positive and negative cases | M6 (harness, runner, reporter, skip logic), M7 (generated cases) | §11 (fixture format, runner, summary table, other test files), §12.3 (generated cases) | `runner.test.ts` over all `tests/cases/**/*.yaml` (every file has ≥ 1 allow and ≥ 1 block/redact case per control), `tests/.last-report.json`, `bun run test:fast` |

| # | Deliverable (brief) | Milestone(s) | SPEC section(s) | Proof |
|---|---|---|---|---|
| D1 | The control layer: a functional gateway developers can easily integrate; showcase with an agent; a simple architecture diagram | M1–M4 (+M3b), demo agent M4, diagram M9 | §1 (architecture, ASCII + Mermaid, module layout), §2 (lifecycle), §8 (HTTP API) | the whole suite; `README.md` integration snippets (two settings: `baseURL`, `apiKey`); `docs/ARCHITECTURE.md` + `docs/architecture.png`; `bun run demo` |
| D2 | Sample configuration: documented policy file showing different strictness levels and budget rules | M1 | §4.1 (schema with defaults, presets paragraph), §5 (budget keys) | `policy.yaml` (every key commented), `policy.strict.yaml`, `policy.monitor.yaml`; `policy-schema.test.ts` parses all three; `bun run policy:check` |
| D3 | Simple interactive dashboard: controls, overall security posture, blocked threats, resource consumption / cost | M5 | §10 (routes `/`, `/security`, `/security/events/[id]`, `/policy`, `/coverage`, `/redteam`, `/approvals`, `/playground`), §10.1 posture, §10.2 coverage, §8 `/admin/metrics`, `/admin/events` | `admin.test.ts` (the data the dashboard consumes), `bun run --filter @tollgate/dashboard typecheck`, M5 acceptance in `HANDOFF.md` §5, screenshots in `docs/screenshots/` |
| D4 | Executable test suite, ready to run, verifying controls including budget limits and exploit mitigation | M6 | §11 | `bun test` from a fresh clone (`docs/SUBMISSION.md` §4); `budgets.yaml` and `feed.yaml` are the budget-limit and exploit-mitigation halves the brief names |

Judge behaviours (HANDOFF §2 table) → proof: run the suite (R6/D4); type prompts (`/playground`, §10; `admin.test.ts` playground route); edit `policy.yaml` / feed live (`hotreload.test.ts`, `policy.yaml` fixtures, `feed-control-disabled-allow`); real-time reflection (`policy.loaded` event + `X-Tollgate-Policy` header, `hotreload.test.ts`); telemetry (`/metrics`, `/admin/metrics`, `latency.test.ts`, `bun run bench`); architecture and logs (`docs/ARCHITECTURE.md`, `/security`, `/admin/audit/export`).

## 2. Control coverage check (policy.yaml ↔ coverage map ↔ fixtures)

| `controls.*` key in `policy.yaml` | In coverage map (SPEC §10.2) | Fixture file | Positive case | Negative case |
|---|---|---|---|---|
| `pii` | row 3 | `pii.yaml`, `output.yaml` | `pii-clean-business-text-allow`, `pii-iban-bad-checksum-allow` | `pii-iban-pl-redact` |
| `secrets` | row 3 | `secrets.yaml`, `output.yaml` | `secrets-talk-about-keys-allow` | `secrets-aws-access-key-block` |
| `unicode` | row 1 | `injection.yaml` | `inj-unicode-threshold-raised-allow` | `inj-zero-width-block` |
| `decode` | row 1 | `injection.yaml`, `feed.yaml` | `inj-base64-benign-allow` | `inj-hex-wrapped-block` |
| `prompt_injection` | row 1 | `injection.yaml` | `inj-ordinary-word-ignore-allow` | `inj-direct-override-block` |
| `content_safety` | row 2 | `injection.yaml` (model) | `inj-model-benign-question-allow` | `inj-llamaguard-weapons-block` |
| `canaries` | row 7 | `canaries.yaml` | `canary-in-system-prompt-only-allow` | `canary-in-output-kill-session` |
| `link_exfil` | row 5 | `output.yaml` | `out-link-allowlisted-domain-allow` | `out-link-exfil-markdown-image-redact` |
| `sysprompt` | row 7 | `output.yaml` | `out-sysprompt-paraphrase-allow` | `out-sysprompt-leak-redact` |
| `tool_calls` | row 6 | `tool_calls.yaml` | `tool-call-allowed-passes` | `tool-call-denied-glob-block` |
| `signatures` | rows 4, 5, 6, 10 | `feed.yaml` | `feed-probllama-valid-digest-allow` | `feed-probllama-digest-traversal-block` |
| implicit `auth` | row 8 | `models.yaml` | `auth-dry-run-allowed-no-upstream` | `auth-unknown-key-block` |
| implicit `models` | row 4 | `models.yaml` | `models-allowed-exact-allow` | `models-not-in-allowlist-block` |
| implicit `budget` | row 9 | `budgets.yaml` | `budget-within-limits-allow` | `budget-tokens-per-hour-block` |

Feed entry types (`regex`, `url-pattern`, `pickle-opcode`, `tool-description`, `version-range`) are each handled in SPEC §6.3 and each has a fixture in `feed.yaml` except `version-range`, which never blocks traffic (it is evaluated against `/api/version` and reported; covered by `admin.test.ts` via `/admin/feed.versionMatches` and `/healthz.upstream.ollamaVersion`).

Fixture inventory at the time of writing: 131 cases in 11 files (`pii` 12, `secrets` 12, `injection` 17, `models` 10, `budgets` 11, `feed` 19, `output` 11, `tool_calls` 14, `canaries` 9, `policy` 10, `audit` 6). Every `expect.rule` / `rule_in` / `last_rule` value matches a rule id defined in SPEC; every `sig.<id>` exists in `feeds/ai-exploits.json`; every `policy:` override path exists in `tests/policy.test.yaml`; every `agent` exists in the policy; every `[model]` case has `requires`.

## 3. Fixes applied by the consistency pass (3 Oct 2026)

Rule: `docs/SPEC.md` wins over every other file; `_context.md` wins over SPEC. The pre-SPEC vocabulary in `HANDOFF.md`, `docs/PLAN.md`, `CLAUDE.md` and `README.md` was replaced wholesale; the other files needed targeted edits.

SPEC itself (internal gaps and one `_context`-driven addition):
- Added §2.1 "No-models mode": `SEMANTIC_PROVIDER=ollama|mock|off` (SemanticProvider interface, mock semantics with `SEMANTIC_MOCK_MARKERS`, `TG-MOCK-UNCERTAIN`, `TG-MOCK-JUDGE-BLOCK`) and `UPSTREAM=ollama|echo` (echo upstream, `X-Tollgate-Echo` header). HANDOFF §0 required this and SPEC did not mention it. The test harness now uses the echo upstream instead of a separate `tests/harness/mockUpstream.ts`; `X-Mock-Case` is gone.
- Env-var list completed in the conventions (one spelling, no aliases): `TOLLGATE_*`, `OLLAMA_KEEP_ALIVE`, `SEMANTIC_*`, `UPSTREAM`, `DEMO_MODEL`, `NEXT_PUBLIC_*`, tuning vars.
- Module list: added `cli/validate-policy.ts`, `cli/validate-feed.ts`, `semantic/*`, `upstream/echo.ts`; `packages/policy` now explicitly owns `decision.ts`, `feed.ts`, `testcase.ts` (the "frozen schemas" story in CLAUDE.md/HANDOFF needs them there; SPEC §3 had the record in `apps/gateway/src/types.ts`).
- Runner file name unified to `tests/runner.test.ts` (§1.4 said `runner.test.ts`, §11.2 said `cases.test.ts`); added `semantic-mock.test.ts` and `admin.test.ts` to §11.2 with their contents; `tests/.last-report.json` listed.
- Stage 1: `auth.missing_key` is now a distinct `ruleId` (the fixture `auth-missing-key-block` expected it; SPEC wrote both cases as `auth.unknown_key`).
- Stage 2: budget pre-check order now includes `budget.requests_per_minute` (§5.3 had it, stage 2 did not); `controlId: "budget"`, monitor-mode note.
- Stage 4: `keep_alive` from `OLLAMA_KEEP_ALIVE` on every Ollama call (SETUP.md claimed SPEC covered it).
- Stage 7: output-path hits have `tier: 0` with `direction: response | tool_call` (was unspecified; needed by `X-Tollgate-Tier` assertions).
- §6.1: `published?` and `description?` added to `SignatureEntry` (the shipped feed has them); §6.2 now says 14 entries and names the 7 generic ones; the version-range entry's `action` is `allow` (it is a reporting signal, §6.3 says it never blocks).
- §8: `/healthz.mode`, `POST /admin/playground` gains `session_id` and `echo`; `POST /admin/redteam/run` gains `control` and `max_minutes`; §12 defines the CLI flags (`--minutes`, `--control`, …) that CLAUDE.md promised.
- §10.2: `unicode` and `decode` named explicitly in the first row; a sentence lists every `controls.*` key and the implicit `auth`/`models`/`budget` so the "every control appears in the map" check is literal.
- §11.1: `expect.enforced` added (monitor-mode fixtures need it); `headers` semantics stated; `control` may be `policy` or `audit` for cross-cutting cases; `mock_upstream` → `X-Tollgate-Echo`.
- §12.1 seed format gains the optional `expected` field that §12.1's prose already used.
- §4.1 reference-policy paragraph now lists `finance-agent` and `tests/policy.test.yaml`.

`CLAUDE.md` (rewritten): layout (`budgets.yaml`, `tests/harness`, `tests/cases/generated/`, `policy.test.yaml`, `pricing.json`, presets, `semantic/`, `upstream/echo.ts`), routes (`/admin/events`, `/admin/audit/export`), commands (`test:fast`, `policy:check`, `feed:check`, `audit:verify`, `bench`), record fields (`policyVersion` `p-…`, `tier 0|1|2|null`, `direction`, `enforced`), `semantic.fail_mode` replaces `on_timeout`/`on_error` (default `open`, not `block`), events `policy.loaded`/`policy.rejected`, fixture tags `tags: [model]` + `requires: [<model>]`, the SPEC skip message, streaming baseline "buffered", rule-id vocabulary, reading order incl. SPEC/PLAN/CHECKLIST, track E in the subagent table.

`HANDOFF.md` (rewritten, brief restated in full): §0 aligned to §2.1 (`X-Tollgate-Echo`, M3b, `semantic-mock.test.ts`); §3 decisions use SPEC ids (`models.not_allowed`, `secrets.aws_access_key`, `budget.loop_breaker`, `budget.circuit_open`, `sig.<id>`, `link_exfil.*`, `sysprompt.leak`, `canaries.in_*`, `tool_calls.*`, `session.killed`), SPEC routes, feed fields (`references[]`, `scope`, `severity`, `enabled`, the 14 entry ids), presets as files not commented blocks, `/metrics` text + `/admin/metrics` JSON, uncertain band = tier-1 score band (HANDOFF had "classifiers disagree or soft signals", which contradicted `_context.md`), tier-0 heuristics act (not soft signals); §4 schema list and dashboard contract point at SPEC sections; §5 acceptance checks use the real keys (`tg_demo-agent_…`), `$ADMIN_TOKEN`, SPEC rule ids and routes, M3 split into M3 (mock) + M3b (Ollama adapter), M4 generic entries and `firstBadLine`, M5 routes, M6 eleven fixture files and the SPEC skip message, M7 SPEC §12 mutators / bypass rule / `tests/cases/generated/` (no oracle, no `redteam-found.yaml`), M8 SPEC §13 (`canaries.in_output`, `session.killed`, `/admin/sessions/killed/:id`, no `agent.locked` / `/admin/agents/<id>/unlock`), M9 `docs/screenshots/`, `docs/architecture.png`; §6 track E added; §8 model/effort table kept, M3b included; §10 tags `freeze`, `submission-1/2`.

`docs/PLAN.md` (rewritten): §1 conventions replaced with the SPEC header set (`X-Tollgate-Event`, `-Latency`; no `-Mode`, no `-Latency-Ms`), SPEC status codes, the full SPEC rule-id list (old `model.*`, `secrets.aws_key`, `injection.soft`, `tool.*`, `budget.loop`, `upstream.circuit_open`, `feed.*`, `output.*`, `canary.leak`, `agent.locked`, `judge.*`, `semantic.timeout` removed), SPEC event names on `/admin/events`; M0 (`TOLLGATE_*` env, no `tests` workspace, `.gitignore` content); M1 file list = SPEC §1.4 and §4 (the old M1 schema with `models.prices`, `agents.*.task`, `semantic.on_timeout`, `feed.*`, `output.*` is gone; snake_case `DecisionRecord` → SPEC camelCase; `applies_to`/`source` → `scope`/`references`); M2 file list = SPEC §1.4 controls layout; M3 + M3b with the provider interface and `semantic-mock.test.ts`; M4 feed/audit/coverage routes; M5 SPEC §10 routes; M6 harness names (`tests/harness/*`, not `tests/lib/*`), eleven fixture files, `tests/.last-report.json` (not `last-run.json`), SPEC skip message; M7 SPEC §12 (mutator ids, severity-based bypass, `tests/cases/generated/`, no oracle); M8 SPEC §13; M9 paths; dependency graph and time table include M3b (takes M8's slot if the models land late); cut list updated (mock adapter never cut; M3b over M8); submission checklist paths (`docs/screenshots/*.png`, `submission-1`).

`README.md` (rewritten): real agent keys, SPEC error body (`tollgate_blocked`, `code`, `event_id`), `X-Tollgate-Latency`, policy excerpt with SPEC keys (`fail_mode`, `uncertain_band`, `deny_registries`, agents), presets as three files, coverage table = SPEC §10.2 with fixture pointers, `bun run test:fast` / `--test-name-pattern`, fixture example in SPEC §11.1 format, SPEC skip message, `tests/cases/generated/`, dashboard route list incl. `/coverage` and `/approvals`, feed table with the real entry ids and the generic row, `TOLLGATE_FEED`, streaming limitation as a TODO with both allowed wordings, disclosure section kept.

Other files:
- `.env.example`: `TOLLGATE_PORT/POLICY/FEED/DATA_DIR` are the only spellings (alias block removed); `GUARD_MODEL`/`JUDGE_MODEL` removed (policy owns them); `DASHBOARD_PORT` removed (fixed by `next dev -p 3000`); `OLLAMA_KEEP_ALIVE`, `NEXT_PUBLIC_MOCK` documented.
- `package.json`: `test:fast` replaces `test:deterministic`; `demo` → `apps/gateway/src/demo/agent.ts`; `bench` → `tests/latency.test.ts --bench`; `policy:check` / `feed:check` → `apps/gateway/src/cli/validate-*.ts`; `dev` comment names the two app scripts.
- `.gitignore`: `tests/.last-report.json` ignored; `tests/cases/generated/` named instead of `redteam-found.yaml`; the `slides/*.pdf` rule removed (the deck is `docs/slides.pdf` and must be committed).
- `scripts/doctor.sh`: reads `TOLLGATE_PORT`, `TOLLGATE_POLICY`, `TOLLGATE_FEED`; classifier/judge names are constants with a pointer to `policy.yaml`; "TODO until M1/M4" messages replaced (the files exist).
- `feeds/ai-exploits.json`: `probllama-cve-2024-37032-version.action` → `allow`; the `generic-tool-call-internal-host` description no longer claims `link_exfil.allow_domains` applies to a regex entry.
- `tests/cases/feed.yaml`: case `feed-entry-action-override-redact` renamed `…-block` (it expects `block`).
- `docs/SETUP.md`: judge model via `policy.yaml`, `keep_alive` sentence, `TOLLGATE_*` names, SPEC skip message, `PUT /admin/policy/raw` fallback.
- `docs/ARCHITECTURE.md`: hash is of the canonical parsed policy (not the file bytes); render command targets `docs/architecture.mmd` → `docs/architecture.png`; echo upstream and `SemanticProvider` named; harness paragraph lists the new test files.
- `docs/SLIDES.md`: diagram export path, screenshot names, coverage row wording.
- `docs/SUBMISSION.md`: tag name `submission-1`.
- `docs/DEMO.md`: no-models fallback explains `X-Tollgate-Echo`.

Files added:
- `tests/cases/tool_calls.yaml` (14 cases: allow, deny glob, allowlist, undeclared name, bad JSON, missing required arg, oversize args, approval timeout, approval not required, secret/PII in arguments, invalid definition, denied definition removed, control disabled).
- `tests/cases/canaries.yaml` (9 cases: output leak kill, killed session refuses the next request, tool-call argument leak, untrusted input, tool result, homoglyphed canary, system prompt only, action override `block`, control disabled).
- `tests/cases/policy.yaml` (10 cases: monitor mode would-redact / would-block / would-kill with `enforced: false`, enforce, control disabled, `action: allow`, entity list, entropy threshold, per-agent model list, budget from policy).
- `tests/cases/audit.yaml` (6 cases: headers on allow / block / redact / 401 / 429 / response path; error body names the rule and never echoes the secret).
- `tests/policy.test.yaml` (copy of `policy.yaml` with `version: 1`, `semantic.enabled: false`).
- `docs/CHECKLIST.md` (this file).

## 4. Remaining concerns (not fixable by editing docs)

1. `policy.strict.yaml` deliberately fails some positive fixtures (`redact` expectations become `block`); the suite runs on `tests/policy.test.yaml`, so this only matters if someone points the harness at the strict preset. Stated in the preset header.
2. `tests/cases/injection.yaml` `inj-granite-jailbreak-block` requires `granite3-guardian:2b`, which is optional; it will skip on most machines. Acceptable, but the README must not claim the granite vote is tested unless it ran.
3. The homoglyph canary case (`canary-homoglyph-still-matches`) depends on the fold table containing Cyrillic `а` and `о` and on the two lookalikes staying below `unicode.max_homoglyphs: 3`; if the implementation counts differently, the deciding rule may become `unicode.homoglyph` (block) — the fixture asserts `kill_session`/`canaries.in_input`, so it would surface the discrepancy rather than hide it.
4. `tool-call-denied-glob-block` accepts either `tool_calls.denied` or `tool_calls.schema` because SPEC removes denied definitions on the request side first; the implementation should pick one and the fixture can be tightened at M6.
5. The echo upstream honours `X-Tollgate-Echo` only when `UPSTREAM=echo`; the real upstream path must strip the header. SPEC §11.2 `admin.test.ts` now lists that case; it still has to be written at M6.
6. Time: PLAN's baseline has zero slack and M3b adds 0.5 h; the plan says M3b takes M8's slot if the models land late, and M8 moves to the afternoon window. Checkpoint 2 must confirm this explicitly.
7. `HANDOFF.md` §5 M3 acceptance for `sysprompt.leak` under the mock/echo path needs the playground or `X-Tollgate-Echo` to inject the leaked system prompt; the fixture `out-sysprompt-leak-redact` is the reliable check, the curl one-liner is illustrative.
