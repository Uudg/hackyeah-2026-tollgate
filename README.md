# Tollgate — AI Control Layer

**One policy file between your agents and their models: deterministic checks in under a millisecond, local-model judgement where it is needed, budgets, a hash-chained audit log, and a test suite that attacks itself.**

![Tollgate dashboard: overview](docs/screenshots/overview.png)

Tollgate is a drop-in control layer for AI traffic. It is an OpenAI-compatible HTTP proxy: point any agent, app or framework at `http://localhost:8787/v1` instead of the model, and every request and response passes through a policy defined in one file, `policy.yaml`. The policy is hot-reloaded; invalid edits are rejected and the last good version stays active.

What it enforces, from a single policy file:

- **Deterministic controls** (sub-millisecond): per-agent API keys and scopes, model allowlist, PII and secret detection with redact/block, invisible-Unicode and homoglyph normalisation, decode-and-rescan of base64/hex/URL/HTML-entity payloads, tool-definition and tool-call checks with allow/deny lists and approval gates.
- **Semantic controls** (local models only): Llama Guard 3 as a tier-1 classifier with a hard timeout and configurable fail-open/fail-closed; a small local LLM judge as tier 2, called only when tier 1 is uncertain.
- **Budgets**: tokens per hour, USD per day (price table, local models at $0 but metered), compute seconds, requests per minute, max tool depth, a loop breaker and an upstream circuit breaker — per agent and by default.
- **Historical attack signatures** from an externally managed feed (`feeds/ai-exploits.json`, file or URL, refreshed on an interval) covering real incidents: malicious pickles in Hugging Face models, nullifAI, ShadowRay, Probllama, EchoLeak, MCP tool poisoning.
- **Output controls**: PII/secret redaction, canary-secret detection, link exfiltration (EchoLeak pattern), system-prompt leakage, tool-call schema and approval gating.
- **Audit and reporting**: a hash-chained JSONL audit log, SQLite event store, exportable JSONL/CSV, `/metrics` (Prometheus) and `/admin/metrics` (JSON), and a dashboard with a management view and a security view.
- **Self-testing**: `bun test` runs YAML fixtures with positive and negative cases for every control, plus a Red Team Loop that mutates seed attacks against the live policy and turns every bypass into a failing test case.

Built solo at HackYeah 2026 (Kraków, 3–4 Oct 2026) for the Goldman Sachs "AI Control Layer" partner task. No cloud APIs anywhere; every model call goes to a local Ollama.

---

## Quickstart (3 commands)

Requirements: macOS or Linux, Homebrew (macOS), Node 20+ for the Next.js dashboard, ~6 GB disk for models. `setup.sh` installs Bun and Ollama if they are missing and asks for nothing else.

```sh
./scripts/setup.sh --wait-models   # installs bun + ollama, pulls llama3.2:3b + llama-guard3:1b (+ granite3-guardian:2b), bun install, writes .env with a generated ADMIN_TOKEN
bun run dev                        # gateway on http://localhost:8787, dashboard on http://localhost:3000
bun test                           # the self-testing suite, in a second terminal
```

Then send a request through the gateway exactly as you would to OpenAI (the key is `agents.demo-agent.key` in `policy.yaml`):

```sh
curl -si localhost:8787/v1/chat/completions \
  -H 'Authorization: Bearer tg_demo-agent_7f3kQ9mZp2xLw8Rv4Nb6' -H 'content-type: application/json' \
  -d '{"model":"llama3.2:3b","messages":[{"role":"user","content":"Pay invoice to PL61 1090 1014 0000 0712 1981 2874"}]}'
```

Response (here with `UPSTREAM=echo`, which answers `OK: <the message it received>`, so you see exactly what the model was sent):

```
HTTP/1.1 200 OK
X-Tollgate-Decision: redact
X-Tollgate-Rule: pii.iban
X-Tollgate-Tier: 0
X-Tollgate-Policy: p-275f88aacc7b
X-Tollgate-Event: 01M41M99XD9MRZE7WAGWR0Z62G
X-Tollgate-Latency: auth=0.17;budget=0.62;tier0=0.22;tier1=204.58;tier2=852.44;upstream=0.11;output=0.72;total=1059.55

{"id":"chatcmpl-echo-d6727536","object":"chat.completion","model":"llama3.2:3b",
 "choices":[{"index":0,"message":{"role":"assistant","content":"OK: Pay invoice to [REDACTED:iban]"},"finish_reason":"stop"}], ...}
```

The IBAN never left the gateway. This request also shows the judge at work: Llama Guard 1B flagged the payment as "S1 violent crimes", and the judge overturned it in 0.85 s (`tier2=852`). `GET /admin/audit/<X-Tollgate-Event>` returns the full decision record.

`bun run demo` runs a scripted walkthrough through the live gateway: clean pass, PII redact, base64-wrapped injection block, reverse shell in a tool call (feed signature), loop breaker, and a poisoned document that makes the agent leak a planted canary key (session killed, next request on that session refused). It prints `scenario | decision | rule | tier | ms`.

**No models yet?** `setup.sh` without `--wait-models` starts the pulls in the background and the stack runs in no-models mode (`SEMANTIC_PROVIDER=mock`, `UPSTREAM=echo` in `.env`): all deterministic controls, budgets, the feed, audit, dashboard and the deterministic tests work; model-backed tests print `SKIP (model-backed): …` and the exit code stays 0. `./scripts/doctor.sh` shows when the models have landed; then set both variables to `ollama`.

Full setup notes and troubleshooting: [`docs/SETUP.md`](docs/SETUP.md).

---

## Architecture

![Tollgate architecture](docs/architecture.png)

Source: [`docs/architecture.mmd`](docs/architecture.mmd) (Mermaid). The same pipeline as text:

```
 agent / app ──bearer key──▶ ┌────────────────────────── Tollgate :8787 ──────────────────────────┐
                             │ identity  key → agent, scopes, session · model allowlist            │
                             │ budget    tokens/h · usd/day · compute/h · req/min · depth · loop    │
                             │ tier 0    deterministic (<1 ms): normalise · decode-and-rescan      │
                             │           PII/secrets · injection heuristics · signatures · canaries│
                             │ tier 1    classifier (llama-guard3:1b, timeout, fail_mode)          │
                             │ tier 2    LLM judge (llama3.2:3b, strict JSON, only if uncertain)   │
                             │ ───────────────── clean traffic only ─────────────────▶ Ollama :11434│
                             │ output    redact PII/secrets · canaries · link exfil · prompt leak  │
                             │           signatures · tool-call schema/allow-deny/approval         │
                             │ side      policy.yaml hot reload (zod) · feed loader · SQLite       │
                             │           hash-chained audit.jsonl · /metrics · SSE /admin/events   │
                             └──────────────────────────────────────────────────────────────────────┘
                                                                     │ HTTP + SSE
                                                           dashboard :3000 (Next.js)
```

Most requests are decided in tier 0 or tier 1; only ambiguous ones pay for the LLM judge. Every decision records the tier that decided it, the rule id, the OWASP ids, per-stage latency, the policy version hash and the feed version hash. Mermaid flowchart and sequence diagram: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

Monorepo layout:

```
apps/gateway        Bun + Hono proxy (pipeline, budgets, audit, feed, telemetry, red team, demo agent)
apps/dashboard      Next.js App Router dashboard (reads the gateway over HTTP + SSE only)
packages/policy     zod schemas + loader for policy.yaml, feed entries, decision records, test cases
packages/controls   pure control functions, one file per control, no I/O
tests/cases/*.yaml  fixtures, grouped by control; tests/redteam/seeds for the fuzzer; tests/cases/generated for found bypasses
policy.yaml         the control catalog; policy.strict.yaml and policy.monitor.yaml are the other two presets
pricing.json        per-model prices (hot-reloaded); local models at $0, plus one labelled shadow price (demo-paid-model) for the USD-budget demo
feeds/ai-exploits.json  the signature feed
```

Technical contract (routes, schemas, record shapes, rule ids): [`docs/SPEC.md`](docs/SPEC.md).

---

## Controls and OWASP coverage

The same table is served live at `GET /admin/coverage` and rendered at `/coverage` in the dashboard with the current `enabled`/`action` per control and the red-team bypass rate.

| Control(s) | Tier | OWASP LLM Top 10 (2025) | OWASP Agentic Top 10 (2026) | Fixtures |
|---|---|---|---|---|
| `prompt_injection` (heuristics, classifier, judge), `decode` (decode-and-rescan), `unicode` (invisible chars, homoglyphs) | 0 / 1 / 2 | LLM01 | ASI01, ASI10 | `tests/cases/injection.yaml` |
| `content_safety` (Llama Guard categories, confirmed by the judge) | 1 / 2 | LLM01 | — | `injection.yaml` (model-tagged), `semantic-mock.test.ts` |
| `pii`, `secrets` | 0 / output | LLM02 | — | `pii.yaml`, `secrets.yaml`, `output.yaml` |
| `models` (allowlist, deny registries), `signatures` pickle-opcode and version-range entries | 0 | LLM03, LLM04 | ASI04, ASI05 | `models.yaml`, `feed.yaml` |
| `link_exfil`, `signatures` url-pattern (EchoLeak) | output | LLM05, LLM02 | ASI01 | `output.yaml`, `feed.yaml` |
| `tool_calls` (schema, allow/deny, approval), ShadowRay signature | output | LLM06 | ASI02, ASI05 | `tool_calls.yaml`, `feed.yaml` |
| `sysprompt`, `canaries` | output | LLM07, LLM02 | ASI06 | `output.yaml`, `canaries.yaml` |
| `auth` (per-agent keys, scopes, session kill), memory namespaces | 0 | — | ASI03, ASI07 | `models.yaml`, `canaries.yaml` |
| `budget` (tokens, usd, compute, requests, loop breaker, circuit breaker, tool depth) | 0 | LLM10 | ASI08 | `budgets.yaml` |
| `signatures` tool-description (MCP tool poisoning) | 0 | LLM03, LLM01 | ASI04, ASI02 | `feed.yaml` |
| Not covered | — | LLM08, LLM09 | ASI09 | — |

Where the code differs from `docs/SPEC.md` (and why) is listed in [SPEC §16](docs/SPEC.md#16-implementation-notes-and-deviations-from-this-document), with a test for each row.

Not covered, by design: **LLM08** (vector/embedding internals), **LLM09** (misinformation), **ASI09** (human-agent trust manipulation at the UI level). Tollgate sits on the wire; these need application-level controls.

---

## The policy file

`policy.yaml` is the single source of truth. It is watched; a save is validated against a strict zod schema (unknown keys are errors) and loaded within a second. A broken file is rejected with the error path (`policy.rejected` event), and the previous version stays active. Every decision carries `policyVersion` (`p-` + 12 hex of the parsed policy), so a judge can edit a rule, resend a request, and see the hash change on the dashboard.

Excerpt (every key is documented inline in the file):

```yaml
version: 12
mode: enforce                  # monitor (evaluate + record, forward unchanged) | enforce

agents:
  demo-agent:   { key: tg_demo-agent_…, scopes: [chat, tools, dry_run] }
  finance-agent: { key: tg_finance-agent_…, scopes: [chat, tools], models: ["llama3.2:3b"] }

models:
  allow: ["llama3.2:3b", "llama3.2:*", "qwen2.5:*", "llama-guard3:1b"]
  deny_registries: ["*"]       # no host/ns/name model names (Probllama vector)

controls:
  pii:              { action: redact, entities: [email, phone, iban, card, pesel] }
  secrets:          { action: block,  entropy_min: 3.5 }
  prompt_injection: { action: block,  threshold: 0.80, heuristics: true }
  canaries:         { action: kill_session }
  link_exfil:       { action: redact, allow_domains: [intranet.example.com], min_query_len: 20 }
  tool_calls:       { deny: ["delete_*", "shell"], require_approval: [send_email, transfer_funds] }
  signatures:       { feed: ./feeds/ai-exploits.json, refresh: 60s, fail_mode: open }

semantic:
  provider: local              # Ollama only
  fail_mode: open              # open: continue and record semantic.unavailable; closed: block
  timeout_ms: 1500
  uncertain_band: [0.30, 0.80] # tier-1 scores here go to the tier-2 judge

budgets:
  default:   { tokens_per_hour: 50000, usd_per_day: 2.00, compute_seconds_per_hour: 600, max_tool_depth: 8 }
  agents:
    research-bot: { tokens_per_hour: 200000, compute_seconds_per_hour: 1800 }
  loop_breaker: { same_request_within: 30s, max_repeats: 5 }
```

Strictness levels ship as three complete files with the same schema: `policy.yaml` (standard: PII redacted, secrets blocked, fail-open), `policy.strict.yaml` (everything blocks, secrets and loops kill the session, fail-closed, budgets cut to a quarter, tool allowlist only), `policy.monitor.yaml` (same controls, nothing enforced, "would block" recorded). `cp policy.strict.yaml policy.yaml` switches in one save. `bun run policy:check` validates a file without starting the gateway.

---

## Running the tests

```sh
bun test                              # everything
bun run test:fast                     # deterministic (model-free) cases only
bun test --test-name-pattern pii      # one control
```

Fixtures are YAML under `tests/cases/`, one file per control, each case tagged with its control id and OWASP ids, with at least one positive (must pass untouched) and one negative (must block/redact) case per control. Model-backed cases carry `tags: [model]` and `requires: [<model>]` and skip with `SKIP (model-backed): needs Ollama at :11434 with <model> — run \`ollama serve\` and \`ollama pull <model>\`` when the models are absent; the exit code stays 0.

```yaml
- id: pii-iban-pl-redact
  control: pii
  owasp: [LLM02]
  tags: [deterministic]
  agent: demo-agent
  input: "Pay the invoice to PL61 1090 1014 0000 0712 1981 2874 by Friday."
  expect: { decision: redact, rule: pii.iban, tier: 0, status: 200, output_not_contains: ["PL61 1090 1014"] }
- id: pii-clean-business-text-allow
  control: pii
  owasp: [LLM02]
  tags: [deterministic]
  input: "Summarise the Q3 revenue memo in three bullets and flag any open risks."
  expect: { decision: allow, status: 200 }
```

The run ends with a summary grouped by control and OWASP id. Current run (M1 Max, Ollama up; `granite3-guardian:2b` not pulled):

```
control             pass  fail  skip   OWASP
audit                  6     0     0   ASI03, LLM02, LLM05, LLM10
auth                   9     0     0   ASI03, LLM06
budget                19     0     0   ASI07, ASI08, LLM06, LLM10
canaries              16     0     0   ASI02, ASI03, ASI06, LLM02, LLM07
content_safety        24     0     0   LLM01
decode                20     0     0   ASI01, LLM01, LLM02
link_exfil            29     0     0   ASI01, ASI02, LLM02, LLM05
models                 9     0     0   ASI03, ASI04, LLM03
pii                   41     0     0   LLM02, LLM05
policy                12     0     0   ASI03, ASI06, LLM01, LLM02, LLM03, LLM10
prompt_injection     101     0     1   ASI01, ASI06, LLM01, LLM07     (1 skipped: model-backed)
secrets               25     0     0   ASI02, LLM01, LLM02
signatures            42     0     0   ASI01, ASI02, ASI03, ASI04, ASI05, LLM01, LLM02, LLM03, LLM04, LLM05, LLM07
sysprompt             27     0     0   ASI02, LLM01, LLM02, LLM07
tool_calls            21     0     0   ASI02, ASI05, ASI08, LLM02, LLM05, LLM06
unicode               11     0     0   LLM01, LLM02
TOTAL  412 pass · 0 fail · 1 skip   in 46.1 s
known open bypasses (red-team backlog): 318   not run, not counted above; tests/cases/generated/*-open.yaml, run them with TOLLGATE_BACKLOG=1 bun test
```

Whole `bun test` on a fresh clone: 565 pass, 2 skip, 0 fail in ~52 s with Ollama up (fixtures plus the suites below and the controls unit tests). The 318 open red-team cases are reported on their own line and not counted.

Also included: a hot-reload test (edits a temp policy and the feed, asserts the next request uses them), a policy-schema test (the three presets validate, misspelt keys are rejected), a mock-semantic test (tiers 1–2 and fail-open/closed without a model), an audit-chain tamper test, an admin-API shape test, and a latency test (tier-0 overhead vs calling the upstream directly).

### Red Team Loop

```sh
bun run redteam --minutes 30 --control prompt_injection
```

Mutates seed attacks (base64, hex, URL-encoding, leetspeak, homoglyphs, zero-width characters, case shuffle, role-play wrappers, markdown/JSON wrapping, payload splitting, prefix padding, multi-turn; translation and paraphrase only when a model is allowed) against the live policy as a dry-run agent. Every bypass is written to `tests/cases/generated/` as a failing case and shown in the dashboard with a bypass rate per control.

Measured on the shipped `policy.yaml`, all 88 seeds, depth 1 (each mutator alone plus the unmutated seed), `rng_seed 1`, Llama Guard 1B + llama3.2:3b judge on, 4 workers on an M1 Max (~5–8 min per run):

| control | attempts | M7, first run | after M7 fixes | after hardening pass |
|---|---:|---:|---:|---:|
| prompt_injection | 364 | 31.9 % | 19.0 % | 14.8 % |
| content_safety | 126 | 21.4 % | 13.5 % | 12.7 % |
| signatures | 266 | 13.9 % | 12.4 % | 14.3 % |
| tool_calls | 126 | 34.1 % | 34.1 % | 34.1 % |
| sysprompt | 40 → 52 | 77.5 % | 22.5 % | 7.7 % |
| secrets | 66 → 69 | 7.6 % | 7.6 % | 1.4 % |
| link_exfil | 50 | 6.0 % | 6.0 % | 6.0 % |
| pii | 142 → 151 | 4.2 % | 4.2 % | 0.7 % |
| **total** | **1180 → 1204** | **22.7 %** | **15.7 %** | **13.3 %** |

The attempt count grew because encoding mutators now also apply to response seeds (an encoded secret or system prompt in the reply is a leak, so those chains are real attacks). Tier 1/2 rows move by a few points between runs because the local models are not fully deterministic under load.

What the loop found and what changed:
- M7 (SPEC §16, D17–D20): leetspeak, split string fragments and payloads split over several user turns beat tier 0, so these are now decoded and rescanned; URL-encoding blinded the classifier, so tiers 1–2 now also read the decoded text; soft "show me your initial instructions" requests got through, so the prompt-leak signature was widened. The sysprompt "before" figure also includes a harness bug (the system prompt was shorter than the 20-word minimum), fixed in the runner.
- Hardening pass (D23–D27): output-side decode-and-rescan for secrets, PII, canaries and the system prompt; case-insensitive IBAN and AWS keys; PII and secrets on joined user turns; 30+ input-format and normalization fixes; two new injection heuristics and wider feed entries; output-path fixes for links, tool names and extra message fields. An adversarial review then found five quadratic regexes (one 40 kB field froze the gateway for seconds) and several false positives; all fixed with tests (`tests/hardening-review.test.ts`).
- Depth-2 run (D28): stacked obfuscation. Decoded text is now normalized and run through the leetspeak, fragment and URL rewrites again; output links are read after homoglyph folding; joined fragments are checked for exfil links; leetspeak output is checked for PII; a card number right after another number is found. 16 fixtures in `tests/cases/redteam-depth2.yaml`, 4 of them allow cases for false positives.

**Depth 2** (every ordered pair of mutators, 12 922 attempts, same seeds and models, ~63 min): **12.1 %** bypass rate (1 569) before the depth-2 fixes.

| control | attempts | bypasses | rate | caught after D28 (deterministic replay) |
|---|---:|---:|---:|---:|
| prompt_injection | 3952 | 501 | 12.7 % | 25 |
| signatures | 2888 | 334 | 11.6 % | 17 |
| tool_calls | 1368 | 309 | 22.6 % | 1 |
| content_safety | 1368 | 185 | 13.5 % | 5 |
| sysprompt | 556 | 104 | 18.7 % | 67 |
| link_exfil | 410 | 69 | 16.8 % | 51 |
| pii | 1633 | 36 | 2.2 % | 20 |
| secrets | 747 | 31 | 4.2 % | 7 |
| **total** | **12 922** | **1 569** | **12.1 %** | **193 → 10.6 %** |

The "after" column replays the 1 569 bypassing inputs through the fixed code with tier 0 and the output path only; attempts that were blocked before stay blocked, so 1 376 / 12 922 = 10.6 % is the deterministic upper bound. About a quarter of the depth-2 bypasses (383) were not misses: Ollama was saturated by 4 workers, tier 1/2 timed out and `semantic.fail_mode: open` let them through (`policy.strict.yaml` fails closed instead). The rest of what is left: request-side tool intents (the tool call is still checked on the response path), paraphrase-level jailbreaks the 1B classifier misses, and chains where the second mutator corrupts an encoded value (base64 then leetspeak) so a reader cannot decode it either.

Committed results in `tests/cases/generated/`: three `*-fixed.yaml` files (50 + 33 + 36 former bypasses that now pass, kept as regression tests) and two `*-open.yaml` files (154 from depth 1 and a 164-case sample of depth 2, each with a `skip:` reason). The open cases are not counted in the `bun test` totals: the summary prints them on their own line, and `TOLLGATE_BACKLOG=1 bun test` runs them. Remove a `skip:` line to turn a case into a regression test once a fix lands.

---

## Dashboard

| Security events | Red team |
|---|---|
| ![Security events](docs/screenshots/security.png) | ![Red team](docs/screenshots/redteam.png) |
| **Coverage** | **Playground** |
| ![Coverage](docs/screenshots/coverage.png) | ![Playground](docs/screenshots/playground.png) |

`http://localhost:3000`, reading the gateway's `/admin/*` endpoints and the `/admin/events` SSE stream.

- **Overview (management):** posture score with breakdown, requests and blocks (5 min), spend today by agent, p50/p95 latency per stage, blocks over time, policy banner (`v12 · p-a1b2c3d4e5f6 · enforce · loaded 4 s ago`) that flashes on every reload and turns red on a rejected edit.
- **Security:** filterable event table (agent, decision, rule, tier, OWASP id, direction, time), event detail with redacted excerpts and per-stage latency, JSONL/CSV export, audit-chain verify button, "add as test case".
- **Policy:** version timeline, current YAML, validate-and-save editor, controls table with OWASP mapping, feed entries with version matches.
- **Coverage:** the OWASP matrix above with live enabled/action state and bypass rate.
- **Red team:** run controls, live progress, bypass rate per control, generated cases.
- **Approvals:** pending tool calls with Approve/Deny and a countdown.
- **Playground:** send a prompt through the gateway as any agent, with or without tools and a planted canary, and watch each stage's verdict and latency.

A short guide opens on the first visit and walks through the header links one by one; the **Guide** button in the header runs it again.

---

## Telemetry

Per-stage timers (auth, budget, tier 0, tier 1, tier 2, upstream, output) with p50/p95/p99, throughput, and overhead = total − upstream, exposed as:

- `GET /metrics` — Prometheus text
- `GET /admin/metrics` — JSON for the dashboard (also pushed as `metrics.tick` SSE events every 2 s)
- `X-Tollgate-Latency` response header per request (`auth=…;budget=…;tier0=…;tier1=…;tier2=…;upstream=…;output=…;total=…`)

| Stage | p50 | p95 | Notes |
|---|---|---|---|
| tier 0 | 0.48 ms | 2.1 ms | pure TypeScript, no I/O (live gateway, mixed traffic) |
| tier 1 (llama-guard3:1b) | 49 ms | 138 ms | Ollama, model resident (`keep_alive: 30m`) |
| tier 2 (llama3.2:3b judge) | 677 ms | 970 ms | only for uncertain scores and flagged content-safety categories |
| output scan | 0.68 ms | 1.5 ms | |
| gateway overhead vs direct call, tier 0 only | 0.49 ms | 0.78 ms | `bun run bench`, 1000 sequential requests |

`bun run bench` on the M1 Max (echo upstream, semantic tiers off, after the depth-2 fixes): tier-0 stage p50 0.12 ms, p95 0.17 ms; throughput ~1,700 req/s with one client and ~2,050 req/s with 32 concurrent clients, 0 errors. (Before the hardening pass and the depth-2 decoders it was ~2,500 / ~3,400 req/s: the extra decode-and-rescan work costs about 0.2 ms per request.) The model tiers dominate when they run: a clean request adds ~50 ms (tier 1); a flagged one adds ~0.7 s (judge).

---

## Historical attack feed

`feeds/ai-exploits.json` is loaded from a file path or a URL (`controls.signatures.feed`, overridable with `TOLLGATE_FEED`) and refreshed on `controls.signatures.refresh`, so an external team can manage signatures without touching the gateway. Each entry has `id`, `title`, `cve`, `published`, `description`, `type` (`regex` | `url-pattern` | `pickle-opcode` | `tool-description` | `version-range`), `pattern`, `scope`, `action`, `severity`, `owasp`, `references`, `enabled`. A hit is recorded as `sig.<id>`.

| Entry | Incident | What is detected |
|---|---|---|
| `jfrog-hf-pickle-rce-2024` | JFrog, Feb 2024: ~100 Hugging Face models with pickle `__reduce__` reverse shells | pickle opcodes `GLOBAL`/`STACK_GLOBAL` → `os`, `subprocess`, `builtins.exec` … followed by `REDUCE`, in base64 blobs and uploaded model files |
| `nullifai-broken-pickle-2025` | ReversingLabs, Jan 2025: 7z-compressed PyTorch file with a deliberately broken pickle | non-ZIP / non-pickle model archives and truncated opcode streams are blocked, not passed |
| `shadowray-cve-2023-48022` | Ray Jobs API without auth; thousands of clusters compromised | tool calls / requests to port 8265 with the Ray Jobs/cluster API paths |
| `probllama-cve-2024-37032-digest`, `-version` | path traversal in Ollama `/api/pull` digest; fixed 0.1.34 | digest must match `sha256:[a-f0-9]{64}`, `../` rejected; Ollama < 0.1.34 flagged on the posture score |
| `echoleak-cve-2025-32711` | zero-click exfiltration via markdown images in M365 Copilot | markdown images in output or tool-call arguments pointing at non-allowlisted hosts with a long query |
| `mcp-tool-poisoning-2025` | Invariant Labs, Apr 2025; CVE-2025-54136 (Cursor) | hidden instructions, suspicious paths, HTML comments, invisible characters or over-long text in tool descriptions |
| `generic-*` (7 entries) | reverse shells, `curl | sh`, textual pickles, "decode and follow" wrappers, cloud-metadata SSRF, tool calls to internal hosts, prompt-leak phrases, jailbreak persona families | regex on requests, responses and tool-call arguments |

Edit the file while the gateway runs: the next request uses the new entries and carries the new `feedVersion`; the dashboard shows `feed.loaded` with the entry count.

---

## Works with any OpenAI-compatible client

Any OpenAI-compatible client works by changing two values. `examples/openai-sdk.ts` uses the official `openai` npm package with only `baseURL` and `apiKey` changed and sends a clean request, one with an IBAN and one injection:

```sh
bun run example:sdk
```

```
clean     200 allow -  OK: In one sentence, what is a supplier payment batch?
iban      200 redact pii.iban  OK: Refund the client to [REDACTED:iban] and confirm.
injection 403 block inject.heuristic.1  403 Blocked by Tollgate rule inject.heuristic.1
```

(Output with `UPSTREAM=echo`; with Ollama the replies are the model's. `tests/sdk.test.ts` runs the same SDK against an in-process gateway and skips with a message if the package is not installed.)

The same two values in your own code:

```ts
import OpenAI from "openai";
const client = new OpenAI({ baseURL: "http://localhost:8787/v1", apiKey: "tg_research-bot_Ym3dK8pQ2sT6vW9xA1bC" });
```

```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8787/v1", api_key="tg_research-bot_Ym3dK8pQ2sT6vW9xA1bC")
```

The API key identifies the agent (`agents.<id>.key` in `policy.yaml`) and selects its scopes, allowed models and budget. Blocked requests return `403` with `{ error: { type: "tollgate_blocked", code: "<rule id>", message, event_id } }`; budget limits return `429` with `Retry-After`; redacted ones return `200` with the content rewritten and an `X-Tollgate-Decision: redact` header. Tool definitions (`tools[]`) and tool calls in the completion are governed too, which is how agent↔MCP traffic is covered without a separate transport.

---

## Limitations

- Semantic controls are only as good as the local 1B/3B models; the deterministic tier and the Red Team Loop exist because the classifier alone misses things. Bypass rates are reported, not hidden.
- Streaming is buffered: the upstream is called non-streamed, the output path runs on the full completion, then the reply is re-emitted as SSE chunks. No unscanned token ever reaches the client; the cost is time-to-first-token.
- `llama-guard3:1b` over-flags finance text: in our measurement it flagged 5 of 14 ordinary finance prompts (supplier payments and wire transfers as S1/S2, hedging and stock questions as S6). Flagged categories are therefore confirmed by the 3B judge before blocking (`controls.content_safety.confirm_with_judge`, on by default; off in `policy.strict.yaml`). The judge got all 10 of our test cases right (5 false positives overturned, 5 real harms kept blocked), but it is a 3B model and can be wrong both ways.
- The judge is weak against indirect injection: in the demo it sometimes lets a poisoned document through. Canaries are the backstop (the leak is caught and the session killed).
- The dashboard sends the admin token from the browser (`NEXT_PUBLIC_ADMIN_TOKEN`). Fine for a local demo; a deployment would put the dashboard behind SSO and proxy the admin calls server-side. Agent keys never reach the browser (the playground goes through `POST /admin/playground`).
- Budgets are tracked in a single SQLite file; horizontal scale needs a shared store (the ledger interface is one file).
- Model-file scanning (`POST /admin/scan/model`) covers the documented incident patterns, not arbitrary payloads, and is a stretch item. ModelScan or a sandboxed loader is the production answer.
- A generic MCP transport proxy and manifest pinning (rug-pull detection) are stretch items; tool definitions and tool calls inside chat completions are governed.
- `kill_session` is keyed by (agent, session id). An agent that sends a fresh `X-Session-Id` after a kill gets a new session; the agent itself is not frozen. Revoke the agent key (or set its budget to 0) to stop a compromised agent.
- Character-level obfuscation of a value in the model's reply (a secret written letter by letter with spaces, a split IBAN) is only partly caught: output decode-and-rescan covers encodings and case changes, not arbitrary re-spelling. These stay in the red-team backlog.
- The feed entry `generic-tool-call-internal-host` blocks any `file://`, `gopher://` or `dict://` URL in tool-call arguments. An agent that legitimately reads local files through a URL needs that entry's action set to `allow` (or the entry disabled) in its policy.
- Tier 0 joins the user turns without a separator to catch values split across turns, so digits at the end of one turn and the start of the next can form a card or IBAN by chance. That conversation then stays blocked; start a new one.
- Not covered: LLM08, LLM09, ASI09 (see coverage table).
- Single node; no HA. The hash-chained audit log is tamper-evident, not tamper-proof (an attacker with write access to the host can rewrite the whole chain — ship the head hash off-host).

---

## AI and third-party use (disclosure)


**Implementation assistance:** [Claude Code](https://claude.com/claude-code) (Anthropic) was used for planning, scaffolding, code generation, test generation and review during the hackathon: Claude Opus 5.5 (main session: gateway, controls, test suites, acceptance runs, review; subagents: the four hardening-pass tracks) and Claude Sonnet (subagents: dashboard, test fixtures, red-team seeds, UI review, code review of the hardening pass, slides and screenshots). The planning documents (`HANDOFF.md`, `docs/SPEC.md`, `docs/PLAN.md`, `docs/CHECKLIST.md`, `CLAUDE.md`) were written with Claude in the Claude desktop app (Cowork): Claude Sonnet 5.5, with Claude Fable 5.1 subagents drafting files. The design system in `design/` was made there with Claude Opus 5.5. All code was reviewed and is explainable by the author.

**Local models (via Ollama):**

| Model | Role | Licence |
|---|---|---|
| `llama3.2:3b` | demo agent, tier-2 judge | Llama 3.2 Community License |
| `llama-guard3:1b` | tier-1 safety classifier | Llama 3.2 Community License |
| `granite3-guardian:2b` (optional) | jailbreak classifier (second vote) | Apache 2.0 |

**Attack corpora:** seed prompts in `tests/redteam/seeds/` are adapted from [garak](https://github.com/NVIDIA/garak) (Apache 2.0) and [promptfoo](https://github.com/promptfoo/promptfoo) (MIT), with attribution in each file. The historical-attack feed entries cite their public sources (JFrog, ReversingLabs, Oligo, Wiz, NVD, The Hacker News, Aim Security, Invariant Labs / Cloud Security Alliance).

**Referenced but not used in the critical path:** Presidio (MIT), ModelScan (Apache 2.0), Prompt Guard 2 (Llama licence), LlamaFirewall paper (Meta). LLM Guard (archived July 2026) and LiteLLM enterprise features were deliberately not used; the pipeline and budget engine are written from scratch in TypeScript.

**Docs tooling (run once, not dependencies):** Marp CLI (MIT) rendered `docs/slides.pdf` from `docs/SLIDES.md`; mermaid-cli (MIT) rendered `docs/architecture.png` from `docs/architecture.mmd`.

**npm dependencies:**

| Package | Licence | Used for |
|---|---|---|
| hono | MIT | gateway HTTP framework |
| openai (dev) | Apache 2.0 | `examples/openai-sdk.ts` and `tests/sdk.test.ts` only, proves SDK compatibility |
| zod | MIT | schema validation at every boundary |
| yaml | ISC | policy and fixture parsing |
| next, react, react-dom | MIT | dashboard |
| tailwindcss, @tailwindcss/postcss | MIT | dashboard styling |
| eslint, eslint-config-next | MIT | dashboard lint |
| typescript, @types/bun, @types/node, @types/react, @types/react-dom | Apache 2.0 / MIT | toolchain |

---

## Licence

MIT, see [LICENSE](LICENSE).
