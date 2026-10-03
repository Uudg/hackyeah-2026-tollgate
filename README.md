# Tollgate — AI Control Layer

<!-- TODO(submit): one-line tagline + docs/screenshots/overview.png -->

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

<!-- TODO(M2): paste the actual response showing [REDACTED:iban] and the headers X-Tollgate-Decision: redact, X-Tollgate-Rule: pii.iban, X-Tollgate-Tier: 0, X-Tollgate-Policy: p-… -->

`bun run demo` runs a scripted walkthrough: clean pass, PII redact, base64-wrapped injection block, canary kill, budget loop.

**No models yet?** `setup.sh` without `--wait-models` starts the pulls in the background and the stack runs in no-models mode (`SEMANTIC_PROVIDER=mock`, `UPSTREAM=echo` in `.env`): all deterministic controls, budgets, the feed, audit, dashboard and the deterministic tests work; model-backed tests print `SKIP (model-backed): …` and the exit code stays 0. `./scripts/doctor.sh` shows when the models have landed; then set both variables to `ollama`.

Full setup notes and troubleshooting: [`docs/SETUP.md`](docs/SETUP.md).

---

## Architecture

<!-- TODO(M9): add docs/architecture.png exported from docs/architecture.mmd; keep the ASCII version for terminals -->

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
pricing.json        per-model prices (hot-reloaded)
feeds/ai-exploits.json  the signature feed
```

Technical contract (routes, schemas, record shapes, rule ids): [`docs/SPEC.md`](docs/SPEC.md).

---

## Controls and OWASP coverage

The same table is served live at `GET /admin/coverage` and rendered at `/coverage` in the dashboard with the current `enabled`/`action` per control and the red-team bypass rate.

| Control(s) | Tier | OWASP LLM Top 10 (2025) | OWASP Agentic Top 10 (2026) | Fixtures |
|---|---|---|---|---|
| `prompt_injection` (heuristics, classifier, judge), `decode` (decode-and-rescan), `unicode` (invisible chars, homoglyphs) | 0 / 1 / 2 | LLM01 | ASI01, ASI10 | `tests/cases/injection.yaml` |
| `content_safety` (Llama Guard categories) | 1 | LLM01 | — | `injection.yaml` (model-tagged) |
| `pii`, `secrets` | 0 / output | LLM02 | — | `pii.yaml`, `secrets.yaml`, `output.yaml` |
| `models` (allowlist, deny registries), `signatures` pickle-opcode and version-range entries | 0 | LLM03, LLM04 | ASI04, ASI05 | `models.yaml`, `feed.yaml` |
| `link_exfil`, `signatures` url-pattern (EchoLeak) | output | LLM05, LLM02 | ASI01 | `output.yaml`, `feed.yaml` |
| `tool_calls` (schema, allow/deny, approval), ShadowRay signature | output | LLM06 | ASI02, ASI05 | `tool_calls.yaml`, `feed.yaml` |
| `sysprompt`, `canaries` | output | LLM07, LLM02 | ASI06 | `output.yaml`, `canaries.yaml` |
| `auth` (per-agent keys, scopes, session kill), memory namespaces | 0 | — | ASI03, ASI07 | `models.yaml`, `canaries.yaml` |
| `budget` (tokens, usd, compute, requests, loop breaker, circuit breaker, tool depth) | 0 | LLM10 | ASI08 | `budgets.yaml` |
| `signatures` tool-description (MCP tool poisoning) | 0 | LLM03, LLM01 | ASI04, ASI02 | `feed.yaml` |
| Not covered | — | LLM08, LLM09 | ASI09 | — |

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

The run ends with a summary grouped by control and OWASP id. <!-- TODO(M6): paste the summary table -->

Also included: a hot-reload test (edits a temp policy and the feed, asserts the next request uses them), a policy-schema test (the three presets validate, misspelt keys are rejected), a mock-semantic test (tiers 1–2 and fail-open/closed without a model), an audit-chain tamper test, an admin-API shape test, and a latency test (tier-0 overhead vs calling the upstream directly).

### Red Team Loop

```sh
bun run redteam --minutes 30 --control prompt_injection
```

Mutates seed attacks (base64, hex, URL-encoding, leetspeak, homoglyphs, zero-width characters, case shuffle, role-play wrappers, markdown/JSON wrapping, payload splitting, prefix padding, multi-turn; translation and paraphrase only when a model is allowed) against the live policy as a dry-run agent. Every bypass is written to `tests/cases/generated/` as a failing case and shown in the dashboard with a bypass rate per control. <!-- TODO(M7): numbers from the overnight run -->

---

## Dashboard

<!-- TODO(M5): screenshots in docs/screenshots/ -->

`http://localhost:3000`, reading the gateway's `/admin/*` endpoints and the `/admin/events` SSE stream.

- **Overview (management):** posture score with breakdown, requests and blocks (5 min), spend today by agent, p50/p95 latency per stage, blocks over time, policy banner (`v12 · p-a1b2c3d4e5f6 · enforce · loaded 4 s ago`) that flashes on every reload and turns red on a rejected edit.
- **Security:** filterable event table (agent, decision, rule, tier, OWASP id, direction, time), event detail with redacted excerpts and per-stage latency, JSONL/CSV export, audit-chain verify button, "add as test case".
- **Policy:** version timeline, current YAML, validate-and-save editor, controls table with OWASP mapping, feed entries with version matches.
- **Coverage:** the OWASP matrix above with live enabled/action state and bypass rate.
- **Red team:** run controls, live progress, bypass rate per control, generated cases.
- **Approvals:** pending tool calls with Approve/Deny and a countdown.
- **Playground:** send a prompt through the gateway as any agent, with or without tools and a planted canary, and watch each stage's verdict and latency.

---

## Telemetry

<!-- TODO(M9): real numbers from the M1 Max with models loaded -->

Per-stage timers (auth, budget, tier 0, tier 1, tier 2, upstream, output) with p50/p95/p99, throughput, and overhead = total − upstream, exposed as:

- `GET /metrics` — Prometheus text
- `GET /admin/metrics` — JSON for the dashboard (also pushed as `metrics.tick` SSE events every 2 s)
- `X-Tollgate-Latency` response header per request (`auth=…;budget=…;tier0=…;tier1=…;tier2=…;upstream=…;output=…;total=…`)

| Stage | p50 | p95 | Notes |
|---|---|---|---|
| tier 0 | TODO | TODO | pure TypeScript, no I/O |
| tier 1 (llama-guard3:1b) | TODO | TODO | Ollama, model resident |
| tier 2 (llama3.2:3b judge) | TODO | TODO | only in the uncertain band |
| output scan | TODO | TODO | |
| gateway overhead vs direct call | TODO | TODO | `bun run bench` |

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

## Integrating Tollgate

Any OpenAI-compatible client works by changing two values:

```ts
import OpenAI from "openai";
const client = new OpenAI({ baseURL: "http://localhost:8787/v1", apiKey: "tg_research-bot_Ym3dK8pQ2sT6vW9xA1bC" });
```

```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8787/v1", api_key="tg_research-bot_Ym3dK8pQ2sT6vW9xA1bC")
```

The API key identifies the agent (`agents.<id>.key` in `policy.yaml`) and selects its scopes, allowed models and budget. Blocked requests return `403` with `{ error: { type: "tollgate_blocked", code: "<rule id>", message, event_id } }`; budget limits return `429` with `Retry-After`; redacted ones return `200` with the content rewritten and an `X-Tollgate-Decision: redact` header. Tool definitions (`tools[]`) and tool calls in the completion are governed too, which is how agent↔MCP traffic is covered without a separate transport. <!-- TODO(M1): verify snippets against the running gateway -->

---

## Limitations

<!-- TODO(M9): review before submission; be honest, judges are security people -->

- Semantic controls are only as good as the local 1B/3B models; the deterministic tier and the Red Team Loop exist because the classifier alone misses things. Bypass rates are reported, not hidden.
- Streaming: <!-- TODO(M3): "buffered — the upstream reply is scanned in full and re-emitted as SSE chunks" or "sliding 64-character buffer; a redaction can straddle two chunks" -->.
- The dashboard sends the admin token from the browser (`NEXT_PUBLIC_ADMIN_TOKEN`). Fine for a local demo; a deployment would put the dashboard behind SSO and proxy the admin calls server-side. Agent keys never reach the browser (the playground goes through `POST /admin/playground`).
- Budgets are tracked in a single SQLite file; horizontal scale needs a shared store (the ledger interface is one file).
- Model-file scanning (`POST /admin/scan/model`) covers the documented incident patterns, not arbitrary payloads, and is a stretch item. ModelScan or a sandboxed loader is the production answer.
- A generic MCP transport proxy and manifest pinning (rug-pull detection) are stretch items; tool definitions and tool calls inside chat completions are governed.
- Not covered: LLM08, LLM09, ASI09 (see coverage table).
- Single node; no HA. The hash-chained audit log is tamper-evident, not tamper-proof (an attacker with write access to the host can rewrite the whole chain — ship the head hash off-host).

---

## AI and third-party use (disclosure)

<!-- TODO(M9): keep this exact and complete; the rules require disclosure and the team must be able to explain every part -->

**Implementation assistance:** [Claude Code](https://claude.com/claude-code) (Anthropic) was used for planning, scaffolding, code generation, test generation and review during the hackathon <!-- TODO(M9): list the exact models used, e.g. Claude Opus 5.5 for the gateway core, tests and review; Claude Sonnet for the dashboard, fixtures and red-team seeds; Claude Fable 5.1 for the planning documents -->. All code was reviewed and is explainable by the author.

**Local models (via Ollama):**

| Model | Role | Licence |
|---|---|---|
| `llama3.2:3b` | demo agent, tier-2 judge | Llama 3.2 Community License |
| `llama-guard3:1b` | tier-1 safety classifier | Llama 3.2 Community License |
| `granite3-guardian:2b` (optional) | jailbreak classifier (second vote) | Apache 2.0 |

**Attack corpora:** seed prompts in `tests/redteam/seeds/` are adapted from [garak](https://github.com/NVIDIA/garak) (Apache 2.0) and [promptfoo](https://github.com/promptfoo/promptfoo) (MIT), with attribution in each file. The historical-attack feed entries cite their public sources (JFrog, ReversingLabs, Oligo, Wiz, NVD, The Hacker News, Aim Security, Invariant Labs / Cloud Security Alliance).

**Referenced but not used in the critical path:** Presidio (MIT), ModelScan (Apache 2.0), Prompt Guard 2 (Llama licence), LlamaFirewall paper (Meta). LLM Guard (archived July 2026) and LiteLLM enterprise features were deliberately not used; the pipeline and budget engine are written from scratch in TypeScript.

**npm dependencies:**

| Package | Licence | Used for |
|---|---|---|
| hono | MIT | gateway HTTP framework |
| zod | MIT | schema validation at every boundary |
| yaml | ISC | policy and fixture parsing |
| next, react, react-dom | MIT | dashboard |
| typescript, @types/bun | Apache 2.0 / MIT | toolchain |
| <!-- TODO(M9): every dependency added during the build, from `bun pm ls` --> | | |

---

## Licence

MIT. <!-- TODO(M0): add LICENSE file -->
