# Tollgate — slide outline (10 slides, PDF for HackTribe)

Format: one title, three bullets, one visual per slide. Export with `bunx @marp-team/marp-cli docs/slides.md -o docs/slides.pdf` once this outline is turned into `docs/slides.md` (Marp markdown) in M9. Keep text short; judges read this before they open the repo. No claim on a slide that is not backed by a passing test or a real measurement (the final `ultracode` review checks exactly that).

Visuals come from: dashboard screenshots in `docs/screenshots/` (taken in M9 with real data: `overview.png`, `security.png`, `playground.png`, `policy-reload.png`, `redteam.png`, `coverage.png`), the Mermaid diagrams in `docs/ARCHITECTURE.md` (export to PNG with `bunx @mermaid-js/mermaid-cli -i docs/architecture.mmd -o docs/architecture.png -w 2000` or screenshot the rendered README), and the terminal output of `bun test`.

---

## Slide 1 — The problem: agents are now traffic, and nobody is at the gate

- An agent is a process that reads untrusted text (documents, web pages, tool output) and can act on it: call tools, spend tokens, leak context. Prompt injection, data exfiltration and runaway loops are already real incidents (EchoLeak CVE-2025-32711, ShadowRay, MCP tool poisoning).
- Controls today live inside each app or inside the model vendor. A bank needs them in one place, defined once, enforced on the wire, auditable, and independent of which model or framework a team picked.
- The brief: a lightweight control layer with deterministic AND semantic controls, budgets for paid and local models, historical-attack signatures from an external feed, reporting, and a self-testing suite.

Visual: a simple before/after sketch. Left: three agents each talking straight to a model and to tools, with a red "?" on every line. Right: the same agents, one Tollgate box between them and everything else, one `policy.yaml` icon feeding it.

## Slide 2 — What Tollgate is

- An OpenAI-compatible HTTP proxy (Bun + Hono, port 8787): point any agent's `base_url` at it and change nothing else. Governs model calls and the tool definitions and tool calls inside them.
- One `policy.yaml` is the control catalog: controls, actions (allow / redact / block / kill_session), thresholds, allowed models, budgets, feed source. Hot-reloaded, schema-validated, versioned by content hash.
- Everything runs locally: Ollama models only (`llama-guard3:1b` classifier, `llama3.2:3b` judge and demo agent), SQLite, a hash-chained JSONL audit log, a Next.js dashboard on port 3000.

Visual: the flowchart from `docs/ARCHITECTURE.md` (caller → identity → budget → tier 0 → tier 1 → tier 2 → upstream → output path → caller; side services: policy watcher, feed loader, audit, SQLite, metrics, SSE → dashboard). Full width.

## Slide 3 — Hybrid pipeline and OWASP coverage

- Tier 0, deterministic, < 1 ms: auth and scopes, model allowlist, budget pre-check, Unicode normalisation (invisible characters, homoglyphs), decode-and-rescan (base64 / hex / URL / HTML entities, depth 2), PII and secrets, injection heuristics, signature feed, canaries, tool-definition checks.
- Tier 1, local classifier with a hard timeout and configurable fail-open / fail-closed; tier 2, local LLM judge with a strict JSON verdict, only when tier 1 lands in the uncertain band. Output path: redact, canary, link exfiltration, system-prompt leakage, tool-call gate.
- Every decision carries the deciding tier, rule id, OWASP ids (LLM Top 10 2025 and Agentic Top 10 2026), per-stage latency and the policy hash. Not covered, on purpose: LLM08, LLM09, ASI09.

Visual: the coverage map as a matrix. Rows = controls (`auth`, `models`, `budget`, `unicode` + `decode`, `pii` + `secrets`, `prompt_injection`, `content_safety`, `signatures`, `link_exfil`, `sysprompt` + `canaries`, `tool_calls`). Columns = LLM01–LLM10, ASI01–ASI10. Filled cell = covered; a tier badge (0 / 1 / 2 / out) at the start of each row; the three not-covered columns greyed with a footnote. Use the `/coverage` dashboard screenshot if it reads well at slide size, otherwise a hand-built table.

| Control | Tier | LLM | ASI |
|---|---|---|---|
| prompt_injection (heuristics, classifier, judge), decode, unicode | 0/1/2 | 01 | 01, 10 |
| content_safety | 1 | 01 | — |
| pii, secrets | 0 / out | 02 | — |
| models (allowlist, deny registries), signatures: pickle, version-range | 0 | 03, 04 | 04, 05 |
| link_exfil, signatures: url-pattern (EchoLeak) | out | 05, 02 | 01 |
| tool_calls (schema, allow/deny, approval), ShadowRay signature | out | 06 | 02, 05 |
| sysprompt, canaries | out | 07, 02 | 06 |
| auth (keys, scopes, session kill) | 0 | — | 03, 07 |
| budget (tokens, usd, compute, loop breaker, circuit breaker, tool depth) | 0 | 10 | 08 |
| signatures: tool-description (MCP poisoning) | 0 | 03, 01 | 04, 02 |
| not covered | — | 08, 09 | 09 |

## Slide 4 — Policy engine and live reload

- `policy.yaml` is parsed with a strict zod schema: a misspelt key, a wrong enum, a bad type is rejected with the exact path; the last good version stays active; a `policy.rejected` event shows on the dashboard.
- A save is live on the next request (< 300 ms); every decision records the policy hash, so a judge can edit a rule, resend, and see the hash change on the event. `mode: monitor` evaluates and records everything, forwards unchanged ("would block"); `mode: enforce` acts.
- Strictness is thresholds plus per-control action; three presets ship: standard (`policy.yaml`), `policy.strict.yaml` (everything blocks, fail-closed, small budgets), `policy.monitor.yaml`.

Visual: left, a 12-line excerpt of `policy.yaml` (`mode`, `controls.pii`, `controls.prompt_injection.threshold`, `semantic.fail_mode`, `budgets.default`); right, two dashboard banner screenshots stacked: green `v12 · p-3f9a1c2b · enforce · loaded 2 s ago` and red `rejected: controls.pii.action — expected allow | redact | block | kill_session`.

## Slide 5 — Budgets and resource governance

- Per agent, with a default: tokens per hour, USD per day (from a hot-reloaded `pricing.json`; local models at $0 but metered, with an optional shadow price), compute seconds per hour, requests per minute, max tool depth.
- Pre-checked on an estimate before the model is called; reconciled with the real `usage` after. Over budget → 429 with `Retry-After`, rule id `budget.<window>`, OWASP LLM10 / ASI08.
- Two pattern breakers: loop breaker (same normalised request N times in T → block) and an upstream circuit breaker (fail fast after N errors, half-open probe).

Visual: dashboard screenshot of the spend-by-agent bar chart and the budget-usage bars for `demo-agent`, `research-bot`, `finance-agent`, `test-small-budget`, with the `test-small-budget` bar at 100% and a `429 budget.tokens_per_hour` event next to it.

## Slide 6 — Historical attack feed

- `feeds/ai-exploits.json` is loaded from a file (watched) or a URL (polled), validated, refreshed on an interval: an external security team can ship signatures without touching the gateway.
- Entry types: `regex`, `url-pattern`, `pickle-opcode`, `tool-description`, `version-range`; each carries action, severity, scope (request / response / tool_call / tool_description / model_file), OWASP ids and the public source.
- Shipped entries come from real incidents: JFrog's malicious Hugging Face pickles (2024), nullifAI (2025), ShadowRay CVE-2023-48022, Probllama CVE-2024-37032 (digest and version check), EchoLeak CVE-2025-32711, MCP tool poisoning (CVE-2025-54136), plus generic reverse-shell / `curl | sh` / SSRF-to-metadata patterns.

Visual: a six-row table: incident → what happened (one clause) → the signature Tollgate checks (one clause) → feed entry id. Below it, one line of the feed JSON for `shadowray-cve-2023-48022`.

## Slide 7 — Reporting and audit

- Management view: posture score with its breakdown, requests and blocks (5 min), blocks over time by decision, spend and tokens per agent, p50/p95 latency per stage, policy banner.
- Security view: filterable event table (agent, decision, tier, rule, OWASP id, direction, time), event detail with redacted excerpts and the per-stage latency bar, JSONL / CSV export, "add as test case", approval queue for gated tool calls.
- Audit log: append-only JSONL, each line carries the SHA-256 of the previous line; `GET /admin/audit/verify` and `bun run audit:verify` find the first tampered line. Secrets are masked before they reach the writer.

Visual: two dashboard screenshots side by side, management overview (`/`) and security table (`/security`), with a small terminal strip underneath: `bun run audit:verify → OK 1 842 lines, head 9f3c…` then after `sed` on line 5 → `BROKEN at line 5: hash mismatch`.

## Slide 8 — Test suite and the Red Team Loop

- `bun test`: YAML fixtures under `tests/cases/`, one file per control, every case tagged with control id and OWASP ids, at least one positive (must pass untouched) and one negative (must block / redact) per control; hot-reload, invalid-policy, feed-reload, budget-exhaustion, audit-tamper and latency tests. Model-backed cases skip with a visible message when Ollama is absent; exit code stays 0.
- Red Team Loop: ~40 seed attacks (own, plus garak and promptfoo corpora with attribution) × mutation chains (base64, hex, URL, leetspeak, homoglyphs, zero-width, case, role-play, markdown / JSON wrapping, payload split, prefix padding, multi-turn) against the live policy, as a dry-run agent.
- Every bypass is written to `tests/cases/generated/` as a failing fixture, with the seed, mutators and policy hash; bypass rate per control is shown on the dashboard and feeds the posture score. The suite grows from real bypasses, not hand-written guesses.

Visual: the `bun test` summary table (control | pass | fail | skip | OWASP, then by-OWASP line and TOTAL) as a terminal screenshot, and next to it the `/redteam` panel with attempts / bypasses / bypass rate per control from the overnight run. <!-- TODO(M7/M9): real numbers only -->

## Slide 9 — Telemetry and performance

- Per-stage timers (auth, budget, tier 0, tier 1, tier 2, upstream, output) with p50 / p95 / p99, throughput, and overhead = total − upstream, on the dashboard, on `GET /metrics` (Prometheus text) and in the `X-Tollgate-Latency` response header.
- Measured on an M1 Max, single Bun process: tier 0 p95 <!-- TODO: n ms -->, gateway overhead for tier-0 decisions p50 / p95 <!-- TODO -->, tier 1 (`llama-guard3:1b`) p50 / p95 <!-- TODO -->, tier 2 judge p95 <!-- TODO -->, throughput on the tier-0 path <!-- TODO req/s --> (`bun run bench`).
- The cascade is the performance story: most requests are decided at tier 0 or 1; the judge's seconds are paid only in the uncertain band. Audit writes are off the request path.

Visual: a horizontal bar chart of p50 and p95 per stage (log scale on the x-axis so tier 0 and tier 2 fit) from the dashboard's latency panel, plus a one-line "share of requests decided per tier" strip.

## Slide 10 — Limitations and next steps

- Honest limits: semantic controls are bounded by 1B / 3B local models and the bypass rate is published; streaming redaction is <!-- TODO(M3): buffered | sliding 64-char buffer -->; the dashboard sends the admin token from the browser (demo only); single node with SQLite; the audit chain is tamper-evident, not tamper-proof (ship the head hash off-host); LLM08, LLM09, ASI09 are not covered.
- Next: a stdio / HTTP MCP proxy with manifest pinning (hash tool definitions at approval, alert on rug pulls); model-file scanning (`POST /admin/scan/model`, pickle opcodes including the nullifAI broken-archive case); taint tracking from untrusted tool output into privileged tool arguments; a swappable semantic provider behind `semantic.provider`.
- To run it: `./scripts/setup.sh --wait-models`, `bun run dev`, `bun test`. Repo link, licence (MIT), AI-use disclosure in the README.

Visual: a two-column card, "Known limits" / "Next", and the repo QR code or URL at the bottom with the three commands in a monospace box.
