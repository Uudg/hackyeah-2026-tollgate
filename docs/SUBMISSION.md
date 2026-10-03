# Tollgate — HackTribe submission pack

Everything that goes into the HackTribe form, ready to paste. Deadline: Sunday 4 Oct 2026; the rules say "11:00 PM October 4th" but other tracks say 11:00 — submit by 11:00 CEST, then resubmit (if the platform allows editing) with the final numbers before 23:00. Submit an hour before whichever deadline is in force; the form may be slow.

Before pasting anything, run the fresh-clone check from the bottom of this file on a clean folder. The description below makes claims; every one of them must be true at submission time. Remove a sentence rather than leave an unbacked claim.

## 1. Form fields

| Field | Value |
|---|---|
| Project title | Tollgate — AI Control Layer |
| Task | Partner task: Goldman Sachs — AI Control Layer |
| Team name | <!-- TODO: team name as registered on HackTribe --> |
| Members | Danil Pankrashkin (solo) <!-- TODO: add anyone else registered on this entry --> |
| Language | English |
| Description | section 2 below |
| Presentation (PDF, ≤ 10 slides) | `docs/slides.pdf` (built in M9 from `docs/SLIDES.md`; check the page count is ≤ 10 with `mdls -name kMDItemNumberOfPages docs/slides.pdf` or in Preview) |
| Repository | <!-- TODO: public GitHub URL; make the repo public before submitting; confirm the default branch is `main` and the last commit is tagged --> |
| Demo link | none (everything is local by design; say so in the description) |
| Screenshots | `docs/screenshots/overview.png`, `security.png`, `playground.png`, `policy-reload.png`, `redteam.png`, `coverage.png` — taken in M9 with real data, 1600 px wide |
| AI tools disclosure | section 3 below (also in README "AI and third-party use") |

Checklist before pressing submit:

- [ ] `git clone` + `./scripts/setup.sh --wait-models` + `bun run dev` + `bun test` works on a clean folder (section 4).
- [ ] README has the architecture diagram, the coverage map, the policy excerpt, the test how-to with a real summary table, real telemetry numbers, the limitations list and the disclosure section with every npm dependency.
- [ ] `docs/slides.pdf` exists, ≤ 10 pages, every number on it matches `tests/.last-report.json`, `/admin/redteam/status` and `/admin/metrics`.
- [ ] `LICENSE` file (MIT) in the repo root.
- [ ] `data/`, `.env`, `node_modules`, `.next` are not committed. `.env.example` is.
- [ ] `policy.yaml` is the standard preset (mode `enforce`), not a leftover from the demo.
- [ ] Last commit tagged `submission-1` (or `submission-2` for the evening resubmission), repo public, URL pasted.
- [ ] Description ≤ the platform's character limit (check the field; the text below is ~250 words).

## 2. Project description (paste as-is, ~250 words)

Tollgate is an AI Control Layer built as an OpenAI-compatible HTTP proxy. Point any agent, app or framework at `http://localhost:8787/v1` instead of the model, and every request and response passes through controls defined in one file, `policy.yaml`. The file is validated with a strict schema and hot-reloaded: a saved change applies to the next request, an invalid edit is rejected and the last good version stays active, and every decision records the policy hash it was made under.

The defence is hybrid and layered. Tier 0 is deterministic and sub-millisecond: per-agent API keys and scopes, a model allowlist, budget pre-checks, PII and secret detection with redact or block, invisible-Unicode and homoglyph normalisation, decode-and-rescan of base64/hex/URL-encoded payloads, tool-definition checks, and signatures from an externally managed feed of real historical exploits (malicious Hugging Face pickles, nullifAI, ShadowRay, Probllama, EchoLeak, MCP tool poisoning). Tier 1 is a local classifier (Llama Guard 3 via Ollama) with a hard timeout and configurable fail-open or fail-closed. Tier 2 is a local LLM judge, consulted only when tier 1 is uncertain. The response path redacts PII and secrets, detects planted canary secrets, blocks link exfiltration, catches system-prompt leakage and gates tool calls behind allowlists and approvals.

Budgets per agent cover tokens, USD (from a price table, local models at $0), compute seconds and tool depth, with a loop breaker and an upstream circuit breaker. Every decision carries the tier, rule id, OWASP LLM and Agentic Top 10 ids and per-stage latency, lands in a hash-chained audit log with JSONL/CSV export, and feeds a dashboard with a management view and a security view.

`bun test` runs positive and negative YAML fixtures for every control. A built-in Red Team Loop mutates seed attacks against the live policy and turns every bypass into a failing test. No cloud APIs; everything runs locally.

## 3. AI-use disclosure (paste into the form's disclosure field and keep identical in README)

Implementation assistance: Claude Code (Anthropic) was used throughout the hackathon for planning, scaffolding, code generation, test-fixture generation, adversarial review and documentation, running the models <!-- TODO(M9): list exactly the models used, e.g. "Claude Opus 5.5 for the gateway core, tests and review; Claude Sonnet for the dashboard, fixtures and red-team seeds; Claude Fable 5.1 for the planning documents" — remove any that were not used -->. All code was reviewed by the author, who can explain every part. Local models via Ollama: `llama3.2:3b` (demo agent and tier-2 judge; Llama 3.2 Community License), `llama-guard3:1b` (tier-1 safety classifier; Llama 3.2 Community License) and, if enabled, `granite3-guardian:2b` (jailbreak vote; Apache 2.0). No cloud or paid model APIs were used at any point. Attack seed prompts in `tests/redteam/seeds/` are adapted from garak (NVIDIA, Apache 2.0) and promptfoo (MIT), attributed per file; the historical-attack feed entries cite their public sources (JFrog, ReversingLabs, Oligo, Wiz, The Hacker News, Invariant Labs / Cloud Security Alliance). Open-source libraries: hono (MIT), zod (MIT), yaml (ISC), next, react, react-dom (MIT), typescript (Apache 2.0), @types/bun (MIT) <!-- TODO(M9): append every dependency added during the build, with its licence, from `bun pm ls` -->. Referenced but not used in the critical path: Presidio (MIT), ModelScan (Apache 2.0), Prompt Guard 2 (Llama licence), Meta's LlamaFirewall paper. LLM Guard (archived July 2026) and LiteLLM's enterprise features were deliberately not used; the pipeline and budget engine are written from scratch in TypeScript.

## 4. README quickstart (the judges' path; must match what they experience)

The README section "Quickstart (3 commands)" is what a mentor will follow on their own laptop. It must be exactly this and nothing more:

```sh
git clone <repo-url> && cd <repo>
./scripts/setup.sh --wait-models   # installs bun + ollama if missing, pulls llama3.2:3b + llama-guard3:1b (+ granite3-guardian:2b), bun install, writes .env with a generated ADMIN_TOKEN
bun run dev                        # gateway http://localhost:8787, dashboard http://localhost:3000
bun test                           # the self-testing suite, in a second terminal
```

What they must see, in this order:

1. `setup.sh` ends with a readiness table where every row is OK (a WARN for the optional `granite3-guardian:2b` is acceptable). Without `--wait-models` the pulls run in the background and the stack comes up in no-models mode immediately (`SEMANTIC_PROVIDER=mock`, `UPSTREAM=echo` in `.env`); `./scripts/doctor.sh` shows when the models have landed, then both variables are set to `ollama`.
2. `bun run dev` prints the gateway listening on 8787 with the policy hash and feed entry count, and the dashboard on 3000. Opening `http://localhost:3000` shows the overview with a green policy banner.
3. `bun test` ends with the summary table grouped by control and OWASP id. Deterministic cases always run. If Ollama is not reachable or a model is missing, model-backed cases print `SKIP (model-backed): needs Ollama at :11434 with <model> — run \`ollama serve\` and \`ollama pull <model>\`` and the exit code is still 0.
4. The first curl from the README (the IBAN message with `tg_demo-agent_7f3kQ9mZp2xLw8Rv4Nb6`) returns 200 with `[REDACTED:iban]` in the content and `X-Tollgate-Decision: redact`, `X-Tollgate-Rule: pii.iban`, `X-Tollgate-Tier: 0`.
5. Editing `policy.yaml` while `bun run dev` runs produces a `policy.loaded` line in the gateway log and a banner change on the dashboard within a second; the next request uses the new version. A broken edit produces `policy.rejected` with the zod path and the old version stays active. Editing `feeds/ai-exploits.json` behaves the same way with `feed.loaded` / `feed.rejected`.

Fresh-clone check to run before submitting (on the Mac, in a folder outside the repo):

```sh
cd /tmp && rm -rf tg-check && git clone <repo-url> tg-check && cd tg-check
./scripts/setup.sh --skip-models     # models are already on this machine
bun run check
bun test 2>&1 | tail -30             # summary table, 0 fail
bun run dev &  sleep 5
curl -s localhost:8787/healthz | head -c 400
curl -s localhost:8787/v1/chat/completions -H 'Authorization: Bearer tg_demo-agent_7f3kQ9mZp2xLw8Rv4Nb6' \
  -H 'content-type: application/json' \
  -d '{"model":"llama3.2:3b","messages":[{"role":"user","content":"Pay invoice to PL61 1090 1014 0000 0712 1981 2874"}]}' -i | head -20
kill %1
```

If any step differs from the README, fix the README or the script, not the description.

Platform-specific notes to keep in the README under the quickstart: the gateway also runs on Linux and Intel Macs (`setup.sh` uses brew or the Ollama install script; only model speed differs); the full model set needs about 6 GB of disk; Node 20+ is required for Next.js and `setup.sh` checks for it.
