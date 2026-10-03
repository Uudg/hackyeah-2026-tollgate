# Tollgate submission video — Claude Code prompt

Run only after the project is built and redesigned: dashboard on `design/` v3, logo and favicon in place, code freeze reached. Use a SEPARATE terminal and folder:

    mkdir -p ~/Documents/tollgate-promo && cd ~/Documents/tollgate-promo && claude

Model: Opus 5.5 high (Sonnet 5.5 high if quota is short). Start in Plan mode (Shift+Tab). Paste everything below the line.

---

Make the submission video for my hackathon project, Tollgate: 75–90 seconds, 1920x1080, for the Goldman Sachs reviewers who will watch it without anyone explaining. It must show every capability clearly and look like a calm, well-designed product video. Everything it claims must be real: every request, rule id, number, hash and test count on screen comes from the running system, captured by scripts you write. No invented stats, no mocked dashboards.

## The project
Tollgate is an AI Control Layer: an OpenAI-compatible gateway that every AI agent request and response passes through. Integration is two settings (base URL and API key); it works with the official OpenAI SDK. One `policy.yaml` controls everything and hot-reloads without restart; a broken edit is rejected and the last good policy stays active. Cheap deterministic checks run first (auth, model allowlist, budgets, PII and secret detection, Unicode and encoding tricks, a feed of signatures from real historical attacks: malicious Hugging Face pickles, nullifAI, ShadowRay, Probllama, EchoLeak, MCP tool poisoning). A small local model (Llama Guard 3 via Ollama) is consulted only for ambiguous cases, and a local judge only when that model is unsure. Responses are scanned too (redaction, link exfiltration, system-prompt leaks, tool calls). Budgets per agent in tokens, dollars (paid APIs priced, local models at $0) and compute time, with a loop breaker. Every decision goes to a hash-chained audit log. Canary secrets: if one appears in output, the session is killed. Dashboard for management and security teams, a self-testing suite, and a Red Team Loop that turns its own bypasses into tests. HackYeah 2026, Goldman Sachs "AI Control Layer" track. Tagline: "One policy file between your agents and everything they can touch."

Judges score: guardrail robustness (30), architecture and performance (20), security reporting (20), test-suite completeness (15–20), implementability (10–15). Structure the video around those, in that order of weight.

## Where things are
- Repo, READ-ONLY for you: `~/Documents/hackyeah2026`. Read `CLAUDE.md`, `README.md`, `docs/SPEC.md` §8 (HTTP API) and §10 (dashboard), `docs/CHECKPOINTS.md` (measured numbers and their source), `policy.yaml`, `feeds/ai-exploits.json`.
- Design system: `~/Documents/hackyeah2026/design/`. Read `design/README.md` and `design/BRAND.md` first; use `design/tokens.css` / `tokens.json`, `design/components.css`, `design/logo/*.svg` and the canary from `design/mascot/canary.svg` (states `is-idle | is-allow | is-redact | is-block | is-kill`, see `design/mascot/README.md`). `design/examples/SlideTitle.html` and `Slide.html` show the slide language the video shares. Ignore `design/_archive-*`.
- Video tool: HyperFrames, already installed (`npx hyperframes`, cached v0.8.x; Node and ffmpeg present). Its skills live in `~/.agents/skills/hyperframes*` and are NOT auto-loaded: read `hyperframes/SKILL.md`, `hyperframes-cli/SKILL.md`, `hyperframes-core/SKILL.md` and `hyperframes-animation/SKILL.md` before authoring and follow their workflow (catalog search before hand-written motion, `lint`, `check`, `snapshot`, `render`).
- Headless browser: one already on this Mac (Playwright's cached `chromium_headless_shell-*` under `~/Library/Caches/ms-playwright`, or `/Applications/Google Chrome.app`). Internet is slow: no browser downloads, no web fonts, no stock assets. System fonts only, as the design system says.
- Write only inside `~/Documents/tollgate-promo`.

## Isolation (important)
`PUT /admin/policy/raw` writes the policy file the gateway was started with, and scripted traffic fills the audit log and metrics. So never run captures against my normal dev setup:
1. Copy `policy.yaml`, `feeds/ai-exploits.json` and `pricing.json` from the repo into `runtime/` in the promo folder. Generate a fresh `ADMIN_TOKEN` for this run (keep it in memory or `runtime/.env`, which you gitignore); never print it on screen or in captures.
2. Ask me to stop any Tollgate dev servers I have running (or check that ports 8787 and 3000 are free). Then start the repo's gateway and dashboard yourself from the repo folder with environment overrides only: `TOLLGATE_POLICY`, `TOLLGATE_FEED`, `TOLLGATE_DATA_DIR` pointing into `runtime/`, `ADMIN_TOKEN` / `NEXT_PUBLIC_ADMIN_TOKEN` set to the run token, `SEMANTIC_PROVIDER=ollama`, `UPSTREAM=ollama` if the models are present (else `mock` / `echo` and cut the beats that need models). Do not edit any file in the repo.
3. When you finish, stop the servers you started and tell me. The repo's `policy.yaml` and `data/` are never touched.

## Phase 1 — capture (real data)
1. `scripts/preflight.ts`: `/healthz` (mode, semantic provider, models), dashboard 200, Ollama models. Print which beats below are possible. A beat whose feature is missing or broken is CUT, never faked; report it.
2. `scripts/capture-outputs.ts` (bun, `fetch`): send the scripted requests, save request text, status, `X-Tollgate-*` headers, trimmed response and the matching decision record (`/admin/audit/:id`) to `captures/outputs.json`. Use `/admin/playground` where it is simpler. Agent keys come from `runtime/policy.yaml`; on screen mask them as `tg_<agent>_••••`.
   - clean prompt → allow
   - prompt with an IBAN `PL61 1090 1014 0000 0712 1981 2874` → redact `pii.iban`
   - base64-wrapped "ignore all previous instructions" → block (`decode.rescan` or the signature that decides)
   - a tool call to `http://10.0.0.5:8265/api/jobs` → block `sig.shadowray-cve-2023-48022` (or whichever feed entry decides)
   - a response with an EchoLeak-style markdown image carrying data → link stripped (`link_exfil.*`)
   - an ambiguous prompt → tier 1 score → tier 2 verdict with real stage latencies (only if models are present)
   - an ordinary finance prompt that Llama Guard flags and the judge clears (the false-positive fix described in `docs/CHECKPOINTS.md`), if it reproduces; otherwise quote the measured result from CHECKPOINTS with its source line
   - canary planted (`plant_canary: true`) and echoed back → `kill_session`, `canaries.in_output`
   - `test-small-budget` looped until `429` → `budget.*`; the shadow-priced demo model until `429 budget.usd_per_day`
   - hot reload: change one action in `runtime/policy.yaml` through `PUT /admin/policy/raw`, wait for `policy.loaded`, re-send the same request, capture both outcomes; then PUT an invalid value and capture `policy.rejected` with the previous hash still active; finally restore the original text and confirm the hash
   - the official OpenAI SDK example from the repo (`examples/openai-sdk.ts`) pointed at the run, capture its output
3. `scripts/capture-cli.ts`: from the repo folder, with the same env overrides, save stdout to `captures/cli.json`: `bun test` summary (pass / skip / fail, fixture count, the separate red-team backlog line), `bun run audit:verify`, `bun run bench` (tier-0 overhead p50/p95, throughput), latest Red Team numbers (`/admin/redteam/status`, before/after hardening from README/CHECKPOINTS with source).
4. Dashboard visuals from the isolated run (it now holds the captured traffic): captures of `/`, `/security`, one `/security/events/[id]` from step 2, `/policy`, `/coverage`, `/redteam` and the Playground; short Playwright clips (1920x1080, under 6 s each) of an attack typed into the Playground with the verdict and the canary reacting, and of the `/policy` banner on `policy.loaded`.
5. `captures/manifest.json`: every capture with timestamp, policy hash, feed hash and repo commit (`git -C ~/Documents/hackyeah2026 rev-parse --short HEAD`). Show commit and policy hash small in the outro.

`bun run capture` reruns all of Phase 1; `bun run render:submission` rebuilds the video. That is the update path if the product changes before submission.

## Phase 2 — the video
1920x1080, 30 fps, 75–90 s, H.264 `out/tollgate-submission.mp4`, poster `out/poster.png`, plus `out/captions.srt`. Build reusable parts (scene templates for "request → decision", metric cards, the canary, captioned dashboard zooms) in `src/parts/` so the pitch video can reuse them. All on-screen text comes from `captures/*.json` through `src/data.js`.

No voiceover needed: short captions carry the story (one line, sentence case, 30–36 px, `ink` on a `panel` card or `mute` under a title, on screen long enough to read twice). Write an optional voiceover script to `out/voiceover.md` with timecodes, in case I record one.

### Storyboard (lengths are a guide; every point stays readable for 3–5 s)
1. **0–6 s, opening.** `bg` ground. The canary sits on its gate (from `design/mascot/canary.svg`), blinks. The logo fades in top left. Caption: "AI agents now hold keys, tools and data."
2. **6–14 s, the problem.** Three short real cases in a row, shown as the agent would see them: a hidden instruction in a document, a card number in a prompt, an agent looping. The canary watches. Caption: "Nothing checks what goes in or out."
3. **14–22 s, what Tollgate is.** Two-line code diff (base URL, API key) with the SDK output underneath. Then the pipeline as a clean diagram in the design system's panel style: agent → identity → budget → tier 0 → tier 1 → tier 2 → model → output, `policy.yaml` above feeding every stage, the audit log below.
4. **22–44 s, guardrails (heaviest beat).** Five captured cases, about 4 s each: the real prompt (mono) enters, the stage strip lights stage by stage with real latencies, the real decision badge lands with rule id, OWASP id and tier; the canary acts it out (allow: arm lifts; redact: bar over its eyes and the IBAN digits replaced; block: arm shakes; kill: canary tips over, "session killed"). Include the ShadowRay and EchoLeak cases with a one-line note of the real incident.
5. **44–52 s, rules first, models only when unsure.** The ambiguous case with real tier-1 and tier-2 latencies, then the false-positive story with its real numbers. Then the tier-0 bench numbers.
6. **52–58 s, one file.** `policy.yaml` diff of the real changed line, before and after decisions, `policy.loaded` with the new hash; then the broken edit rejected with the previous hash still active. Caption: "No restart. A bad edit never drops protection."
7. **58–63 s, budgets.** Token budget to `429`, the shadow-priced model's dollar spend to `429 budget.usd_per_day`. Caption explains that local models are metered at $0.
8. **63–74 s, reporting.** Zoom through the captured dashboard: overview tiles and blocks over time (management), the event table and one event detail with per-stage latency (security), the coverage map with the honest "not covered" items. Then the audit chain: `audit:verify` OK with the real line count and head hash.
9. **74–84 s, proof.** Real `bun test` summary, the red-team backlog line, the bypass rate before and after hardening, "Reviewers can run all of this with `bun test`."
10. **84–90 s, outro.** The canary on its gate, the arm lifts, logo, tagline, repo URL, small `commit <sha> · policy <hash>`. Hold the last 12 frames still.

### Look (from `design/`)
- `bg` ground, white `panel` cards with 1 px `line` borders and `radius-card`, system fonts, `ink` and `mute` text, `accent` only for links and highlights.
- Decision colours exactly as the dashboard badges: `allow`, `redact`, `block`, `kill` with their `-bg` and `-border` tokens; always the word with the colour.
- The canary is the only illustration and the only character; it reacts to every decision with its built-in states. No other mascots, icons, shields, padlocks or glowing effects. No dark neon look.
- Captured dashboard frames are shown inside `panel` cards and zoomed to the part that matters, never full-screen and tiny.

### Craft
- Calm, precise motion: ease-out moves (no linear), small springs only on badge pops, consistent durations; cut on a 120 BPM grid (a beat every 15 frames).
- A short decaying shake only on blocks, never on allowed traffic. Respect what each beat needs to be read.
- Text at least 28 px at 1080p; every beat readable on a phone-sized preview.

### Audio (optional, last)
HyperFrames audio skill or ffmpeg lavfi: a soft pulse, a light tick on each decision, a riser into the outro. No downloaded samples. Mix to -14 LUFS. If it is not good, ship silent and say so.

## How to work
1. Plan mode first: preflight result (which beats are possible), the capture scripts, the timeline in seconds, the parts list. Wait for my OK.
2. Run the captures. Show me a one-line-per-case summary of `captures/outputs.json` before animating.
3. Rough cut with plain boxes and the real text; `npx hyperframes snapshot` one frame per beat and check them yourself.
4. Polish beat by beat; snapshot first hit / peak / settle and fix overlaps, clipped text and weak contrast. `npx hyperframes check` before the full render.
5. Render, extract 10 evenly spaced frames, check them. Report render time and any beats you cut and why.
6. Deliver `out/tollgate-submission.mp4`, `out/poster.png`, `out/captions.srt`, `out/voiceover.md`, and a README with `bun run capture`, `npx hyperframes preview`, `bun run render:submission`.

Make decisions yourself and tell me what you chose; stop only at the plan checkpoint and before asking me to stop my dev servers.
