# Local setup — macOS Apple Silicon

Target machine: MacBook Pro M1 Max, macOS, Homebrew already installed. Nothing here needs `sudo`. Everything runs locally; no cloud API keys are used anywhere.

Two paths:

- **Fast path:** `./scripts/setup.sh` does every step below and is safe to re-run. Then `./scripts/doctor.sh` to confirm.
- **Manual path:** the steps below, in order. Use this when something in the script fails or you want to see what it does.

Start step 2 (model pulls) **first**, before anything else, then do not wait for it. The pulls are the only step that depends on arena Wi‑Fi and can take from 15 minutes to several hours; everything else takes under five minutes. `setup.sh` starts missing pulls in the background and finishes without them.

**Nothing in the build or the test suite needs the models.** `.env.example` defaults to `SEMANTIC_PROVIDER=mock` and `UPSTREAM=echo` (HANDOFF.md §0): tier-1/tier-2 are served by a deterministic mock and the upstream is a canned echo. When `./scripts/doctor.sh` shows all models present, set both to `ollama` in `.env` and re-run `bun test` to get the model-backed cases and real telemetry.

---

## 0. Homebrew

```sh
brew --version
```

If that fails, install from https://brew.sh (the one-line installer; it asks for your password once for `/opt/homebrew`). Then make sure the shell sees it:

```sh
eval "$(/opt/homebrew/bin/brew shellenv)"
```

Add the same line to `~/.zshrc` if `brew` disappears in new terminals.

## 1. Ollama

```sh
brew install ollama
ollama --version          # must be >= 0.1.34 (Probllama CVE-2024-37032 is fixed from 0.1.34; the signature feed flags older versions)
```

Alternative: download the Ollama.app from https://ollama.com/download and run it; it installs the `ollama` CLI and starts the server itself. Either works. Do not install both.

Start the server:

```sh
brew services start ollama        # if installed via brew; runs at login
# or, foreground in a spare terminal (useful to see model load logs):
ollama serve
```

Verify:

```sh
curl -s localhost:11434/api/version
# {"version":"0.x.y"}
```

## 2. Pull the models (start this first, in a spare terminal)

```sh
ollama pull llama3.2:3b           # demo agent + tier-2 judge
ollama pull llama-guard3:1b       # tier-1 classifier
ollama pull granite3-guardian:2b  # optional jailbreak yes/no classifier
```

Or let `./scripts/setup.sh` start them in the background (logs in `./data/pull-<model>.log`; `./scripts/doctor.sh` shows the percentage). `./scripts/setup.sh --wait-models` pulls inline instead, which is what judges on a normal connection should use.

Sizes and rough pull times:

| Model | Download | 50 Mbit/s | 20 Mbit/s | 5 Mbit/s (bad arena Wi‑Fi) |
|---|---|---|---|---|
| `llama3.2:3b` | ~2.0 GB | ~6 min | ~14 min | ~55 min |
| `llama-guard3:1b` | ~1.6 GB | ~5 min | ~11 min | ~45 min |
| `granite3-guardian:2b` | ~1.6 GB | ~5 min | ~11 min | ~45 min |
| **Total** | **~5.2 GB** | **~16 min** | **~36 min** | **~2.5 h** |

Pull order matters: `llama3.2:3b` and `llama-guard3:1b` are required; `granite3-guardian:2b` is optional. If Wi‑Fi is bad, skip granite until the other two are in. If `llama3.2:3b` cannot be pulled, `qwen2.5:3b` (~1.9 GB) is the documented fallback for the demo agent and judge — set `DEMO_MODEL=qwen2.5:3b` in `.env` and `semantic.judge_model: qwen2.5:3b` in `policy.yaml` (it is already in `models.allow`).

A phone hotspot is usually faster than arena Wi‑Fi for a one-off 5 GB download.

Verify:

```sh
curl -s localhost:11434/api/tags | grep -o '"name":"[^"]*"'
# "name":"llama3.2:3b"
# "name":"llama-guard3:1b"
# "name":"granite3-guardian:2b"
```

Smoke test the OpenAI-compatible endpoint the gateway will forward to:

```sh
curl -s localhost:11434/v1/chat/completions -H 'content-type: application/json' \
  -d '{"model":"llama3.2:3b","messages":[{"role":"user","content":"Say hi in three words"}]}' | head -c 400
```

The first call to each model takes 2–10 s (model load); later calls are fast. Ollama keeps a model in memory for 5 minutes after the last call by default.

## 3. Bun

```sh
curl -fsSL https://bun.sh/install | bash     # installs to ~/.bun, adds to ~/.zshrc
# or
brew install oven-sh/bun/bun
bun --version                                 # >= 1.1
```

Open a new terminal (or `source ~/.zshrc`) if `bun` is not found after the curl install.

## 4. Node 20+ (for Next.js)

Bun runs the gateway and the tests. Next.js is run on Node (see "Bun + Next.js quirks" below), so Node 20 LTS or newer must be present:

```sh
node --version          # v20.x or v22.x
# if missing or old:
brew install node@22 && brew link --overwrite node@22
```

## 5. git and GitHub

```sh
git --version
brew install gh          # GitHub CLI, if missing
gh auth login            # browser flow; choose HTTPS
```

Create the repo from inside the project folder (once):

```sh
cd ~/hackyeah2026        # wherever the folder is
git init -b main
git add -A
git commit -m "chore: scaffold tollgate handoff"
gh repo create tollgate --private --source=. --remote=origin --push
```

Keep it private while building. Before submitting on HackTribe, make it public so judges can clone it:

```sh
gh repo edit --visibility public --accept-visibility-change-consequences
```

## 6. Environment file

```sh
cp .env.example .env
```

Then set `ADMIN_TOKEN` in `.env` to a random value (`openssl rand -hex 16`) and copy it into `NEXT_PUBLIC_ADMIN_TOKEN` (`setup.sh` does both). The other settings (`TOLLGATE_PORT`, `TOLLGATE_POLICY`, `TOLLGATE_FEED`, `TOLLGATE_DATA_DIR`, `OLLAMA_URL`, `DEMO_MODEL`) have working defaults; the classifier and judge models are set in `policy.yaml` (`semantic.*`), not in `.env`. The gateway refuses to start with an empty `ADMIN_TOKEN` unless `TOLLGATE_INSECURE_ADMIN=1` is set. The dashboard reads the same token through `NEXT_PUBLIC_ADMIN_TOKEN` — for the demo it is fine that it is visible in the browser; say so in the README limitations.

Leave `SEMANTIC_PROVIDER=mock` and `UPSTREAM=echo` until the models are present. Every other value has a working default.

`.env` is gitignored. `.env.example` is the documented reference and is committed.

## 7. Install workspaces and check

```sh
bun install
./scripts/doctor.sh
```

`doctor.sh` prints an OK/FAIL row per check. Everything must be OK before the first milestone starts.

## 8. Run

```sh
bun run dev              # gateway on :8787 (watch mode) + dashboard on :3000
# or separately:
bun run dev:gateway
bun run dev:dashboard
bun test                 # full suite; model-backed cases skip with a message if Ollama/models are absent
```

---

## How judges will run it

The README quickstart must match this exactly; judges run on their own machine and will not read this file.

```sh
git clone <repo-url> && cd <repo>
./scripts/setup.sh --wait-models   # checks/installs bun + ollama, pulls the models, bun install, writes .env
bun run dev                        # gateway http://localhost:8787, dashboard http://localhost:3000
bun test                           # in a second terminal
```

Without `--wait-models` the pulls run in the background and the stack comes up in no-models mode immediately; that is the right choice when judges want to see the gateway first and the models later.

What they should see:

- `setup.sh` ends with a readiness table where every row is OK (or a WARN about a model still pulling / optional).
- `bun test` ends with a summary table grouped by control and OWASP id. Deterministic cases always run. If Ollama is not reachable or a model is missing, model-backed cases print `SKIP (model-backed): needs Ollama at :11434 with <model> — run \`ollama serve\` and \`ollama pull <model>\`` and the exit code is still 0.
- Editing `policy.yaml` while `bun run dev` is running produces a `policy.loaded` event in the gateway log and the dashboard banner within a second; the next request uses the new version. A broken edit produces `policy.rejected` with the zod error path and the previous version stays active.

If the judges' laptop is Linux or Intel Mac, `setup.sh` still works (brew or the Ollama install script); the only difference is model speed.

---

## Troubleshooting

**Ollama port 11434 is busy / "address already in use".**
Something is already serving Ollama (the menu-bar app and `brew services` both running is the usual cause). Check with `lsof -nP -iTCP:11434 -sTCP:LISTEN`. Stop one of them: `brew services stop ollama`, or quit the Ollama menu-bar app. If a stale process holds the port, `kill <pid>` from the lsof output. If port 11434 is used by something unrelated, run Ollama elsewhere with `OLLAMA_HOST=127.0.0.1:11435 ollama serve` and set `OLLAMA_URL=http://127.0.0.1:11435` in `.env`.

**`ollama pull` stalls or shows a stuck percentage.**
Keep building; nothing waits on it (no-models mode). Ollama downloads blobs in parallel chunks and resumes; Ctrl‑C (or `pkill -f "ollama pull"`) and re-run the same `ollama pull` — it continues from the blobs it already has. If the registry connection keeps dropping, switch to a phone hotspot for the pull. Check for a half-downloaded blob with `du -sh ~/.ollama/models/blobs`. If a model is listed in `api/tags` but fails to run, `ollama rm <model>` then pull again.

**Memory on M1 (32 GB on the M1 Max, 16 GB on lower configs).**
Keep every model at 3B parameters or smaller. `llama3.2:3b` + `llama-guard3:1b` + `granite3-guardian:2b` loaded together use about 6–7 GB of unified memory. Do not pull `llama-guard3:8b` or `granite3-guardian:8b` for the demo. If Ollama evicts models between requests (visible as 2–10 s first-token latency), the gateway already sends `keep_alive` from `OLLAMA_KEEP_ALIVE` (default `30m`, SPEC §2 stage 4) on every call; you can also start the server with `OLLAMA_KEEP_ALIVE=30m ollama serve`. `OLLAMA_MAX_LOADED_MODELS=3` keeps all three resident.

**Tier-1 classifier is slow (hundreds of ms).**
Expected on first call (model load). Steady state for `llama-guard3:1b` on an M1 Max is tens of ms for short prompts. If it stays slow, confirm with `ollama ps` that the model shows `100% GPU`; if it says CPU, memory pressure is forcing it off the GPU — close other apps or drop granite.

**Bun + Next.js quirks.**
- Run Next.js with `bun run dev:dashboard` (which executes `next dev` under Node, because the `next` binary has a Node shebang and `bun run` respects it). Do **not** use `bun --bun run dev` for the dashboard: that forces the Bun runtime, and Next's dev server, SWC and `next/font` are not reliable under it.
- `bun install` is fine for the dashboard's dependencies; only the runtime must be Node.
- If `next dev` complains about the Node version, check `node --version` inside the same terminal (nvm/fnm shells sometimes shadow the brew Node).
- If `bun run dev` (concurrent) interleaves output confusingly, run `dev:gateway` and `dev:dashboard` in two terminals.
- `bun:sqlite` is Bun-only; the dashboard must never import from `apps/gateway` — it talks to the gateway over HTTP/SSE only.
- Turbopack is the default in `next dev`; if it fails on a dependency, run `next dev --webpack` once to confirm, then fix the dependency rather than switching permanently.

**Port 8787 or 3000 is busy.**
`lsof -nP -iTCP:8787 -sTCP:LISTEN` (same for 3000) shows the process; kill it or change `TOLLGATE_PORT` in `.env` (and `NEXT_PUBLIC_GATEWAY_URL` to match); the dashboard port is the `-p` flag of `next dev` in `apps/dashboard/package.json`. Changing ports is a last resort; README, the tests and the dashboard default assume 8787/3000.

**`bun test` finds no tests.**
The runner is `tests/runner.test.ts`; `bun test` must be run from the repo root so `bunfig.toml` applies. Fixtures live in `tests/cases/*.yaml`.

**`policy.yaml` edit does not take effect.**
Check the gateway log for `policy.rejected` — an invalid file keeps the previous version active by design. `bun run policy:check` prints the zod error path. Also check you edited the file the gateway loaded (`TOLLGATE_POLICY` in `.env`, shown as `path` on `GET /admin/policy`). Editors that write through a temp file + rename are handled (the watcher watches the directory); if nothing fires, `PUT /admin/policy/raw` or the dashboard's Policy editor saves through the gateway.

**`gh repo create` says the name is taken.**
Pick another name (`tollgate-hackyeah2026`) or `gh repo create <owner>/<name>`.
