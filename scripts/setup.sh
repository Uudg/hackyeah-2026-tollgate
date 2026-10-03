#!/usr/bin/env bash
# Tollgate local setup — idempotent. Safe to re-run at any time.
# Checks each tool and installs it only if missing; starts Ollama if not running;
# pulls the three models if absent; creates ./data; writes .env from .env.example;
# runs bun install; prints a readiness table.
#
# Model pulls never block: by default missing models are pulled in the BACKGROUND (logs in ./data/pull-<model>.log)
# and the script finishes. The system runs without models (SEMANTIC_PROVIDER=mock, UPSTREAM=echo, see HANDOFF.md §0);
# model-backed tests skip until the pulls land. ./scripts/doctor.sh shows pull progress.
#
# Usage: ./scripts/setup.sh [--wait-models] [--skip-models] [--skip-install]
#   --wait-models   pull missing models inline and wait (use on a fast connection / judges' machine)
#   --skip-models   do not pull anything
#   --skip-install  do not run bun install
# Env:   OLLAMA_URL (default http://127.0.0.1:11434)

set -u
set -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SKIP_MODELS=0
SKIP_INSTALL=0
WAIT_MODELS=0
for arg in "$@"; do
  case "$arg" in
    --wait-models) WAIT_MODELS=1 ;;
    --skip-models) SKIP_MODELS=1 ;;
    --skip-install) SKIP_INSTALL=1 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

OLLAMA_URL="${OLLAMA_URL:-http://127.0.0.1:11434}"
REQUIRED_MODELS=("llama3.2:3b" "llama-guard3:1b")
OPTIONAL_MODELS=("granite3-guardian:2b")
MIN_OLLAMA="0.1.34"   # Probllama CVE-2024-37032 fixed here

# ---------- output helpers ----------
if [ -t 1 ]; then
  C_OK=$'\033[32m'; C_FAIL=$'\033[31m'; C_WARN=$'\033[33m'; C_DIM=$'\033[2m'; C_RST=$'\033[0m'
else
  C_OK=""; C_FAIL=""; C_WARN=""; C_DIM=""; C_RST=""
fi
step() { printf '\n%s==> %s%s\n' "$C_DIM" "$*" "$C_RST"; }
info() { printf '    %s\n' "$*"; }
ok()   { printf '    %sOK%s   %s\n' "$C_OK" "$C_RST" "$*"; }
warn() { printf '    %sWARN%s %s\n' "$C_WARN" "$C_RST" "$*"; }
fail() { printf '    %sFAIL%s %s\n' "$C_FAIL" "$C_RST" "$*"; }

ROWS=()
row() { ROWS+=("$1|$2|$3"); }   # status|item|detail

have() { command -v "$1" >/dev/null 2>&1; }

# Make brew / bun visible in this shell even if the user's rc file was not reloaded.
[ -x /opt/homebrew/bin/brew ] && eval "$(/opt/homebrew/bin/brew shellenv)"
[ -d "$HOME/.bun/bin" ] && export PATH="$HOME/.bun/bin:$PATH"

version_ge() { # version_ge A B → 0 if A >= B (dotted numerics)
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

# ---------- 0. platform ----------
step "Platform"
OS="$(uname -s)"; ARCH="$(uname -m)"
info "$OS $ARCH"
if [ "$OS" = "Darwin" ] && [ "$ARCH" = "arm64" ]; then
  ok "macOS Apple Silicon"
  row OK platform "macOS arm64"
else
  warn "Not macOS/arm64. Script continues; Homebrew steps may not apply."
  row WARN platform "$OS $ARCH (script tuned for macOS arm64)"
fi

# ---------- 1. Homebrew ----------
step "Homebrew"
if have brew; then
  ok "brew $(brew --version | head -n1 | awk '{print $2}')"
  row OK homebrew "$(command -v brew)"
  HAVE_BREW=1
else
  if [ "$OS" = "Darwin" ]; then
    fail "Homebrew not found. Install from https://brew.sh then re-run this script."
    row FAIL homebrew "missing — https://brew.sh"
  else
    warn "Homebrew not found (non-macOS); tools will be installed with their own scripts where possible."
    row WARN homebrew "missing"
  fi
  HAVE_BREW=0
fi

# ---------- 2. Bun ----------
step "Bun"
if ! have bun; then
  info "Installing bun via https://bun.sh/install"
  if curl -fsSL https://bun.sh/install | bash >/dev/null 2>&1; then
    export PATH="$HOME/.bun/bin:$PATH"
  elif [ "$HAVE_BREW" = 1 ]; then
    brew install oven-sh/bun/bun
  fi
fi
if have bun; then
  BUN_V="$(bun --version)"
  if version_ge "$BUN_V" "1.1.0"; then
    ok "bun $BUN_V"; row OK bun "$BUN_V"
  else
    warn "bun $BUN_V is older than 1.1; run: bun upgrade"; row WARN bun "$BUN_V (< 1.1, run bun upgrade)"
  fi
else
  fail "bun could not be installed"; row FAIL bun "missing"
fi

# ---------- 3. Node (for Next.js) ----------
step "Node (Next.js runtime)"
if ! have node && [ "$HAVE_BREW" = 1 ]; then
  info "Installing node@22 via brew"
  brew install node@22 >/dev/null && brew link --overwrite node@22 >/dev/null 2>&1 || true
fi
if have node; then
  NODE_V="$(node --version | sed 's/^v//')"
  if version_ge "$NODE_V" "20.0.0"; then
    ok "node $NODE_V"; row OK node "$NODE_V"
  else
    warn "node $NODE_V < 20; Next.js needs 20+. brew install node@22"; row WARN node "$NODE_V (< 20)"
  fi
else
  fail "node missing; Next.js dashboard will not start"; row FAIL node "missing"
fi

# ---------- 4. git / gh ----------
step "git and gh"
if have git; then ok "git $(git --version | awk '{print $3}')"; row OK git "$(git --version | awk '{print $3}')"; else fail "git missing"; row FAIL git "missing"; fi
if have gh; then
  ok "gh $(gh --version | head -n1 | awk '{print $3}')"; row OK gh "$(gh --version | head -n1 | awk '{print $3}')"
else
  if [ "$HAVE_BREW" = 1 ]; then info "Installing gh via brew"; brew install gh >/dev/null 2>&1 || true; fi
  if have gh; then ok "gh installed"; row OK gh "installed"; else warn "gh missing (optional; needed only for gh repo create)"; row WARN gh "missing (optional)"; fi
fi

# ---------- 5. Ollama ----------
step "Ollama"
if ! have ollama; then
  if [ "$HAVE_BREW" = 1 ]; then
    info "Installing ollama via brew"
    brew install ollama >/dev/null
  elif [ "$OS" = "Linux" ]; then
    info "Installing ollama via https://ollama.com/install.sh"
    curl -fsSL https://ollama.com/install.sh | sh >/dev/null 2>&1 || true
  fi
fi
if have ollama; then
  OLLAMA_V="$(ollama --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"
  OLLAMA_V="${OLLAMA_V:-0.0.0}"
  if version_ge "$OLLAMA_V" "$MIN_OLLAMA"; then
    ok "ollama $OLLAMA_V"; row OK ollama "$OLLAMA_V"
  else
    warn "ollama $OLLAMA_V < $MIN_OLLAMA (Probllama); brew upgrade ollama"; row WARN ollama "$OLLAMA_V (< $MIN_OLLAMA)"
  fi
else
  warn "ollama not installed — build and tests run in no-models mode; install later with: brew install ollama"
  row WARN ollama "missing (brew install ollama); no-models mode active"
fi

ollama_up() { curl -fsS --max-time 2 "$OLLAMA_URL/api/tags" >/dev/null 2>&1; }

if have ollama; then
  if ollama_up; then
    ok "server reachable at $OLLAMA_URL"
  else
    info "starting ollama server"
    STARTED=0
    if [ "$HAVE_BREW" = 1 ] && brew list ollama >/dev/null 2>&1; then
      brew services start ollama >/dev/null 2>&1 && STARTED=1
    fi
    if [ "$STARTED" = 0 ]; then
      mkdir -p "$ROOT/data"
      nohup ollama serve >"$ROOT/data/ollama.log" 2>&1 &
      disown || true
    fi
    for _ in $(seq 1 30); do ollama_up && break; sleep 1; done
    if ollama_up; then ok "server started at $OLLAMA_URL"; else warn "server not reachable at $OLLAMA_URL after 30 s (see docs/SETUP.md troubleshooting)"; fi
  fi
fi
if ollama_up; then row OK "ollama server" "$OLLAMA_URL"
elif have ollama; then row WARN "ollama server" "not reachable at $OLLAMA_URL (ollama serve); no-models mode active"
else row WARN "ollama server" "ollama not installed; no-models mode active"; fi

# ---------- 6. Models ----------
step "Models"
model_present() { # exact tag match against /api/tags
  curl -fsS --max-time 3 "$OLLAMA_URL/api/tags" 2>/dev/null | grep -q "\"name\":\"$1\""
}
pull_in_progress() { pgrep -f "ollama pull $1" >/dev/null 2>&1; }
BG_PULLS=0
pull_model() {
  local m="$1" kind="$2" log="$ROOT/data/pull-$(echo "$m" | tr ':/' '__').log"
  if model_present "$m"; then
    ok "$m present"; row OK "model $m" "present ($kind)"
    return
  fi
  if pull_in_progress "$m"; then
    ok "$m pull already running in background (log: ${log#$ROOT/})"; row WARN "model $m" "pulling in background ($kind)"
    BG_PULLS=$((BG_PULLS+1))
    return
  fi
  if [ "$SKIP_MODELS" = 1 ] || ! ollama_up; then
    warn "$m missing ($kind) — system runs in no-models mode (SEMANTIC_PROVIDER=mock, UPSTREAM=echo)"
    row WARN "model $m" "missing ($kind); ollama pull $m"
    return
  fi
  if [ "$WAIT_MODELS" = 1 ]; then
    info "pulling $m ($kind) inline — slow on arena Wi-Fi; Ctrl-C and re-run resumes"
    if ollama pull "$m"; then ok "$m pulled"; row OK "model $m" "pulled ($kind)"
    else warn "$m pull failed ($kind)"; row WARN "model $m" "pull failed ($kind); retry: ollama pull $m"; fi
  else
    mkdir -p "$ROOT/data"
    nohup ollama pull "$m" >"$log" 2>&1 &
    disown || true
    ok "$m pull started in background (log: ${log#$ROOT/})"
    row WARN "model $m" "pulling in background ($kind); progress: tail -f ${log#$ROOT/}"
    BG_PULLS=$((BG_PULLS+1))
  fi
}
for m in "${REQUIRED_MODELS[@]}"; do pull_model "$m" required; done
for m in "${OPTIONAL_MODELS[@]}"; do pull_model "$m" optional; done
if [ "$BG_PULLS" -gt 0 ]; then
  info "Models are not needed to build or test: .env defaults to SEMANTIC_PROVIDER=mock and UPSTREAM=echo."
  info "When ./scripts/doctor.sh shows all models present, set SEMANTIC_PROVIDER=ollama and UPSTREAM=ollama in .env."
fi

# ---------- 7. Directories ----------
step "Directories"
for d in data feeds tests/cases; do
  mkdir -p "$ROOT/$d"
done
ok "./data ./feeds ./tests/cases exist"
row OK directories "data/ feeds/ tests/cases/"

# ---------- 8. .env ----------
step ".env"
if [ -f "$ROOT/.env" ]; then
  ok ".env exists (left unchanged)"
  row OK ".env" "exists"
elif [ -f "$ROOT/.env.example" ]; then
  cp "$ROOT/.env.example" "$ROOT/.env"
  if have openssl; then
    TOKEN="$(openssl rand -hex 16)"
    # replace an empty or placeholder ADMIN_TOKEN with a generated one (macOS and GNU sed)
    sed -i.bak -E "s/^ADMIN_TOKEN=.*/ADMIN_TOKEN=$TOKEN/; s/^NEXT_PUBLIC_ADMIN_TOKEN=.*/NEXT_PUBLIC_ADMIN_TOKEN=$TOKEN/" "$ROOT/.env" && rm -f "$ROOT/.env.bak"
    ok ".env created from .env.example with a generated ADMIN_TOKEN (also set as NEXT_PUBLIC_ADMIN_TOKEN)"
  else
    ok ".env created from .env.example — set ADMIN_TOKEN manually"
  fi
  row OK ".env" "created"
else
  fail ".env.example missing; cannot create .env"
  row FAIL ".env" ".env.example missing"
fi
if [ -f "$ROOT/.env" ] && grep -qE '^ADMIN_TOKEN=\s*$' "$ROOT/.env"; then
  warn "ADMIN_TOKEN is empty in .env; the gateway will refuse to start"
  row WARN "ADMIN_TOKEN" "empty"
fi

# ---------- 9. bun install ----------
step "bun install"
if [ "$SKIP_INSTALL" = 1 ]; then
  info "skipped (--skip-install)"; row WARN "bun install" "skipped"
elif [ ! -f "$ROOT/package.json" ]; then
  warn "no package.json yet; skipping"; row WARN "bun install" "no package.json"
elif have bun; then
  if bun install --silent 2>&1 | tail -n 5; then ok "dependencies installed"; row OK "bun install" "done"; else fail "bun install failed"; row FAIL "bun install" "failed"; fi
else
  fail "bun missing"; row FAIL "bun install" "bun missing"
fi

# ---------- 10. Readiness table ----------
printf '\n%s' "Readiness"
printf '\n%-6s %-28s %s\n' "STATUS" "ITEM" "DETAIL"
printf '%-6s %-28s %s\n' "------" "----------------------------" "------"
FAILS=0
for r in "${ROWS[@]}"; do
  IFS='|' read -r s i d <<<"$r"
  case "$s" in
    OK)   c="$C_OK" ;;
    WARN) c="$C_WARN" ;;
    *)    c="$C_FAIL"; FAILS=$((FAILS+1)) ;;
  esac
  printf '%s%-6s%s %-28s %s\n' "$c" "$s" "$C_RST" "$i" "$d"
done
printf '\n'
if [ "$FAILS" -gt 0 ]; then
  printf '%s%d check(s) failed.%s See docs/SETUP.md → Troubleshooting, fix, and re-run ./scripts/setup.sh\n' "$C_FAIL" "$FAILS" "$C_RST"
  exit 1
fi
if [ "$BG_PULLS" -gt 0 ]; then
  printf '%sReady (no-models mode).%s %d model pull(s) running in background. Next: bun run dev, then bun test. Re-run ./scripts/doctor.sh to see when models land.\n' "$C_OK" "$C_RST" "$BG_PULLS"
else
  printf '%sReady.%s Next: bun run dev   (gateway :8787 + dashboard :3000), then bun test\n' "$C_OK" "$C_RST"
fi
