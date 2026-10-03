#!/usr/bin/env bash
# Tollgate doctor — read-only health checks. Installs nothing, starts nothing, writes nothing.
# Prints one OK/WARN/FAIL row per check and exits 1 if any required check fails.
#
# Usage: ./scripts/doctor.sh
# Env:   OLLAMA_URL, GATEWAY_PORT, DASHBOARD_PORT, POLICY_PATH, FEED_PATH (defaults match .env.example)

set -u
set -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Load .env for ports/paths if present (values already exported take precedence).
if [ -f "$ROOT/.env" ]; then
  while IFS='=' read -r k v; do
    case "$k" in ''|\#*) continue ;; esac
    k="$(echo "$k" | tr -d '[:space:]')"
    v="${v%%#*}"; v="${v%"${v##*[![:space:]]}"}"; v="${v#\"}"; v="${v%\"}"
    [ -z "${!k:-}" ] && export "$k=$v"
  done < "$ROOT/.env"
fi

OLLAMA_URL="${OLLAMA_URL:-http://127.0.0.1:11434}"
GATEWAY_PORT="${GATEWAY_PORT:-8787}"
DASHBOARD_PORT="${DASHBOARD_PORT:-3000}"
POLICY_PATH="${POLICY_PATH:-./policy.yaml}"
FEED_PATH="${FEED_PATH:-./feeds/ai-exploits.json}"
DEMO_MODEL="${DEMO_MODEL:-llama3.2:3b}"
GUARD_MODEL="${GUARD_MODEL:-llama-guard3:1b}"
JUDGE_MODEL="${JUDGE_MODEL:-llama3.2:3b}"
OPTIONAL_MODEL="granite3-guardian:2b"
MIN_OLLAMA="0.1.34"

[ -x /opt/homebrew/bin/brew ] && eval "$(/opt/homebrew/bin/brew shellenv)" 2>/dev/null
[ -d "$HOME/.bun/bin" ] && export PATH="$HOME/.bun/bin:$PATH"

if [ -t 1 ]; then C_OK=$'\033[32m'; C_FAIL=$'\033[31m'; C_WARN=$'\033[33m'; C_RST=$'\033[0m'; else C_OK=""; C_FAIL=""; C_WARN=""; C_RST=""; fi

FAILS=0
printf '%-6s %-30s %s\n' "STATUS" "CHECK" "DETAIL"
printf '%-6s %-30s %s\n' "------" "------------------------------" "------"
emit() { # emit STATUS check detail
  local c
  case "$1" in OK) c="$C_OK" ;; WARN) c="$C_WARN" ;; *) c="$C_FAIL"; FAILS=$((FAILS+1)) ;; esac
  printf '%s%-6s%s %-30s %s\n' "$c" "$1" "$C_RST" "$2" "$3"
}

have() { command -v "$1" >/dev/null 2>&1; }
version_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

port_free() { # 0 if nothing is LISTENing on the port
  if have lsof; then
    ! lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
  elif have ss; then
    ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1\$"
  else
    return 0
  fi
}
port_owner() {
  if have lsof; then lsof -nP -iTCP:"$1" -sTCP:LISTEN 2>/dev/null | awk 'NR==2{print $1" (pid "$2")"}'; fi
}

# ---- toolchain ----
if have bun; then
  v="$(bun --version)"; if version_ge "$v" "1.1.0"; then emit OK "bun" "$v"; else emit WARN "bun" "$v (< 1.1; bun upgrade)"; fi
else emit FAIL "bun" "missing"; fi

if have node; then
  v="$(node --version | sed 's/^v//')"; if version_ge "$v" "20.0.0"; then emit OK "node" "$v"; else emit WARN "node" "$v (< 20; Next.js needs 20+)"; fi
else emit FAIL "node" "missing (Next.js runtime)"; fi

if have git; then emit OK "git" "$(git --version | awk '{print $3}')"; else emit FAIL "git" "missing"; fi
if have gh; then emit OK "gh" "$(gh --version | head -n1 | awk '{print $3}')"; else emit WARN "gh" "missing (optional)"; fi

# ---- ollama ----
if have ollama; then
  v="$(ollama --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"; v="${v:-unknown}"
  if [ "$v" != unknown ] && version_ge "$v" "$MIN_OLLAMA"; then emit OK "ollama cli" "$v"; else emit WARN "ollama cli" "$v (< $MIN_OLLAMA, Probllama CVE-2024-37032)"; fi
else emit FAIL "ollama cli" "missing"; fi

TAGS="$(curl -fsS --max-time 3 "$OLLAMA_URL/api/tags" 2>/dev/null)"
if [ -n "$TAGS" ]; then
  sv="$(curl -fsS --max-time 2 "$OLLAMA_URL/api/version" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"
  emit OK "ollama server" "$OLLAMA_URL (v${sv:-?})"
  OLLAMA_UP=1
else
  emit FAIL "ollama server" "not reachable at $OLLAMA_URL"
  OLLAMA_UP=0
fi

check_model() { # check_model <tag> <role> <required|optional>
  if [ "$OLLAMA_UP" = 0 ]; then emit "$([ "$3" = required ] && echo FAIL || echo WARN)" "model $1" "unknown (server down) — $2"; return; fi
  if echo "$TAGS" | grep -q "\"name\":\"$1\""; then emit OK "model $1" "present — $2"
  else emit "$([ "$3" = required ] && echo FAIL || echo WARN)" "model $1" "not pulled — $2 (ollama pull $1)"; fi
}
check_model "$DEMO_MODEL" "demo agent (DEMO_MODEL)" required
check_model "$GUARD_MODEL" "tier-1 classifier (GUARD_MODEL)" required
[ "$JUDGE_MODEL" != "$DEMO_MODEL" ] && check_model "$JUDGE_MODEL" "tier-2 judge (JUDGE_MODEL)" required
check_model "$OPTIONAL_MODEL" "optional jailbreak classifier" optional

if [ "$OLLAMA_UP" = 1 ]; then
  loaded="$(curl -fsS --max-time 2 "$OLLAMA_URL/api/ps" 2>/dev/null | grep -o '"name":"[^"]*"' | sed 's/"name":"//;s/"//' | tr '\n' ' ')"
  emit OK "models loaded in memory" "${loaded:-none (first request will take 2–10 s per model)}"
fi

# ---- ports ----
if port_free "$GATEWAY_PORT"; then emit OK "port $GATEWAY_PORT (gateway)" "free"; else emit WARN "port $GATEWAY_PORT (gateway)" "in use by $(port_owner "$GATEWAY_PORT") — fine if that is the gateway"; fi
if port_free "$DASHBOARD_PORT"; then emit OK "port $DASHBOARD_PORT (dashboard)" "free"; else emit WARN "port $DASHBOARD_PORT (dashboard)" "in use by $(port_owner "$DASHBOARD_PORT") — fine if that is next dev"; fi

# ---- files ----
if [ -f "$ROOT/.env" ]; then
  if grep -qE '^ADMIN_TOKEN=\S+' "$ROOT/.env"; then emit OK ".env" "present, ADMIN_TOKEN set"; else emit WARN ".env" "present, ADMIN_TOKEN empty (gateway refuses to start)"; fi
else emit WARN ".env" "missing (cp .env.example .env)"; fi

[ -d "$ROOT/data" ] && emit OK "data/" "exists" || emit WARN "data/" "missing (created on first run or by setup.sh)"

if [ -f "$ROOT/$FEED_PATH" ] || [ -f "$FEED_PATH" ]; then
  if have python3 && python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$FEED_PATH" 2>/dev/null; then
    n="$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(len(d if isinstance(d,list) else d.get('entries',[])))" "$FEED_PATH" 2>/dev/null)"
    emit OK "feed $FEED_PATH" "valid JSON, ${n:-?} entries"
  elif have python3; then emit FAIL "feed $FEED_PATH" "invalid JSON"
  else emit OK "feed $FEED_PATH" "present (python3 absent, not parsed)"; fi
else emit WARN "feed $FEED_PATH" "missing (TODO until M4)"; fi

if [ -f "$POLICY_PATH" ]; then
  if [ -f "$ROOT/package.json" ] && grep -q '"policy:check"' "$ROOT/package.json" && have bun; then
    out="$(bun run --silent policy:check 2>&1)"; rc=$?
    if [ $rc -eq 0 ]; then emit OK "policy $POLICY_PATH" "validates (bun run policy:check)"; else emit FAIL "policy $POLICY_PATH" "invalid: $(echo "$out" | tail -n1)"; fi
  else
    emit OK "policy $POLICY_PATH" "present (policy:check script not available yet)"
  fi
else emit WARN "policy $POLICY_PATH" "missing (TODO until M1)"; fi

[ -d "$ROOT/node_modules" ] && emit OK "node_modules" "installed" || emit WARN "node_modules" "missing (bun install)"

# ---- running services (informational) ----
if curl -fsS --max-time 2 "http://localhost:$GATEWAY_PORT/healthz" >/dev/null 2>&1; then
  emit OK "gateway /healthz" "responding on :$GATEWAY_PORT"
else
  emit WARN "gateway /healthz" "not running (bun run dev:gateway)"
fi

printf '\n'
if [ "$FAILS" -gt 0 ]; then
  printf '%s%d required check(s) failed.%s Run ./scripts/setup.sh or see docs/SETUP.md → Troubleshooting.\n' "$C_FAIL" "$FAILS" "$C_RST"
  exit 1
fi
printf '%sAll required checks OK.%s\n' "$C_OK" "$C_RST"
