#!/usr/bin/env bash
# Cache diagnostics: X-Lagran-Cache-Reason, tag purge, range cache.
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18480}"
EDGE_PORT="${EDGE_PORT:-18481}"
ORIGIN_PORT="${ORIGIN_PORT:-19400}"
DOMAIN="diag-$$.test"
LOG_DIR="${LOG_DIR:-/tmp/lagran-cache-diag}"
mkdir -p "$LOG_DIR"

PIDS=()
FAILED=0
TOKEN=""
DOMAIN_ID=""

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }
check() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }
contains() { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 (missing '$3')"; fi; }

cleanup() {
  if [[ -n "$TOKEN" && -n "$DOMAIN_ID" ]]; then
    curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID" \
      -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
  fi
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

api() { curl -s -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' "$@"; }
hdr() { tr -d '\r' <"$LOG_DIR/h" | awk -F': ' -v k="$1" 'tolower($1)==k{print $2}' | head -1; }
get() {
  local path=$1
  shift
  curl -s -H "Host: $DOMAIN" "$@" -D "$LOG_DIR/h" -o "$LOG_DIR/b" -w '%{http_code}' \
    "http://127.0.0.1:$EDGE_PORT$path"
}

MOCK_BIN="$ROOT/target/mock-origin"
if [[ ! -x "$MOCK_BIN" || tools/mock-origin/origin.rs -nt "$MOCK_BIN" ]]; then
  rustc -O tools/mock-origin/origin.rs -o "$MOCK_BIN" || { echo "mock origin build failed"; exit 1; }
fi
"$MOCK_BIN" "$ORIGIN_PORT" >"$LOG_DIR/origin.log" 2>&1 & PIDS+=($!)

echo "== start control =="
CONTROL_BIND="127.0.0.1:$CONTROL_PORT" AGENT_TOKEN=test-global ALERT_EVAL_SECS=60 \
  ./target/debug/lagran-control >"$LOG_DIR/control.log" 2>&1 & PIDS+=($!)
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null && break; sleep 0.5; done
TOKEN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r .token)
[[ -n "$TOKEN" ]] || { echo "login failed"; exit 1; }

CREATED=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" \
  -d "{\"name\":\"$DOMAIN\",\"origin_host\":\"127.0.0.1\",\"origin_port\":$ORIGIN_PORT,\"origin_proto\":\"http\"}")
DOMAIN_ID=$(printf '%s' "$CREATED" | jq -r .id)
[[ -n "$DOMAIN_ID" ]] || { echo "domain failed: $CREATED"; exit 1; }

api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/rules" \
  -d "{\"domain_id\":\"$DOMAIN_ID\",\"path_pattern\":\"/api/*\",\"action\":\"bypass\",\"priority\":10}" >/dev/null
api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/rules" \
  -d "{\"domain_id\":\"$DOMAIN_ID\",\"path_pattern\":\"/*\",\"match_content_type\":\"text/html\",\"action\":\"bypass\",\"priority\":20}" >/dev/null

NODE=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" \
  -d "{\"name\":\"diag-edge-$$\",\"region\":\"test\",\"agent_url\":\"http://127.0.0.1:$EDGE_PORT\"}")
NODE_TOKEN=$(printf '%s' "$NODE" | jq -r .token)
[[ -n "$NODE_TOKEN" ]] || { echo "node failed: $NODE"; exit 1; }

echo "== start edge =="
CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
NODE_ID="diag-edge-$$" AGENT_TOKEN="$NODE_TOKEN" \
EDGE_LISTEN="127.0.0.1:$EDGE_PORT" EDGE_ADMIN_LISTEN= \
CACHE_TTL=60 CACHE_BACKEND=memory \
./target/debug/lagran-edge >"$LOG_DIR/edge.log" 2>&1 & PIDS+=($!)
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$EDGE_PORT/__lagran/health" >/dev/null && break; sleep 0.5; done
SYNCED=0
for _ in $(seq 1 40); do
  get "/warmup" >/dev/null
  [[ "$(hdr x-cache)" == "MISS" || "$(hdr x-cache)" == "HIT" ]] && { SYNCED=1; break; }
  sleep 0.5
done
check "edge synced" "$SYNCED" "1"

echo "== normal hit/miss =="
get "/cached" >/dev/null
check "miss is MISS" "$(hdr x-cache)" "MISS"
get "/cached" >/dev/null
check "second is HIT" "$(hdr x-cache)" "HIT"

echo "== request reasons =="
get "/cached" -H 'Cookie: session=1' >/dev/null
check "cookie reason" "$(hdr x-lagran-cache-reason)" "cookie"
get "/cached" -H 'Authorization: Bearer x' >/dev/null
check "authorization reason" "$(hdr x-lagran-cache-reason)" "authorization"
get "/cached" -H 'Cache-Control: no-store' >/dev/null
check "request no-store reason" "$(hdr x-lagran-cache-reason)" "no-store"
get "/api/x" >/dev/null
check "rule bypass reason" "$(hdr x-lagran-cache-reason)" "rule-bypass"
get "/html" >/dev/null
check "content-type bypass reason" "$(hdr x-lagran-cache-reason)" "content-type-bypass"

echo "== response reasons =="
get "/nostore" >/dev/null
check "origin no-store reason" "$(hdr x-lagran-cache-reason)" "no-store"
get "/private" >/dev/null
check "origin private reason" "$(hdr x-lagran-cache-reason)" "private"
get "/nocache" >/dev/null
check "origin no-cache reason" "$(hdr x-lagran-cache-reason)" "no-cache"
get "/vary-ua" >/dev/null
check "vary user-agent reason" "$(hdr x-lagran-cache-reason)" "vary:user-agent"

echo "== tag purge =="
get "/tagged" >/dev/null
check "tagged first MISS" "$(hdr x-cache)" "MISS"
get "/tagged" >/dev/null
check "tagged second HIT" "$(hdr x-cache)" "HIT"
PURGE=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/purge" \
  -d "{\"domain\":\"$DOMAIN\",\"tags\":[\"product-1\"]}")
check "tag purge succeeds" "$(printf '%s' "$PURGE" | jq -r '.success')" "true"
get "/tagged" >/dev/null
check "tag purge invalidates entry" "$(hdr x-cache)" "MISS"

echo "== range cache =="
get "/big" >/dev/null
check "full object cached" "$(hdr x-cache)" "MISS"
CODE=$(get "/big" -H 'Range: bytes=0-3')
check "range status 206" "$CODE" "206"
contains "range content-range" "$(hdr content-range)" "bytes 0-3/"
check "range served from cache" "$(hdr x-cache)" "HIT"
check "range body length" "$(wc -c < "$LOG_DIR/b")" "4"

echo "== edge prefetch =="
PREFETCH=$(curl -s -X POST "http://127.0.0.1:$EDGE_PORT/__lagran/prefetch" \
  -H "x-lagran-agent-token: $NODE_TOKEN" -H 'content-type: application/json' \
  -d "{\"domain\":\"$DOMAIN\",\"paths\":[\"/prefetched\"]}")
check "prefetch warmed" "$(printf '%s' "$PREFETCH" | jq -r '.warmed')" "1"
get "/prefetched" >/dev/null
check "prefetched path is HIT" "$(hdr x-cache)" "HIT"

echo "== control prefetch worker =="
api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/prefetch" \
  -d "{\"domain\":\"$DOMAIN\",\"paths\":[\"/workerwarm\"]}" >/dev/null
TASK_STATUS=""
for _ in $(seq 1 30); do
  TASK_STATUS=$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/prefetch/tasks" | \
    jq -r --arg d "$DOMAIN" '.[] | select(.domain==$d and .url_path=="/workerwarm") | .status' | head -1)
  [[ "$TASK_STATUS" == "done" || "$TASK_STATUS" == "failed" ]] && break
  sleep 1
done
check "control worker completes task" "$TASK_STATUS" "done"
get "/workerwarm" >/dev/null
check "control prefetched path is HIT" "$(hdr x-cache)" "HIT"

echo "== scheduled prefetch =="
SCHED=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/prefetch/schedules" \
  -d "{\"domain\":\"$DOMAIN\",\"paths\":[\"/schedwarm\"],\"interval_minutes\":5,\"enabled\":true}")
SCHED_ID=$(printf '%s' "$SCHED" | jq -r .id)
check "schedule created" "$([[ -n "$SCHED_ID" && "$SCHED_ID" != "null" ]] && echo yes)" "yes"
SCHED_STATUS=""
for _ in $(seq 1 30); do
  SCHED_STATUS=$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/prefetch/tasks" | \
    jq -r --arg d "$DOMAIN" '.[] | select(.domain==$d and .url_path=="/schedwarm" and .source=="schedule") | .status' | head -1)
  [[ "$SCHED_STATUS" == "done" || "$SCHED_STATUS" == "failed" ]] && break
  sleep 1
done
check "scheduled task completes" "$SCHED_STATUS" "done"
get "/schedwarm" >/dev/null
check "scheduled prefetched path is HIT" "$(hdr x-cache)" "HIT"
api -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/prefetch/schedules/$SCHED_ID" >/dev/null

echo "== origin shield =="
SHIELD_PORT=19500
SHIELD_LOG="$LOG_DIR/shield-host.log"
: >"$SHIELD_LOG"
MOCK_SHIELD=1 MOCK_SHIELD_LOG="$SHIELD_LOG" "$MOCK_BIN" "$SHIELD_PORT" >"$LOG_DIR/shield.log" 2>&1 & PIDS+=($!)
sleep 0.5
api -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/settings" \
  -d "{\"shield_url\":\"http://127.0.0.1:$SHIELD_PORT\"}" >/dev/null
sleep 4
SHIELD_BODY=$(curl -s -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/shield-check")
check "shield serves request" "$SHIELD_BODY" "shield-hit"
contains "shield receives public Host" "$(tail -1 "$SHIELD_LOG")" "$DOMAIN"

if (( FAILED > 0 )); then
  echo "CACHE DIAGNOSTIC CHECKS FAILED: $FAILED"
  exit 1
fi
echo "ALL CACHE DIAGNOSTIC CHECKS PASSED"
