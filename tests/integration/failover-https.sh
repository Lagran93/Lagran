#!/usr/bin/env bash
# Backup-origin failover + domain HTTPS redirect regression.
#
#   bash tests/integration/failover-https.sh
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18450}"
EDGE_PORT="${EDGE_PORT:-18451}"
HTTPS_REDIRECT_PORT="${HTTPS_REDIRECT_PORT:-18452}"
PRIMARY_PORT="${PRIMARY_PORT:-19450}"
BACKUP_PORT="${BACKUP_PORT:-19451}"
DOMAIN="failover-$$.test"
LOG_DIR="${LOG_DIR:-/tmp/lagran-failover}"
mkdir -p "$LOG_DIR"

PIDS=()
FAILED=0
TOKEN=""
DOMAIN_ID=""
PRIMARY_PID=""

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }
check() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }
contains() { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 (missing '$3')"; fi; }

cleanup() {
  if [[ -n "$TOKEN" && -n "$DOMAIN_ID" ]]; then
    curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID" \
      -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
  fi
  [[ -n "$PRIMARY_PID" ]] && kill "$PRIMARY_PID" 2>/dev/null
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

echo "== mock origins =="
MOCK_BIN="$ROOT/target/mock-origin"
if [[ ! -x "$MOCK_BIN" || tools/mock-origin/origin.rs -nt "$MOCK_BIN" ]]; then
  rustc -O tools/mock-origin/origin.rs -o "$MOCK_BIN" || { echo "mock origin build failed"; exit 1; }
fi
"$MOCK_BIN" "$PRIMARY_PORT" >"$LOG_DIR/primary.log" 2>&1 &
PRIMARY_PID=$!
PIDS+=("$PRIMARY_PID")
"$MOCK_BIN" "$BACKUP_PORT" >"$LOG_DIR/backup.log" 2>&1 &
PIDS+=($!)

echo "== control + domain =="
CONTROL_BIND="127.0.0.1:$CONTROL_PORT" AGENT_TOKEN= ./target/debug/lagran-control >"$LOG_DIR/control.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null && break; sleep 0.5; done
curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null || { echo "control did not start"; exit 1; }

TOKEN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r '.token // empty')
[[ -n "$TOKEN" ]] || { echo "login failed"; exit 1; }

CREATE=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" \
  -d "{\"name\":\"$DOMAIN\",\"origin_host\":\"127.0.0.1\",\"origin_port\":$PRIMARY_PORT,\"origin_proto\":\"http\",\"backup_origin_host\":\"localhost\",\"backup_origin_port\":$BACKUP_PORT,\"backup_origin_proto\":\"http\"}")
DOMAIN_ID=$(printf '%s' "$CREATE" | jq -r '.id // empty')
[[ -n "$DOMAIN_ID" ]] || { echo "create failed: $CREATE"; exit 1; }

echo "== edge =="
CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
NODE_ID="failover-edge-$$" \
EDGE_LISTEN="127.0.0.1:$EDGE_PORT" \
EDGE_HTTPS_REDIRECT_PORT="$HTTPS_REDIRECT_PORT" \
CACHE_BACKEND=memory \
CACHE_TTL=60 \
./target/debug/lagran-edge >"$LOG_DIR/edge.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$EDGE_PORT/__lagran/health" >/dev/null && break; sleep 0.5; done

SYNCED=0
for _ in $(seq 1 40); do
  CODE=$(get "/nostore")
  [[ "$CODE" == "200" ]] && { SYNCED=1; break; }
  sleep 0.5
done
check "edge synced domain" "$SYNCED" "1"
check "primary origin serves first" "$(hdr x-origin-port)" "$PRIMARY_PORT"

echo "== failover when primary is down =="
kill "$PRIMARY_PID" 2>/dev/null
wait "$PRIMARY_PID" 2>/dev/null
PRIMARY_PID=""

FAILOVER=0
for _ in $(seq 1 40); do
  CODE=$(get "/nostore")
  if [[ "$CODE" == "200" && "$(hdr x-origin-port)" == "$BACKUP_PORT" ]]; then
    FAILOVER=1
    break
  fi
  sleep 0.5
done
check "backup serves after primary stops" "$FAILOVER" "1"
check "backup receives its own Host" "$(hdr x-origin-host)" "localhost"
CODE=$(get "/api/data")
check "bypass/API path also fails over" "$(hdr x-origin-port)" "$BACKUP_PORT"

echo "== HTTPS redirect toggle =="
api -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID" \
  -d '{"ssl_enabled":true}' >/dev/null

REDIRECTED=0
for _ in $(seq 1 40); do
  CODE=$(get "/page?x=1")
  if [[ "$CODE" == "301" ]]; then REDIRECTED=1; break; fi
  sleep 0.5
done
check "ssl_enabled redirects HTTP" "$REDIRECTED" "1"
check "redirect status is 301" "$CODE" "301"
check "redirect location uses HTTPS port" "$(hdr location)" "https://$DOMAIN:$HTTPS_REDIRECT_PORT/page?x=1"
check "redirect marker header" "$(hdr x-lagran-redirect)" "https"

CODE=$(get "/submit" -X POST -d 'a=1')
check "POST uses 308 redirect" "$CODE" "308"

api -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID" \
  -d '{"ssl_enabled":false}' >/dev/null
STOPPED=0
for _ in $(seq 1 40); do
  CODE=$(get "/page")
  [[ "$CODE" == "200" ]] && { STOPPED=1; break; }
  sleep 0.5
done
check "disabling HTTPS redirect takes effect" "$STOPPED" "1"

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL FAILOVER / HTTPS CHECKS PASSED"
else
  echo "$FAILED FAILOVER / HTTPS CHECK(S) FAILED (logs: $LOG_DIR)"
  exit 1
fi
