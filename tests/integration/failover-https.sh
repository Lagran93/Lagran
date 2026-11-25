#!/usr/bin/env bash
# Backup-origin failover + domain HTTPS redirect regression.
#
#   bash tests/integration/failover-https.sh
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

# See head-h2.sh: a shell-level http_proxy turns curl's HTTPS calls into CONNECT
# tunnels that ignore `--resolve`, so the loopback TLS checks fail with 000.
# These tests only talk to loopback and must not use a proxy.
unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY no_proxy NO_PROXY

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
NODE_ROW_ID=""
NODE_TOKEN=""

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }
check() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }
contains() { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 (missing '$3')"; fi; }

cleanup() {
  if [[ -n "$TOKEN" && -n "$DOMAIN_ID" ]]; then
    curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID" \
      -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
  fi
  # Leaving the node row behind would keep it "online" until the heartbeat
  # timeout expires, and a later run's purge fan-out would then hit a dead
  # address with a stale token (and report success:false).
  if [[ -n "$TOKEN" && -n "$NODE_ROW_ID" ]]; then
    curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes/$NODE_ROW_ID" \
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
  curl -s --max-time 15 -H "Host: $DOMAIN" "$@" -D "$LOG_DIR/h" -o "$LOG_DIR/b" -w '%{http_code}' \
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
CONTROL_BIND="127.0.0.1:$CONTROL_PORT" AGENT_TOKEN= CAPTCHA_ENABLED=false ./target/debug/lagran-control >"$LOG_DIR/control.log" 2>&1 &
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
# The edge pulls /api/v1/config with its per-node token. Without a registered
# node the request is rejected, the registry stays empty, and every request falls
# into the legacy single-origin mode -- which points at ORIGIN_URL (default
# https://example.com) and answers 404 for the origin paths this test asserts on.
NODE=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" \
  -d "{\"name\":\"failover-edge-$$\",\"region\":\"test\",\"agent_url\":\"http://127.0.0.1:$EDGE_PORT\"}")
NODE_ROW_ID=$(printf '%s' "$NODE" | jq -r '.node.id // empty')
NODE_TOKEN=$(printf '%s' "$NODE" | jq -r '.token // empty')
[[ -n "$NODE_ROW_ID" && -n "$NODE_TOKEN" ]] || { echo "node failed: $NODE"; exit 1; }

CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
NODE_ID="failover-edge-$$" \
AGENT_TOKEN="$NODE_TOKEN" \
EDGE_LISTEN="127.0.0.1:$EDGE_PORT" \
EDGE_ADMIN_LISTEN= \
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

# The very next request must already be served by the backup: `origin_order` walks
# priority layers, so a refused primary falls through to the priority-1 origin
# within the same request (阶段 3/4 fix).
FIRST_CODE=$(get "/nostore")
FIRST_PORT=$(hdr x-origin-port)
check "first request after primary death is served by backup" "$FIRST_CODE:$FIRST_PORT" "200:$BACKUP_PORT"
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
