#!/usr/bin/env bash
# End-to-end WebSocket frame echo through Pingora's native upgrade tunnel.
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18540}"
EDGE_PORT="${EDGE_PORT:-18542}"
ADMIN_PORT="${ADMIN_PORT:-18543}"
WS_PORT="${WS_PORT:-19660}"
LOG_DIR="${LOG_DIR:-/tmp/lagran-ws-echo}"
DOMAIN="ws-$$.test"
mkdir -p "$LOG_DIR"

PIDS=()
FAILED=0
TOKEN=""
DOMAIN_ID=""
NODE_ID=""
pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }
cleanup() {
  if [[ -n "$TOKEN" && -n "$DOMAIN_ID" ]]; then
    curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID" \
      -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
  fi
  if [[ -n "$TOKEN" && -n "$NODE_ID" ]]; then
    curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes/$NODE_ID" \
      -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
  fi
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

echo "== websocket echo origin =="
perl tools/ws-echo.pl "$WS_PORT" >"$LOG_DIR/ws-origin.log" 2>&1 &
PIDS+=($!)
sleep 0.3

CONTROL_BIND="127.0.0.1:$CONTROL_PORT" AGENT_TOKEN= CAPTCHA_ENABLED=false ./target/debug/lagran-control \
  >"$LOG_DIR/control.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null && break; sleep .2; done

TOKEN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r '.token // empty')
[[ -n "$TOKEN" ]] || { echo "login failed"; exit 1; }
AUTH="authorization: Bearer $TOKEN"

NODE_NAME="ws-edge-$RANDOM"
NODE=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"$NODE_NAME\",\"region\":\"test\",\"agent_url\":\"http://127.0.0.1:$ADMIN_PORT\"}")
NODE_ID=$(printf '%s' "$NODE" | jq -r '.id // empty')
NODE_TOKEN=$(printf '%s' "$NODE" | jq -r '.token // empty')
[[ -n "$NODE_TOKEN" ]] || { echo "node create failed: $NODE"; exit 1; }

CREATE=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"$DOMAIN\",\"origin_host\":\"127.0.0.1\",\"origin_port\":$WS_PORT,\"origin_proto\":\"http\",\"ssl_enabled\":false}")
DOMAIN_ID=$(printf '%s' "$CREATE" | jq -r '.id // empty')
[[ -n "$DOMAIN_ID" ]] || { echo "domain create failed: $CREATE"; exit 1; }

echo "== edge =="
EDGE_LISTEN="127.0.0.1:$EDGE_PORT" \
EDGE_ADMIN_LISTEN="127.0.0.1:$ADMIN_PORT" \
EDGE_HTTPS_LISTEN= \
AGENT_URL="http://127.0.0.1:$ADMIN_PORT" \
AGENT_TOKEN="$NODE_TOKEN" \
CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
NODE_ID="$NODE_NAME" \
PUBLIC_IP=127.0.0.1 \
ORIGIN_URL="http://127.0.0.1:$WS_PORT" \
CONFIG_SYNC_INTERVAL_SECS=5 \
CACHE_BACKEND=memory \
CERT_DIR="$LOG_DIR/certs" \
./target/debug/lagran-edge >"$LOG_DIR/edge.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 80); do
  curl -sf "http://127.0.0.1:$EDGE_PORT/__lagran/health" >/dev/null && break
  sleep .25
done

echo "== websocket frames =="
OK=0
for _ in $(seq 1 20); do
  if perl tools/ws-client.pl 127.0.0.1 "$EDGE_PORT" "$DOMAIN" / >"$LOG_DIR/client.log" 2>&1; then
    OK=1
    break
  fi
  sleep 0.5
done

if [[ "$OK" == "1" ]]; then
  pass "websocket text/binary/ping/close echo"
else
  fail "websocket frame echo"
  cat "$LOG_DIR/client.log"
fi

if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL WEBSOCKET ECHO CHECKS PASSED"
else
  echo "$FAILED WEBSOCKET ECHO CHECK(S) FAILED (logs: $LOG_DIR)"
  exit 1
fi
