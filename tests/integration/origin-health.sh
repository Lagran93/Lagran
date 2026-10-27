#!/usr/bin/env bash
# origin_health integration: health probe marks primary down and upstream_peer
# selects the backup even though the primary TCP endpoint is still alive.
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18530}"
EDGE_PORT="${EDGE_PORT:-18532}"
ADMIN_PORT="${ADMIN_PORT:-18533}"
PRIMARY_PORT="${PRIMARY_PORT:-19550}"
BACKUP_PORT="${BACKUP_PORT:-19551}"
LOG_DIR="${LOG_DIR:-/tmp/lagran-origin-health}"
DOMAIN="health-$$.test"
mkdir -p "$LOG_DIR"

PIDS=()
FAILED=0
TOKEN=""
DOMAIN_ID=""
NODE_ID=""
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
  if [[ -n "$TOKEN" && -n "$NODE_ID" ]]; then
    curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes/$NODE_ID" \
      -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
  fi
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

echo "== build mock origin =="
MOCK_BIN="$ROOT/target/mock-origin"
if [[ ! -x "$MOCK_BIN" || tools/mock-origin/origin.rs -nt "$MOCK_BIN" ]]; then
  rustc -O tools/mock-origin/origin.rs -o "$MOCK_BIN" || { echo "mock origin build failed"; exit 1; }
fi

echo "== origins =="
MOCK_ROOT_STATUS=500 "$MOCK_BIN" "$PRIMARY_PORT" >"$LOG_DIR/primary.log" 2>&1 &
PRIMARY_PID=$!; PIDS+=("$PRIMARY_PID")
"$MOCK_BIN" "$BACKUP_PORT" >"$LOG_DIR/backup.log" 2>&1 &
PIDS+=($!)

CONTROL_BIND="127.0.0.1:$CONTROL_PORT" AGENT_TOKEN= ./target/debug/lagran-control \
  >"$LOG_DIR/control.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null && break; sleep .2; done

TOKEN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r '.token // empty')
[[ -n "$TOKEN" ]] || { echo "login failed"; exit 1; }
AUTH="authorization: Bearer $TOKEN"

NODE_NAME="health-edge-$RANDOM"
NODE=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"$NODE_NAME\",\"region\":\"test\",\"agent_url\":\"http://127.0.0.1:$ADMIN_PORT\"}")
NODE_ID=$(printf '%s' "$NODE" | jq -r '.id // empty')
NODE_TOKEN=$(printf '%s' "$NODE" | jq -r '.token // empty')
[[ -n "$NODE_TOKEN" ]] || { echo "node create failed: $NODE"; exit 1; }

CREATE=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"$DOMAIN\",\"origin_host\":\"127.0.0.1\",\"origin_port\":$PRIMARY_PORT,\"origin_proto\":\"http\",\"backup_origin_host\":\"127.0.0.1\",\"backup_origin_port\":$BACKUP_PORT,\"backup_origin_proto\":\"http\",\"ssl_enabled\":false}")
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
ORIGIN_URL="http://127.0.0.1:$PRIMARY_PORT" \
ORIGIN_HEALTH_INTERVAL_SECS=5 \
ORIGIN_HEALTH_FAIL_THRESHOLD=1 \
ORIGIN_HEALTH_RECOVER_THRESHOLD=1 \
CONFIG_SYNC_INTERVAL_SECS=5 \
CACHE_BACKEND=memory \
CERT_DIR="$LOG_DIR/certs" \
./target/debug/lagran-edge >"$LOG_DIR/edge.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 80); do
  curl -sf "http://127.0.0.1:$EDGE_PORT/__lagran/health" >/dev/null && break
  sleep .25
done

origin_port() {
  curl -s -D "$LOG_DIR/headers" -o /dev/null -H "Host: $DOMAIN" \
    "http://127.0.0.1:$EDGE_PORT/ok?probe=$RANDOM$RANDOM"
  awk 'tolower($1)=="x-origin-port:" {print $2}' "$LOG_DIR/headers" | tr -d '\r' | tail -1
}

echo "== wait for health down -> backup =="
GOT_BACKUP=0
for _ in $(seq 1 30); do
  PORT=$(origin_port)
  if [[ "$PORT" == "$BACKUP_PORT" ]]; then GOT_BACKUP=1; break; fi
  sleep 1
done
check "health-unhealthy primary selects backup" "$GOT_BACKUP" "1"
check "primary process is still alive" "$(kill -0 "$PRIMARY_PID" 2>/dev/null && echo yes || echo no)" "yes"
contains "origin marked unhealthy log" "$(cat "$LOG_DIR/edge.log")" "origin marked unhealthy"

echo "== recover primary and select primary again =="
kill "$PRIMARY_PID" 2>/dev/null
wait "$PRIMARY_PID" 2>/dev/null
PRIMARY_PID=""
sleep 1
"$MOCK_BIN" "$PRIMARY_PORT" >"$LOG_DIR/primary-recovered.log" 2>&1 &
PRIMARY_PID=$!; PIDS+=("$PRIMARY_PID")

GOT_PRIMARY=0
for _ in $(seq 1 30); do
  PORT=$(origin_port)
  if [[ "$PORT" == "$PRIMARY_PORT" ]]; then GOT_PRIMARY=1; break; fi
  sleep 1
done
check "recovered primary is selected again" "$GOT_PRIMARY" "1"

if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL ORIGIN HEALTH CHECKS PASSED"
else
  echo "$FAILED ORIGIN HEALTH CHECK(S) FAILED (logs: $LOG_DIR)"
  exit 1
fi
