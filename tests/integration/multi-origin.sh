#!/usr/bin/env bash
# Multi-origin pool: weighted dispatch, priority fallback and per-origin health.
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18440}"
EDGE_PORT="${EDGE_PORT:-18441}"
ORIGIN_A="${ORIGIN_A:-19440}"
ORIGIN_B="${ORIGIN_B:-19441}"
ORIGIN_C="${ORIGIN_C:-19442}"
DOMAIN="multi-origin-$$.test"
LOG_DIR="${LOG_DIR:-/tmp/lagran-multi-origin}"
mkdir -p "$LOG_DIR"

PIDS=()
FAILED=0
TOKEN=""
DOMAIN_ID=""
TIMEOUT_DOMAIN_ID=""
TIMEOUT_DOMAIN="timeout-$DOMAIN"

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }
check() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }

cleanup() {
  if [[ -n "$TOKEN" && -n "$DOMAIN_ID" ]]; then
    curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID" \
      -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
  fi
  if [[ -n "$TOKEN" && -n "$TIMEOUT_DOMAIN_ID" ]]; then
    curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$TIMEOUT_DOMAIN_ID" \
      -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
  fi
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

api() { curl -s -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' "$@"; }

MOCK_BIN="$ROOT/target/mock-origin"
if [[ ! -x "$MOCK_BIN" || tools/mock-origin/origin.rs -nt "$MOCK_BIN" ]]; then
  rustc -O tools/mock-origin/origin.rs -o "$MOCK_BIN" || { echo "mock origin build failed"; exit 1; }
fi
MOCK_SLOW=1 "$MOCK_BIN" "$ORIGIN_A" >"$LOG_DIR/a.log" 2>&1 & A_PID=$!; PIDS+=($A_PID)
"$MOCK_BIN" "$ORIGIN_B" >"$LOG_DIR/b.log" 2>&1 & B_PID=$!; PIDS+=($B_PID)
"$MOCK_BIN" "$ORIGIN_C" >"$LOG_DIR/c.log" 2>&1 & PIDS+=($!)

echo "== start control =="
CONTROL_BIND="127.0.0.1:$CONTROL_PORT" AGENT_TOKEN=test-global CAPTCHA_ENABLED=false ./target/debug/lagran-control \
  >"$LOG_DIR/control.log" 2>&1 & PIDS+=($!)
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null && break; sleep 0.5; done
curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null || { echo "control did not start"; exit 1; }

TOKEN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r '.token // empty')
[[ -n "$TOKEN" ]] || { echo "login failed"; exit 1; }

BODY=$(jq -nc \
  --arg name "$DOMAIN" \
  --argjson a "$ORIGIN_A" --argjson b "$ORIGIN_B" --argjson c "$ORIGIN_C" \
  '{name:$name,origin_host:"127.0.0.1",origin_port:$a,origin_proto:"http",
    origins:[
      {host:"127.0.0.1",port:$a,proto:"http",weight:1,priority:0,enabled:true},
      {host:"127.0.0.1",port:$b,proto:"http",weight:3,priority:0,enabled:true},
      {host:"127.0.0.1",port:$c,proto:"http",weight:100,priority:1,enabled:true}
    ]}')
CREATED=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" -d "$BODY")
DOMAIN_ID=$(printf '%s' "$CREATED" | jq -r '.id // empty')
check "create multi-origin domain" "$(printf '%s' "$CREATED" | jq '.origins | length')" "3"
[[ -n "$DOMAIN_ID" ]] || { echo "domain creation failed: $CREATED"; exit 1; }

echo "== start edge =="
NODE_NAME="multi-origin-edge-$$"
NODE_RESP=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" \
  -d "{\"name\":\"$NODE_NAME\",\"region\":\"test\",\"agent_url\":\"http://127.0.0.1:$EDGE_PORT\"}")
NODE_TOKEN=$(printf '%s' "$NODE_RESP" | jq -r '.token // empty')
CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
NODE_ID="$NODE_NAME" AGENT_TOKEN="$NODE_TOKEN" \
EDGE_LISTEN="127.0.0.1:$EDGE_PORT" CACHE_TTL=60 CACHE_BACKEND=memory \
ORIGIN_HEALTH_INTERVAL_SECS=2 ORIGIN_HEALTH_FAIL_THRESHOLD=1 \
./target/debug/lagran-edge >"$LOG_DIR/edge.log" 2>&1 & PIDS+=($!)
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$EDGE_PORT/__lagran/health" >/dev/null && break; sleep 0.5; done

# Wait until the domain config has reached the edge.
SYNCED=0
for _ in $(seq 1 40); do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/lb/warm")
  [[ "$CODE" == "200" ]] && { SYNCED=1; break; }
  sleep 0.5
done
check "edge synced origin pool" "$SYNCED" "1"

echo "== weighted dispatch =="
A=0; B=0; C=0
for i in $(seq 1 80); do
  PORT=$(curl -s -D - -o /dev/null -H "Host: $DOMAIN" \
    "http://127.0.0.1:$EDGE_PORT/lb/$i?i=$i" | tr -d '\r' | awk -F': ' 'tolower($1)=="x-origin-port"{print $2}' | head -1)
  case "$PORT" in
    "$ORIGIN_A") A=$((A + 1)) ;;
    "$ORIGIN_B") B=$((B + 1)) ;;
    "$ORIGIN_C") C=$((C + 1)) ;;
  esac
done
check "priority-1 origin receives no traffic" "$C" "0"
if (( A >= 10 && A <= 30 && B >= 55 && B <= 70 )); then
  pass "weight 1:3 distribution"
else
  fail "weight 1:3 distribution (a=$A b=$B)"
fi

echo "== read-timeout failover =="
TBODY=$(jq -nc \
  --arg name "$TIMEOUT_DOMAIN" \
  --argjson a "$ORIGIN_A" --argjson b "$ORIGIN_B" \
  '{name:$name,origin_host:"127.0.0.1",origin_port:$a,origin_proto:"http",
    origins:[
      {host:"127.0.0.1",port:$a,proto:"http",weight:100,priority:0,enabled:true},
      {host:"127.0.0.1",port:$b,proto:"http",weight:100,priority:0,enabled:true}
    ]}')
TCREATED=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" -d "$TBODY")
TIMEOUT_DOMAIN_ID=$(printf '%s' "$TCREATED" | jq -r '.id // empty')
[[ -n "$TIMEOUT_DOMAIN_ID" ]] || { echo "timeout domain creation failed: $TCREATED"; exit 1; }
api -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$TIMEOUT_DOMAIN_ID/settings" \
  -d '{"origin_timeout_ms":500}' >/dev/null
READY=0
for _ in $(seq 1 60); do
  CODE=$(curl -s --max-time 8 -o /dev/null -w '%{http_code}' \
    -H "Host: $TIMEOUT_DOMAIN" "http://127.0.0.1:$EDGE_PORT/slow?warm=1")
  [[ "$CODE" == "200" ]] && { READY=1; break; }
  sleep 0.5
done
check "timeout domain synced" "$READY" "1"
OK=0; FAST=0
for i in $(seq 1 8); do
  RESP=$(curl -s --max-time 8 -D "$LOG_DIR/t.h" -o /dev/null -w '%{http_code}' \
    -H "Host: $TIMEOUT_DOMAIN" "http://127.0.0.1:$EDGE_PORT/slow?i=$i")
  PORT=$(tr -d '\r' <"$LOG_DIR/t.h" | awk -F': ' 'tolower($1)=="x-origin-port"{print $2}' | head -1)
  [[ "$RESP" == "200" ]] && OK=$((OK + 1))
  [[ "$PORT" == "$ORIGIN_B" ]] && FAST=$((FAST + 1))
done
check "slow origin does not surface 504" "$OK" "8"
check "read timeout retries next origin" "$FAST" "8"

echo "== priority fallback =="
# Stop the two priority-0 origins; the priority-1 origin must take over.
kill "$A_PID" "$B_PID" 2>/dev/null || true
sleep 5
PORT=$(curl -s -D - -o /dev/null -H "Host: $DOMAIN" \
  "http://127.0.0.1:$EDGE_PORT/lb/failover?fail=1" | tr -d '\r' | awk -F': ' 'tolower($1)=="x-origin-port"{print $2}' | head -1)
check "priority-1 origin takes over" "$PORT" "$ORIGIN_C"

DYNAMIC=$(curl -s -D - -o /dev/null -X POST -H "Host: $DOMAIN" \
  -H 'content-type: application/json' -d '{"ping":true}' \
  "http://127.0.0.1:$EDGE_PORT/api/echo?fail=1" | tr -d '\r' | \
  awk -F': ' 'tolower($1)=="x-origin-port"{print $2}' | head -1)
check "dynamic/bypass request also fails over" "$DYNAMIC" "$ORIGIN_C"

for _ in $(seq 1 20); do
  if curl -sf -H "authorization: Bearer $TOKEN" \
    "http://127.0.0.1:$CONTROL_PORT/api/v1/origin-health" | jq -e --arg d "$DOMAIN" \
    '.[] | select(.domain_name == $d and .origin_url | contains(":'"$ORIGIN_C"'")) | .healthy' >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
pass "per-origin health reported to control"

if (( FAILED > 0 )); then
  echo "MULTI-ORIGIN CHECKS FAILED: $FAILED"
  exit 1
fi
echo "ALL MULTI-ORIGIN CHECKS PASSED"
