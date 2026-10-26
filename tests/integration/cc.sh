#!/usr/bin/env bash
# CC / L7 flood protection E2E: per-IP rate limit, auto-ban, allowlist,
# monitor mode and 429 headers.
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18600}"
EDGE_PORT="${EDGE_PORT:-18601}"
EDGE2_PORT="${EDGE2_PORT:-18602}"
ORIGIN_PORT="${ORIGIN_PORT:-19600}"
DOMAIN="cc-$$.test"
LOG_DIR="${LOG_DIR:-/tmp/lagran-cc}"
mkdir -p "$LOG_DIR"

PIDS=()
FAILED=0
TOKEN=""
DOMAIN_ID=""
NODE_NAME="cc-edge-$$"
NODE2_NAME="cc-edge2-$$"
NODE_TOKEN=""

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }
check() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }

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
get() { curl -s -H "Host: $DOMAIN" -D "$LOG_DIR/h" -o "$LOG_DIR/b" -w '%{http_code}' "http://127.0.0.1:$EDGE_PORT$1"; }
get2() { curl -s -H "Host: $DOMAIN" -D "$LOG_DIR/h2" -o "$LOG_DIR/b2" -w '%{http_code}' "http://127.0.0.1:$EDGE2_PORT$1"; }
hdr2() { tr -d '\r' <"$LOG_DIR/h2" | awk -F': ' -v k="$1" 'tolower($1)==k{print $2}' | head -1; }
hdr() { tr -d '\r' <"$LOG_DIR/h" | awk -F': ' -v k="$1" 'tolower($1)==k{print $2}' | head -1; }

echo "== build mock origin =="
MOCK_BIN="$ROOT/target/mock-origin"
if [[ ! -x "$MOCK_BIN" || tools/mock-origin/origin.rs -nt "$MOCK_BIN" ]]; then
  rustc -O tools/mock-origin/origin.rs -o "$MOCK_BIN" || { echo "mock origin build failed"; exit 1; }
fi
"$MOCK_BIN" "$ORIGIN_PORT" >"$LOG_DIR/origin.log" 2>&1 &
PIDS+=($!)

echo "== start control =="
CONTROL_BIND="127.0.0.1:$CONTROL_PORT" AGENT_TOKEN=test-global ./target/debug/lagran-control >"$LOG_DIR/control.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null && break; sleep 0.25; done
curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null || { echo "control did not start"; exit 1; }

TOKEN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r '.token // empty')
[[ -n "$TOKEN" ]] || { echo "login failed"; exit 1; }

api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" \
  -d "{\"name\":\"$DOMAIN\",\"origin_host\":\"127.0.0.1\",\"origin_port\":$ORIGIN_PORT,\"origin_proto\":\"http\"}" >/dev/null
DOMAIN_ID=$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" | jq -r --arg n "$DOMAIN" '.[] | select(.name == $n) | .id')
[[ -n "$DOMAIN_ID" ]] || { echo "domain creation failed"; exit 1; }

NODE_RESP=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" \
  -d "{\"name\":\"$NODE_NAME\",\"region\":\"test\",\"agent_url\":\"http://127.0.0.1:$EDGE_PORT\"}")
NODE_TOKEN=$(printf '%s' "$NODE_RESP" | jq -r '.token // empty')
[[ -n "$NODE_TOKEN" ]] || { echo "node creation failed"; exit 1; }

echo "== enable CC =="
api -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/settings" \
  -d '{"cc_enabled":true,"cc_rps":1,"cc_burst":0,"cc_ban_after":1,"cc_ban_seconds":60,"cc_mode":"block","cc_allow_ips":""}' >/dev/null

echo "== start edge =="
CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
NODE_ID="$NODE_NAME" \
AGENT_TOKEN="$NODE_TOKEN" \
EDGE_LISTEN="127.0.0.1:$EDGE_PORT" \
ORIGIN_URL="http://127.0.0.1:$ORIGIN_PORT" \
CACHE_BACKEND=memory \
CC_SYNC_INTERVAL=2 \
./target/debug/lagran-edge >"$LOG_DIR/edge.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$EDGE_PORT/__lagran/health" >/dev/null && break; sleep 0.25; done

sleep 3

echo "== per-IP limit + auto-ban =="
CODE=$(get "/")
check "first request allowed" "$CODE" "200"
CODE=$(get "/")
check "second request banned" "$CODE" "429"
check "ban header" "$(hdr x-lagran-cc)" "banned"
check "retry-after present" "$([[ -n "$(hdr retry-after)" ]] && echo yes)" "yes"
CODE=$(get "/")
check "banned IP stays blocked" "$CODE" "429"

echo "== cross-node shared ban =="
NODE2_RESP=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" \
  -d "{\"name\":\"$NODE2_NAME\",\"region\":\"test\",\"agent_url\":\"http://127.0.0.1:$EDGE2_PORT\"}")
NODE2_TOKEN=$(printf '%s' "$NODE2_RESP" | jq -r '.token // empty')
[[ -n "$NODE2_TOKEN" ]] || { echo "second node creation failed"; exit 1; }
CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
NODE_ID="$NODE2_NAME" \
AGENT_TOKEN="$NODE2_TOKEN" \
EDGE_LISTEN="127.0.0.1:$EDGE2_PORT" \
ORIGIN_URL="http://127.0.0.1:$ORIGIN_PORT" \
CACHE_BACKEND=memory \
CC_SYNC_INTERVAL=2 \
./target/debug/lagran-edge >"$LOG_DIR/edge2.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$EDGE2_PORT/__lagran/health" >/dev/null && break; sleep 0.25; done
SHARED=0
for _ in $(seq 1 40); do
  CODE=$(get2 "/")
  [[ "$CODE" == "429" ]] && { SHARED=1; break; }
  sleep 0.25
done
check "second edge receives shared ban" "$SHARED" "1"
check "second edge ban header" "$(hdr2 x-lagran-cc)" "banned"
BANS=$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/cc/bans/all?domain=$DOMAIN")
check "control plane lists shared ban" "$(printf '%s' "$BANS" | jq -r '.bans[0].ip')" "127.0.0.1"

echo "== allowlist bypasses ban =="
api -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/settings" \
  -d '{"cc_allow_ips":"127.0.0.1/32"}' >/dev/null
ALLOWED=0
for _ in $(seq 1 80); do
  CODE=$(get "/")
  [[ "$CODE" == "200" ]] && { ALLOWED=1; break; }
  sleep 0.25
done
check "allowlisted IP is not blocked" "$ALLOWED" "1"

echo "== monitor mode =="
api -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/settings" \
  -d '{"cc_allow_ips":"","cc_mode":"monitor"}' >/dev/null
MONITORED=0
for _ in $(seq 1 80); do
  CODE=$(get "/")
  [[ "$CODE" == "200" ]] && { MONITORED=1; break; }
  sleep 0.25
done
check "monitor mode does not block" "$MONITORED" "1"

echo "== manual unban =="
DEL=$(api -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/cc/bans/$DOMAIN/127.0.0.1" | jq -r '.deleted')
check "admin deletes shared ban" "$DEL" "1"
BANS=$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/cc/bans/all?domain=$DOMAIN")
check "ban list is empty after unban" "$(printf '%s' "$BANS" | jq -r '.bans | length')" "0"
api -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/settings" \
  -d '{"cc_mode":"block"}' >/dev/null
CLEARED=0
for _ in $(seq 1 80); do
  CODE=$(get "/")
  [[ "$CODE" == "200" ]] && { CLEARED=1; break; }
  sleep 0.25
done
check "reporting edge clears local ban after admin unban" "$CLEARED" "1"

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL CC CHECKS PASSED"
else
  echo "$FAILED CC CHECK(S) FAILED (logs: $LOG_DIR)"
  exit 1
fi
