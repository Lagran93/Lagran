#!/usr/bin/env bash
# End-to-end verification of the cache TTL precedence:
#
#   rule TTL → origin s-maxage → origin max-age → Expires → domain default
#
# Strategy: run the edge with a small default TTL (2s) and observe whether a
# cached object is still HIT a few seconds later. A layer that wins makes the
# object expire early; a layer that is ignored lets the default/other value win.
#
# The last section kills the mock origin to check the origin-down behaviour:
# fresh cache still served, expired cache → HTML error page (502/503).
#
#   bash tests/integration/ttl.sh
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18280}"
EDGE_PORT="${EDGE_PORT:-18281}"
ORIGIN_PORT="${ORIGIN_PORT:-19290}"
DOMAIN="${DOMAIN:-ttl.lagran.test}"
DEFAULT_TTL="${DEFAULT_TTL:-2}"
LOG_DIR="${LOG_DIR:-/tmp/lagran-ttl}"
mkdir -p "$LOG_DIR"

PIDS=()
FAILED=0
pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }
contains() { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 (missing '$3')"; fi; }
cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

jget() { printf '%s' "$1" | jq -r "$2"; }
req() { curl -s -D - -o /dev/null -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT$1"; }

echo "== build mock origin =="
MOCK_BIN="$ROOT/target/mock-origin"
if [[ ! -x "$MOCK_BIN" || tools/mock-origin/origin.rs -nt "$MOCK_BIN" ]]; then
  rustc -O tools/mock-origin/origin.rs -o "$MOCK_BIN" || { echo "failed to build mock origin"; exit 1; }
fi

"$MOCK_BIN" "$ORIGIN_PORT" >"$LOG_DIR/origin.log" 2>&1 &
ORIGIN_PID=$!
PIDS+=($!)
CONTROL_BIND="127.0.0.1:$CONTROL_PORT" ./target/debug/lagran-control >"$LOG_DIR/control.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 60); do
  curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null && break
  sleep 0.5
done
curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null || {
  echo "control did not start"; tail -20 "$LOG_DIR/control.log"; exit 1
}

TOKEN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r '.token // empty')
AUTH="authorization: Bearer $TOKEN"
[[ -n "$TOKEN" ]] || { echo "login failed"; exit 1; }

# Domain (idempotent across runs) + exactly one rule: /ttl/rule -> 1s.
CREATE=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"$DOMAIN\",\"origin_host\":\"127.0.0.1\",\"origin_port\":$ORIGIN_PORT,\"origin_proto\":\"http\"}")
DOMAIN_ID=$(jget "$CREATE" '.id // empty')
if [[ -z "$DOMAIN_ID" ]]; then
  DOMAIN_ID=$(curl -s -H "$AUTH" "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" \
    | jq -r --arg n "$DOMAIN" '.[] | select(.name == $n) | .id')
fi
[[ -n "$DOMAIN_ID" ]] || { echo "could not create/find $DOMAIN"; exit 1; }

# Re-runs may already have the domain: force this run's mock origin onto it.
curl -s -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"origin_host\":\"127.0.0.1\",\"origin_port\":$ORIGIN_PORT,\"origin_proto\":\"http\"}" >/dev/null

for id in $(curl -s -H "$AUTH" "http://127.0.0.1:$CONTROL_PORT/api/v1/rules" \
  | jq -r --arg d "$DOMAIN_ID" '.[] | select(.domain_id == $d) | .id'); do
  curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/rules/$id" -H "$AUTH" >/dev/null
done
curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/rules" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"domain_id\":\"$DOMAIN_ID\",\"path_pattern\":\"/ttl/rule\",\"ttl_seconds\":1,\"action\":\"cache\"}" >/dev/null

echo "== start edge (CACHE_TTL=$DEFAULT_TTL) =="
CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
EDGE_LISTEN="127.0.0.1:$EDGE_PORT" \
AGENT_URL="http://127.0.0.1:$EDGE_PORT" \
NODE_ID="ttl-edge-$$" \
CACHE_BACKEND=memory \
CACHE_TTL="$DEFAULT_TTL" \
./target/debug/lagran-edge >"$LOG_DIR/edge.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 80); do
  curl -sf "http://127.0.0.1:$EDGE_PORT/__lagran/health" >/dev/null && break
  sleep 0.5
done
for _ in $(seq 1 40); do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/")
  [[ "$CODE" == "200" ]] && break
  sleep 0.5
done
[[ "$CODE" == "200" ]] || { echo "edge did not pick up $DOMAIN"; tail -20 "$LOG_DIR/edge.log"; exit 1; }

# Warm + confirm the object is actually cached, then require it to be gone.
cached_then_expired() {
  local path=$1 h
  h=$(req "$path")
  contains "$path stored (MISS)" "$h" "x-cache: MISS"
  h=$(req "$path")
  contains "$path served from cache (HIT)" "$h" "x-cache: HIT"
  sleep 2.5
  h=$(req "$path")
  if [[ "$h" == *"x-cache: HIT"* ]]; then
    fail "$path still HIT after 2.5s — the shorter TTL did not win"
  else
    pass "$path expired after ~1s as expected"
  fi
}

cached_then_fresh() {
  local path=$1 h
  h=$(req "$path")
  contains "$path stored (MISS)" "$h" "x-cache: MISS"
  h=$(req "$path")
  contains "$path served from cache (HIT)" "$h" "x-cache: HIT"
  sleep 2.5
  h=$(req "$path")
  contains "$path still HIT after 2.5s (long TTL used)" "$h" "x-cache: HIT"
}

echo "== 1. rule TTL (1s) beats origin max-age=60 =="
cached_then_expired "/ttl/rule"

echo "== 2. s-maxage=1 beats max-age=60 =="
cached_then_expired "/ttl/smax"

echo "== 3. max-age=1 beats far-future Expires =="
cached_then_expired "/ttl/maxage"

echo "== 4. Expires is used when no Cache-Control (not the 2s default) =="
cached_then_fresh "/ttl/expires"

echo "== 5. nothing declared -> domain default CACHE_TTL=2s =="
H=$(req "/ttl/default")
contains "default: stored (MISS)" "$H" "x-cache: MISS"
H=$(req "/ttl/default")
contains "default: served from cache (HIT)" "$H" "x-cache: HIT"
sleep 3.5
H=$(req "/ttl/default")
if [[ "$H" == *"x-cache: HIT"* ]]; then
  fail "/ttl/default still HIT after 3.5s — default TTL not applied"
else
  pass "/ttl/default expired after ~${DEFAULT_TTL}s as expected"
fi

echo "== 6. origin down: fresh cache still served, expired cache shows page =="
# Warm a long-TTL object (/cached: max-age=120) and the 1s rule object.
req "/cached" >/dev/null
req "/cached" >/dev/null
req "/ttl/rule" >/dev/null
req "/ttl/rule" >/dev/null

kill "$ORIGIN_PID" 2>/dev/null
sleep 0.3

H=$(req "/cached")
contains "fresh cache still served while origin is down" "$H" "x-cache: HIT"

sleep 2.5
curl -s -D "$LOG_DIR/down.hdr" -o "$LOG_DIR/down.html" -w '%{http_code}' \
  -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/ttl/rule" >"$LOG_DIR/down.code" || true
CODE=$(cat "$LOG_DIR/down.code")
if [[ "$CODE" == "502" || "$CODE" == "503" ]]; then
  pass "expired cache + dead origin -> $CODE"
else
  fail "expired cache + dead origin status (got $CODE)"
fi
grep -qi '^x-lagran-error: ORIGIN_' "$LOG_DIR/down.hdr" \
  && pass "origin-down page carries ORIGIN_* code" || fail "origin-down page code"
grep -qi '^cache-control: no-store' "$LOG_DIR/down.hdr" \
  && pass "origin-down page is no-store" || fail "origin-down page cache-control"
grep -q '源站' "$LOG_DIR/down.html" \
  && pass "origin-down page explains the problem" || fail "origin-down page body"

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL TTL PRECEDENCE + ORIGIN-DOWN CHECKS PASSED"
else
  echo "$FAILED TTL CHECK(S) FAILED (logs: $LOG_DIR)"
  exit 1
fi
