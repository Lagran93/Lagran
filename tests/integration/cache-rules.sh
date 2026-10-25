#!/usr/bin/env bash
# Cache rule enhancements E2E: method/query conditions, disabled rules,
# browser TTL, per-rule ignore-query, rule tester, update + toggle.
#
#   bash tests/integration/cache-rules.sh
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18400}"
EDGE_PORT="${EDGE_PORT:-18401}"
ORIGIN_PORT="${ORIGIN_PORT:-19400}"
DOMAIN="rules-$$.test"
LOG_DIR="${LOG_DIR:-/tmp/lagran-rules}"
mkdir -p "$LOG_DIR"

PIDS=()
FAILED=0
TOKEN=""
DOMAIN_ID=""
RULE_BROWSER=""
RULE_OFF=""

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

# get <path> [curl args] -> status, headers in h, body in b
get() {
  local path=$1
  shift
  curl -s -H "Host: $DOMAIN" "$@" -D "$LOG_DIR/h" -o "$LOG_DIR/b" -w '%{http_code}' \
    "http://127.0.0.1:$EDGE_PORT$path"
}

echo "== build mock origin =="
MOCK_BIN="$ROOT/target/mock-origin"
if [[ ! -x "$MOCK_BIN" || tools/mock-origin/origin.rs -nt "$MOCK_BIN" ]]; then
  rustc -O tools/mock-origin/origin.rs -o "$MOCK_BIN" || { echo "mock origin build failed"; exit 1; }
fi
"$MOCK_BIN" "$ORIGIN_PORT" >"$LOG_DIR/origin.log" 2>&1 &
PIDS+=($!)

echo "== start control =="
CONTROL_BIND="127.0.0.1:$CONTROL_PORT" AGENT_TOKEN= ./target/debug/lagran-control >"$LOG_DIR/control.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null && break; sleep 0.5; done
curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null || { echo "control did not start"; exit 1; }

TOKEN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r '.token // empty')
[[ -n "$TOKEN" ]] || { echo "login failed"; exit 1; }

api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" \
  -d "{\"name\":\"$DOMAIN\",\"origin_host\":\"127.0.0.1\",\"origin_port\":$ORIGIN_PORT,\"origin_proto\":\"http\"}" >/dev/null
DOMAIN_ID=$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" | jq -r --arg n "$DOMAIN" '.[] | select(.name == $n) | .id')
[[ -n "$DOMAIN_ID" ]] || { echo "domain creation failed"; exit 1; }

echo "== create rules =="
mk_rule() { api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/rules" -d "$1"; }

mk_rule "{\"domain_id\":\"$DOMAIN_ID\",\"path_pattern\":\"/method/*\",\"action\":\"bypass\",\"match_methods\":\"GET\",\"priority\":10,\"note\":\"GET bypass\"}" >/dev/null
mk_rule "{\"domain_id\":\"$DOMAIN_ID\",\"path_pattern\":\"/q/*\",\"action\":\"bypass\",\"match_query\":\"debug=1\",\"priority\":10}" >/dev/null
RULE_OFF=$(mk_rule "{\"domain_id\":\"$DOMAIN_ID\",\"path_pattern\":\"/off/*\",\"action\":\"bypass\",\"enabled\":false,\"priority\":10}" | jq -r '.id')
RULE_BROWSER=$(mk_rule "{\"domain_id\":\"$DOMAIN_ID\",\"path_pattern\":\"/browser/*\",\"action\":\"cache\",\"ttl_seconds\":60,\"browser_ttl_seconds\":3600,\"priority\":10}" | jq -r '.id')
mk_rule "{\"domain_id\":\"$DOMAIN_ID\",\"path_pattern\":\"/iq/*\",\"action\":\"cache\",\"ttl_seconds\":60,\"ignore_query\":true,\"priority\":10}" >/dev/null

BAD=$(curl -s -o /dev/null -w '%{http_code}' -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/rules" \
  -d "{\"domain_id\":\"$DOMAIN_ID\",\"path_pattern\":\"/bad/*\",\"match_methods\":\"TRACE\"}")
check "unsupported method rejected" "$BAD" "400"

echo "== start edge =="
CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
NODE_ID="rules-edge-$$" \
EDGE_LISTEN="127.0.0.1:$EDGE_PORT" \
CACHE_TTL=60 \
CACHE_BACKEND=memory \
./target/debug/lagran-edge >"$LOG_DIR/edge.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$EDGE_PORT/__lagran/health" >/dev/null && break; sleep 0.5; done

# wait for config sync
SYNCED=0
for _ in $(seq 1 40); do
  get "/method/x" >/dev/null
  [[ "$(hdr x-cache)" == "BYPASS" ]] && { SYNCED=1; break; }
  sleep 0.5
done
check "edge synced rules" "$SYNCED" "1"

echo "== method condition =="
get "/method/x" >/dev/null
check "GET matches bypass rule" "$(hdr x-cache)" "BYPASS"
get "/method/x" -X HEAD >/dev/null
check "HEAD does not match GET-only rule (cacheable)" "$(hdr x-cache)" "MISS"
get "/method/x" -X HEAD >/dev/null
check "HEAD response cached on second hit" "$(hdr x-cache)" "HIT"

echo "== query condition =="
get "/q/x?debug=1" >/dev/null
check "query debug=1 matches bypass" "$(hdr x-cache)" "BYPASS"
get "/q/x?other=1" >/dev/null
check "other query cached (miss)" "$(hdr x-cache)" "MISS"
get "/q/x?other=1" >/dev/null
check "other query cached (hit)" "$(hdr x-cache)" "HIT"

echo "== disabled rule =="
get "/off/x" >/dev/null
check "disabled rule ignored (miss)" "$(hdr x-cache)" "MISS"
get "/off/x" >/dev/null
check "disabled rule ignored (hit)" "$(hdr x-cache)" "HIT"

echo "== browser TTL =="
get "/browser/x" >/dev/null
contains "browser TTL overrides Cache-Control" "$(hdr cache-control)" "max-age=3600"

echo "== per-rule ignore query =="
get "/iq/x?a=1" >/dev/null
check "first query variant misses" "$(hdr x-cache)" "MISS"
get "/iq/x?a=2" >/dev/null
check "second query variant hits same entry" "$(hdr x-cache)" "HIT"

echo "== rule tester =="
TEST=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/rules/test" \
  -d "{\"domain_id\":\"$DOMAIN_ID\",\"path\":\"/method/x\",\"method\":\"GET\"}")
check "tester matches method rule" "$(printf '%s' "$TEST" | jq -r '.matched.path_pattern')" "/method/*"
TEST=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/rules/test" \
  -d "{\"domain_id\":\"$DOMAIN_ID\",\"path\":\"/method/x\",\"method\":\"POST\"}")
check "tester skips GET-only rule for POST" "$(printf '%s' "$TEST" | jq -r '.matched // "none"')" "none"
TEST=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/rules/test" \
  -d "{\"domain_id\":\"$DOMAIN_ID\",\"path\":\"/off/x\"}")
check "tester ignores disabled rule" "$(printf '%s' "$TEST" | jq -r '.matched // "none"')" "none"
TEST=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/rules/test" \
  -d "{\"domain_id\":\"$DOMAIN_ID\",\"path\":\"/q/x\",\"query\":\"debug=1\"}")
check "tester matches query rule" "$(printf '%s' "$TEST" | jq -r '.matched.path_pattern')" "/q/*"
check "tester reports ignore_query override" "$(printf '%s' "$TEST" | jq -r '.effective.ignore_query')" "null"

echo "== update + toggle =="
api -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/rules/$RULE_BROWSER" \
  -d '{"ttl_seconds":120,"browser_ttl_seconds":7200}' >/dev/null
UPDATED=0
for _ in $(seq 1 50); do
  get "/browser/x" >/dev/null
  [[ "$(hdr cache-control)" == *"max-age=7200"* ]] && { UPDATED=1; break; }
  sleep 0.5
done
check "updated browser TTL reaches edge" "$UPDATED" "1"

api -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/rules/$RULE_OFF" -d '{"enabled":true}' >/dev/null
ENABLED=0
for _ in $(seq 1 50); do
  get "/off/x" >/dev/null
  [[ "$(hdr x-cache)" == "BYPASS" ]] && { ENABLED=1; break; }
  sleep 0.5
done
check "enabling rule takes effect on edge" "$ENABLED" "1"

api -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/rules/$RULE_OFF" -d '{"enabled":false}' >/dev/null
DISABLED=0
for _ in $(seq 1 50); do
  get "/off/x" >/dev/null
  [[ "$(hdr x-cache)" != "BYPASS" ]] && { DISABLED=1; break; }
  sleep 0.5
done
check "disabling rule takes effect on edge" "$DISABLED" "1"

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL CACHE RULE CHECKS PASSED"
else
  echo "$FAILED CACHE RULE CHECK(S) FAILED (logs: $LOG_DIR)"
  exit 1
fi
