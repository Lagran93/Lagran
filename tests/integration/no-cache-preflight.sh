#!/usr/bin/env bash
# Regression test for the P0-1 bypass: a request carrying `Cache-Control:
# no-cache` used to be answered by the cache-revalidation path before the
# shared preflight ran, so WAF / CC / rate-limit / hotlink / HTTPS-redirect
# were all skipped for cached objects.
#
# The test makes per-domain rate limiting the observable preflight effect:
# once the limit is active, *both* normal and no-cache requests must be
# rejected. Before the fix every no-cache request returned 200.
#
#   bash tests/integration/no-cache-preflight.sh
#
# Needs Postgres, cargo-built debug binaries and jq.
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18382}"
EDGE_PORT="${EDGE_PORT:-18383}"
ADMIN_PORT="${ADMIN_PORT:-18384}"
ORIGIN_PORT="${ORIGIN_PORT:-19392}"
DOMAIN="${DOMAIN:-no-cache-preflight.lagran.test}"
LOG_DIR="${LOG_DIR:-/tmp/lagran-no-cache-preflight}"
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

# request <path> [curl args...] -> status code, body in $LOG_DIR/body
request() {
  local path=$1
  shift
  curl -s -o "$LOG_DIR/body" -D "$LOG_DIR/headers" -w '%{http_code}' \
    -H "Host: $DOMAIN" "$@" "http://127.0.0.1:$EDGE_PORT$path"
}

echo "== build mock origin =="
MOCK_BIN="$ROOT/target/mock-origin"
if [[ ! -x "$MOCK_BIN" || tools/mock-origin/origin.rs -nt "$MOCK_BIN" ]]; then
  rustc -O tools/mock-origin/origin.rs -o "$MOCK_BIN" || { echo "mock origin build failed"; exit 1; }
fi

"$MOCK_BIN" "$ORIGIN_PORT" >"$LOG_DIR/origin.log" 2>&1 &
PIDS+=($!)
CONTROL_BIND="127.0.0.1:$CONTROL_PORT" CAPTCHA_ENABLED=false ./target/debug/lagran-control \
  >"$LOG_DIR/control.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 60); do
  curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null && break
  sleep 0.5
done
curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null || {
  echo "control did not start"; tail -20 "$LOG_DIR/control.log"; exit 1
}

echo "== login + domain + node =="
TOKEN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r '.token // empty')
AUTH="authorization: Bearer $TOKEN"
[[ -n "$TOKEN" ]] || { echo "login failed"; exit 1; }

curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"$DOMAIN\",\"origin_host\":\"127.0.0.1\",\"origin_port\":$ORIGIN_PORT,\"origin_proto\":\"http\"}" >/dev/null
DOMAIN_ID=$(curl -s -H "$AUTH" "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" \
  | jq -r --arg n "$DOMAIN" '.[] | select(.name == $n) | .id')
[[ -n "$DOMAIN_ID" ]] || { echo "domain not found"; exit 1; }

NODE=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"no-cache-edge-$$\",\"region\":\"test\",\"agent_url\":\"http://127.0.0.1:$EDGE_PORT\"}")
NODE_TOKEN=$(printf '%s' "$NODE" | jq -r '.token // empty')
[[ -n "$NODE_TOKEN" ]] || { echo "node failed: $NODE"; exit 1; }

echo "== start edge =="
CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
EDGE_LISTEN="127.0.0.1:$EDGE_PORT" \
EDGE_ADMIN_LISTEN="127.0.0.1:$ADMIN_PORT" \
AGENT_URL="http://127.0.0.1:$EDGE_PORT" \
AGENT_TOKEN="$NODE_TOKEN" \
NODE_ID="no-cache-edge-$$" \
EDGE_HTTPS_LISTEN="" \
CACHE_BACKEND=memory \
CACHE_TTL=60 \
CONFIG_SYNC_INTERVAL_SECS=5 \
ACCESS_LOG_REPORT=false \
WAF_REPORT=false \
RUST_LOG=warn \
./target/debug/lagran-edge >"$LOG_DIR/edge.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 80); do
  curl -sf "http://127.0.0.1:$ADMIN_PORT/__lagran/health" >/dev/null && break
  sleep 0.5
done

CODE=""
for _ in $(seq 1 60); do
  CODE=$(request "/assets/app.css")
  [[ "$CODE" == "200" ]] && break
  sleep 0.5
done
check "edge synced domain" "$CODE" "200"

echo "== warm cache =="
request "/assets/app.css" >/dev/null
request "/assets/app.css" >/dev/null
contains "second request is a cache hit" "$(cat "$LOG_DIR/headers")" "x-cache: HIT"

echo "== WAF must inspect no-cache requests too =="
curl -s -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/waf" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d '{"enabled":true,"mode":"block","sqli":true,"xss":true,"traversal":true,"scanners":true,"rce":true,"ssrf":true,"xxe":true,"log4shell":true,"crlf":true,"ssti":true,"nosql":true,"ldap":true,"java":true,"webshell":true,"protocol":true,"challenge_difficulty":2,"challenge_ttl_secs":300}' >/dev/null
# Match on a header only the no-cache requests carry, so a normal warm-up
# request still fills the cache while the rule is active.
RULE=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/waf/rules" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d '{"name":"no-cache regression","field":"header:cache-control","operator":"contains","value":"no-cache","action":"block","priority":10}')
RULE_ID=$(printf '%s' "$RULE" | jq -r '.id // empty')
[[ -n "$RULE_ID" ]] || { echo "waf rule create failed: $RULE"; exit 1; }

# Re-warm after the rule exists: creating it purges the domain cache, and the
# bypass under test needs an entry to be served from.
request "/assets/app.css" >/dev/null
request "/assets/app.css" >/dev/null
contains "cache warmed while the rule is active" "$(cat "$LOG_DIR/headers")" "x-cache: HIT"

CODE=""
for _ in $(seq 1 60); do
  CODE=$(request "/assets/app.css" -H 'Cache-Control: no-cache')
  [[ "$CODE" == "403" ]] && break
  sleep 0.5
done
check "no-cache request is WAF-blocked" "$CODE" "403"

# Drop the rule again so the rate-limit check below can pass WAF.
curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/waf/rules/$RULE_ID" -H "$AUTH" >/dev/null
for _ in $(seq 1 60); do
  [[ "$(request "/assets/app.css" -H 'Cache-Control: no-cache')" == "200" ]] && break
  sleep 0.5
done

echo "== activate the rate limit (rps=1, burst=1) =="
curl -s -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d '{"rate_limit_rps":1,"rate_limit_burst":1}' >/dev/null

LIMITED=0
for _ in $(seq 1 90); do
  if [[ "$(request "/assets/app.css")" == "429" ]]; then LIMITED=1; break; fi
  sleep 0.5
done
check "rate limit reached the edge" "$LIMITED" "1"

sleep 2
echo "== 10 parallel no-cache requests must also be limited =="
TMP=$(mktemp)
CURL_PIDS=()
for _ in $(seq 1 10); do
  (curl -s -o /dev/null -w '%{http_code}\n' -H "Host: $DOMAIN" \
     -H 'Cache-Control: no-cache' "http://127.0.0.1:$EDGE_PORT/assets/app.css" >>"$TMP") &
  CURL_PIDS+=($!)
done
# Wait only for the load requests: a bare `wait` would also block on the
# control/edge/origin processes started above.
for pid in "${CURL_PIDS[@]}"; do wait "$pid"; done
BLOCKED=$(grep -c '^429$' "$TMP" || true)
ALLOWED=$(grep -c '^200$' "$TMP" || true)
cat "$TMP" | sort | uniq -c
if [[ "$BLOCKED" -ge 5 ]]; then
  pass "no-cache requests hit the same limiter ($BLOCKED/10 blocked)"
else
  fail "no-cache requests bypassed preflight (only $BLOCKED/10 blocked, $ALLOWED allowed)"
fi
rm -f "$TMP"

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "no-cache preflight: all checks passed"
else
  echo "no-cache preflight: $FAILED check(s) failed"
  echo "--- edge log tail ---"
  tail -30 "$LOG_DIR/edge.log"
  exit 1
fi
