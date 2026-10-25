#!/usr/bin/env bash
# End-to-end WAF verification: managed rules, custom rules, IP ACLs,
# block/monitor modes and event reporting.
#
#   bash tests/integration/waf.sh
#
# Needs Postgres, cargo-built binaries and jq.
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18380}"
EDGE_PORT="${EDGE_PORT:-18381}"
ORIGIN_PORT="${ORIGIN_PORT:-19390}"
DOMAIN="${DOMAIN:-waf.lagran.test}"
LOG_DIR="${LOG_DIR:-/tmp/lagran-waf}"
mkdir -p "$LOG_DIR"

PIDS=()
FAILED=0
TOKEN=""
DOMAIN_ID=""
pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }
check() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }
contains() { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 (missing '$3')"; fi; }
not_contains() { if [[ "$2" != *"$3"* ]]; then pass "$1"; else fail "$1 (unexpected '$3')"; fi; }

cleanup() {
  if [[ -n "$TOKEN" && -n "$DOMAIN_ID" ]]; then
    curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID" \
      -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
  fi
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

# request <path> [curl args...] -> prints status code, body in $LOG_DIR/body
request() {
  local path=$1
  shift
  curl -s -o "$LOG_DIR/body" -D "$LOG_DIR/headers" -w '%{http_code}' \
    -H "Host: $DOMAIN" "$@" "http://127.0.0.1:$EDGE_PORT$path"
}

# wait_code <expected> <timeout seconds> <path> [curl args...]
wait_code() {
  local expected=$1 timeout=$2 path=$3
  shift 3
  local deadline=$((SECONDS + timeout)) code=""
  while ((SECONDS < deadline)); do
    code=$(request "$path" "$@")
    [[ "$code" == "$expected" ]] && { echo "$code"; return 0; }
    sleep 0.5
  done
  echo "$code"
  return 1
}

echo "== build mock origin =="
MOCK_BIN="$ROOT/target/mock-origin"
if [[ ! -x "$MOCK_BIN" || tools/mock-origin/origin.rs -nt "$MOCK_BIN" ]]; then
  rustc -O tools/mock-origin/origin.rs -o "$MOCK_BIN" || { echo "mock origin build failed"; exit 1; }
fi

"$MOCK_BIN" "$ORIGIN_PORT" >"$LOG_DIR/origin.log" 2>&1 &
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

echo "== login + domain + WAF config =="
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

# Clean slate for repeat runs (rules/IPs cascade with the domain, but the WAF
# settings row persists if the domain survived a failed previous run).
for id in $(curl -s -H "$AUTH" "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/waf/rules" \
  | jq -r '.[].id'); do
  curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/waf/rules/$id" -H "$AUTH" >/dev/null
done
for id in $(curl -s -H "$AUTH" "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/waf/ips" \
  | jq -r '.[].id'); do
  curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/waf/ips/$id" -H "$AUTH" >/dev/null
done

curl -s -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/waf" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d '{"enabled":true,"mode":"block","sqli":true,"xss":true,"traversal":true,"scanners":true}' >/dev/null
curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/waf/rules" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d '{"name":"拦截后台探测","field":"path","operator":"prefix","value":"/blocked","action":"block","priority":10}' >/dev/null
curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/waf/ips" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d '{"kind":"deny","ip":"203.0.113.9","note":"攻击来源"}' >/dev/null
curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/waf/ips" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d '{"kind":"allow","ip":"198.51.100.7","note":"监控探针"}' >/dev/null

echo "== start edge (TRUST_PROXY_HEADERS=true) =="
CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
EDGE_LISTEN="127.0.0.1:$EDGE_PORT" \
AGENT_URL="http://127.0.0.1:$EDGE_PORT" \
NODE_ID="waf-edge-$$" \
CACHE_BACKEND=memory \
CACHE_TTL=60 \
TRUST_PROXY_HEADERS=true \
WAF_REPORT_INTERVAL=2 \
./target/debug/lagran-edge >"$LOG_DIR/edge.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 80); do
  curl -sf "http://127.0.0.1:$EDGE_PORT/__lagran/health" >/dev/null && break
  sleep 0.5
done
CODE=$(wait_code 200 20 "/" -H 'X-Forwarded-For: 198.51.100.1')
check "edge synced domain" "$CODE" "200"

echo "== managed rules (block mode) =="
CODE=$(request "/search?q=1%27%20or%20%271%27=%271" -H 'X-Forwarded-For: 198.51.100.1')
check "SQLi query blocked" "$CODE" "403"
contains "block page is the WAF page" "$(cat "$LOG_DIR/body")" "安全拦截"
contains "block page carries WAF header" "$(cat "$LOG_DIR/headers")" "x-lagran-waf: blocked"
contains "block page has error code" "$(cat "$LOG_DIR/headers")" "WAF_BLOCKED"

CODE=$(request "/x?q=%3Cscript%3Ealert(1)%3C/script%3E" -H 'X-Forwarded-For: 198.51.100.1')
check "XSS query blocked" "$CODE" "403"

CODE=$(request "/../../etc/passwd" --path-as-is -H 'X-Forwarded-For: 198.51.100.1')
check "path traversal blocked" "$CODE" "403"

CODE=$(request "/" -H 'User-Agent: sqlmap/1.7' -H 'X-Forwarded-For: 198.51.100.1')
check "scanner UA blocked" "$CODE" "403"

CODE=$(request "/.git/config" -H 'X-Forwarded-For: 198.51.100.1')
check "sensitive path blocked" "$CODE" "403"

echo "== custom rule =="
CODE=$(request "/blocked" -H 'X-Forwarded-For: 198.51.100.1')
check "custom path rule blocked" "$CODE" "403"
contains "custom rule name in header" "$(cat "$LOG_DIR/headers")" "x-lagran-waf-rule:"

echo "== IP ACL =="
CODE=$(request "/" -H 'X-Forwarded-For: 203.0.113.9')
check "deny-listed IP blocked" "$CODE" "403"
contains "deny verdict is ip_deny" "$(cat "$LOG_DIR/body")" "IP 黑名单"

CODE=$(request "/search?q=union%20select" -H 'X-Forwarded-For: 198.51.100.7')
check "allow-listed IP bypasses WAF" "$CODE" "200"

echo "== events (block) =="
sleep 3
EVENTS=$(curl -s -H "$AUTH" "http://127.0.0.1:$CONTROL_PORT/api/v1/waf/events?domain=$DOMAIN&limit=50")
BLOCKS=$(printf '%s' "$EVENTS" | jq '[.[] | select(.action == "block")] | length')
if [[ "${BLOCKS:-0}" -ge 5 ]]; then
  pass "block events recorded ($BLOCKS)"
else
  fail "block events recorded (got ${BLOCKS:-0})"
fi
contains "event carries category" "$EVENTS" '"category":"sqli"'
contains "event carries rule name" "$EVENTS" '"rule_name":"SQL 注入"'

echo "== monitor mode =="
curl -s -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/waf" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d '{"enabled":true,"mode":"monitor","sqli":true,"xss":true,"traversal":true,"scanners":true}' >/dev/null

CODE=$(wait_code 200 20 "/search?q=union%20select" -H 'X-Forwarded-For: 198.51.100.1')
check "monitor mode lets malicious request through" "$CODE" "200"

sleep 3
MONITOR=$(curl -s -H "$AUTH" "http://127.0.0.1:$CONTROL_PORT/api/v1/waf/events?domain=$DOMAIN&action=monitor&limit=20")
MONITORED=$(printf '%s' "$MONITOR" | jq 'length')
if [[ "${MONITORED:-0}" -ge 1 ]]; then
  pass "monitor events recorded ($MONITORED)"
else
  fail "monitor events recorded (got ${MONITORED:-0})"
fi

echo "== disable WAF =="
curl -s -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/waf" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d '{"enabled":false,"mode":"block","sqli":true,"xss":true,"traversal":true,"scanners":true}' >/dev/null

CODE=$(wait_code 200 20 "/search?q=union%20select" -H 'X-Forwarded-For: 198.51.100.1')
check "disabled WAF stops blocking" "$CODE" "200"

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL WAF CHECKS PASSED"
else
  echo "$FAILED WAF CHECK(S) FAILED (logs: $LOG_DIR)"
  exit 1
fi
