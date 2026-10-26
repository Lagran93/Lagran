#!/usr/bin/env bash
# Authoritative DNS end-to-end: A/AAAA/SOA/NS, EDNS ECS, TCP, cache fallback.
#
#   bash tests/integration/dns.sh
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18480}"
DNS_PORT="${DNS_PORT:-15353}"
LOG_DIR="${LOG_DIR:-/tmp/lagran-dns}"
GEO_FILE="/tmp/lagran-dns-geo-$$.json"
mkdir -p "$LOG_DIR"

NODE_BIN="${NODE_BIN:-$(command -v node || true)}"
if [[ -z "$NODE_BIN" ]]; then NODE_BIN=/home/lagran/.nvm/versions/node/v24.21.0/bin/node; fi

PIDS=()
FAILED=0
TOKEN=""
NODE_IDS=()

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }
check() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }

cleanup() {
  if [[ -n "$TOKEN" ]]; then
    for id in "${NODE_IDS[@]:-}"; do
      [[ -n "$id" ]] && curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes/$id" \
        -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
    done
  fi
  rm -f "$GEO_FILE"
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

api() { curl -s -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' "$@"; }

cat >"$GEO_FILE" <<'JSON'
[
  {"cidr":"203.0.113.0/24","country":"CN","province":"广东","city":"深圳","isp":"电信"},
  {"cidr":"198.51.100.0/24","country":"CN","province":"北京","city":"北京","isp":"电信"}
]
JSON

echo "== control =="
CONTROL_BIND="127.0.0.1:$CONTROL_PORT" AGENT_TOKEN=test-global-token GEOIP_JSON_PATH="$GEO_FILE" \
DNS_TEST_SERVER="127.0.0.1:$DNS_PORT" \
  ./target/debug/lagran-control >"$LOG_DIR/control.log" 2>&1 &
CONTROL_PID=$!
PIDS+=("$CONTROL_PID")
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null && break; sleep 0.5; done
curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null || { echo "control did not start"; exit 1; }

TOKEN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r '.token // empty')
[[ -n "$TOKEN" ]] || { echo "login failed"; exit 1; }

# Remove nodes left by an earlier failed run (the stale-cache test stops
# control before cleanup can delete them).
for name in dns-gd dns-bj; do
  old_id=$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" \
    | jq -r --arg n "$name" '.[] | select(.name == $n) | .id' | head -1)
  [[ -n "$old_id" ]] && api -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes/$old_id" >/dev/null
done

create_node() {
  local name=$1 public_ip=$2 province=$3 city=$4 isp=$5
  local resp id token
  resp=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" \
    -d "{\"name\":\"$name\",\"region\":\"$province\",\"public_ip\":\"$public_ip\",\"province\":\"$province\",\"city\":\"$city\",\"isp\":\"$isp\",\"weight\":100,\"agent_url\":\"http://127.0.0.1:19000\"}")
  id=$(printf '%s' "$resp" | jq -r '.node.id')
  token=$(printf '%s' "$resp" | jq -r '.token')
  printf '%s|%s\n' "$id" "$token"
}
beat() {
  curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes/heartbeat" \
    -H 'content-type: application/json' \
    -H "x-lagran-agent-token: $3" \
    -d "{\"node_id\":\"$1\",\"region\":\"test\",\"ip\":\"127.0.0.1\",\"agent_url\":\"http://127.0.0.1:19000\",\"public_ip\":\"$2\",\"version\":\"0.1.0\"}" >/dev/null
}

IFS='|' read -r GD GD_TOKEN <<< "$(create_node "dns-gd" "203.0.113.10" "广东" "深圳" "电信")"
IFS='|' read -r BJ BJ_TOKEN <<< "$(create_node "dns-bj" "203.0.113.12" "北京" "北京" "电信")"
NODE_IDS+=("$GD" "$BJ")
beat "dns-gd" "203.0.113.10" "$GD_TOKEN"
beat "dns-bj" "203.0.113.12" "$BJ_TOKEN"

echo "== authoritative DNS =="
CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
AGENT_TOKEN=test-global-token \
DNS_LISTEN="127.0.0.1:$DNS_PORT" \
DNS_ZONE="edge.lagran.net" \
DNS_NS_NAME="ns1.edge.lagran.net,ns2.edge.lagran.net" \
DNS_NS_IP="127.0.0.1,127.0.0.2" \
DNS_TTL=30 \
DNS_CACHE_SECS=2 \
DNS_STALE_SECS=60 \
./target/debug/lagran-dns >"$LOG_DIR/dns.log" 2>&1 &
PIDS+=($!)

q() { "$NODE_BIN" tools/dns/query.mjs 127.0.0.1 "$DNS_PORT" "$@"; }

READY=0
for _ in $(seq 1 40); do
  OUT=$(q "cdn.edge.lagran.net" A 203.0.113.9/24 2>/dev/null || true)
  if [[ "$(printf '%s' "$OUT" | jq -r '.rcode // 9')" == "0" ]]; then READY=1; break; fi
  sleep 0.25
done
check "dns answers" "$READY" "1"

OUT=$(q "cdn.edge.lagran.net" A 203.0.113.9/24)
check "Guangdong ECS → gd node" "$(printf '%s' "$OUT" | jq -r '.answers[0].ip')" "203.0.113.10"
check "TTL is 30" "$(printf '%s' "$OUT" | jq -r '.answers[0].ttl')" "30"

OUT=$(q "cdn.edge.lagran.net" A 198.51.100.7/24)
check "Beijing ECS → bj node" "$(printf '%s' "$OUT" | jq -r '.answers[0].ip')" "203.0.113.12"

OUT=$(q "edge.lagran.net" SOA)
check "SOA answered" "$(printf '%s' "$OUT" | jq -r '.soa')" "true"
OUT=$(q "edge.lagran.net" NS)
check "both NS answered" "$(printf '%s' "$OUT" | jq -r '.answers | length')" "2"
OUT=$(q "ns2.edge.lagran.net" A)
check "ns2 glue A" "$(printf '%s' "$OUT" | jq -r '.answers[0].ip')" "127.0.0.2"
OUT=$(q "ns1.edge.lagran.net" A)
check "ns1 glue A" "$(printf '%s' "$OUT" | jq -r '.answers[0].ip')" "127.0.0.1"

OUT=$(q "example.com" A)
check "out-of-zone refused" "$(printf '%s' "$OUT" | jq -r '.rcode')" "5"
OUT=$(q "cdn.edge.lagran.net" ANY)
check "ANY refused" "$(printf '%s' "$OUT" | jq -r '.rcode')" "5"

OUT=$(q "cdn.edge.lagran.net" AAAA)
check "AAAA NODATA rcode" "$(printf '%s' "$OUT" | jq -r '.rcode')" "0"
check "AAAA has no answer" "$(printf '%s' "$OUT" | jq -r '.answers | length')" "0"
check "AAAA carries SOA" "$(printf '%s' "$OUT" | jq -r '.soa')" "true"

OUT=$(q "cdn.edge.lagran.net" A 203.0.113.9/24 --tcp)
check "TCP query works" "$(printf '%s' "$OUT" | jq -r '.answers[0].ip')" "203.0.113.10"

echo "== console DNS test endpoint =="
DTS=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/dns/test" \
  -d '{"name":"cdn.edge.lagran.net","ip":"203.0.113.9/24"}')
check "dns test endpoint" "$(printf '%s' "$DTS" | jq -r '.answers[0].ip')" "203.0.113.10"
check "dns test rcode" "$(printf '%s' "$DTS" | jq -r '.rcode')" "0"

echo "== cache survives control outage =="
# Delete nodes first (cleanup) while control is still reachable.
api -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes/$GD" >/dev/null 2>&1
api -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes/$BJ" >/dev/null 2>&1
NODE_IDS=()

[[ -n "$CONTROL_PID" ]] && kill "$CONTROL_PID" 2>/dev/null
sleep 3
OUT=$(q "cdn.edge.lagran.net" A 203.0.113.9/24)
check "stale cache answers after control stops" "$(printf '%s' "$OUT" | jq -r '.answers[0].ip // empty')" "203.0.113.10"

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL DNS CHECKS PASSED"
else
  echo "$FAILED DNS CHECK(S) FAILED (logs: $LOG_DIR)"
  exit 1
fi
