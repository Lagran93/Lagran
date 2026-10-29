#!/usr/bin/env bash
# Phase 1 scheduling: node metadata + Geo/ISP scoring + admin test + pipe sample.
#
#   bash tests/integration/schedule.sh
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18460}"
LOG_DIR="${LOG_DIR:-/tmp/lagran-schedule}"
GEO_FILE="/tmp/lagran-geo-$$.json"
mkdir -p "$LOG_DIR"

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
  {"cidr":"198.51.100.0/24","country":"CN","province":"北京","city":"北京","isp":"电信"},
  {"cidr":"192.0.2.0/24","country":"CN","province":"广东","city":"广州","isp":"联通"}
]
JSON

echo "== control with GeoIP table =="
CONTROL_BIND="127.0.0.1:$CONTROL_PORT" AGENT_TOKEN= GEOIP_JSON_PATH="$GEO_FILE" \
  CAPTCHA_ENABLED=false ./target/debug/lagran-control >"$LOG_DIR/control.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null && break; sleep 0.5; done
curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null || { echo "control did not start"; exit 1; }

TOKEN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r '.token // empty')
[[ -n "$TOKEN" ]] || { echo "login failed"; exit 1; }

# Remove nodes left by an earlier failed run.
for name in gd-telecom gd-unicom bj-telecom gd-telecom-low; do
  old_id=$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" \
    | jq -r --arg n "$name" '.[] | select(.name == $n) | .id' | head -1)
  [[ -n "$old_id" ]] && api -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes/$old_id" >/dev/null
done

create_node() {
  local name=$1 public_ip=$2 province=$3 city=$4 isp=$5 weight=$6
  local resp id token
  resp=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" \
    -d "{\"name\":\"$name\",\"region\":\"$province\",\"public_ip\":\"$public_ip\",\"province\":\"$province\",\"city\":\"$city\",\"isp\":\"$isp\",\"weight\":$weight,\"agent_url\":\"http://127.0.0.1:19000\"}")
  id=$(printf '%s' "$resp" | jq -r '.node.id')
  token=$(printf '%s' "$resp" | jq -r '.token')
  printf '%s|%s\n' "$id" "$token"
}
beat() {
  local name=$1 public_ip=$2
  curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes/heartbeat" \
    -H 'content-type: application/json' \
    -H "x-lagran-agent-token: $3" \
    -d "{\"node_id\":\"$name\",\"region\":\"test\",\"ip\":\"127.0.0.1\",\"agent_url\":\"http://127.0.0.1:19000\",\"public_ip\":\"$public_ip\",\"version\":\"0.1.0\"}" >/dev/null
}

IFS='|' read -r GD_TELECOM GD_TELECOM_TOKEN <<< "$(create_node "gd-telecom" "203.0.113.10" "广东" "深圳" "电信" 100)"
IFS='|' read -r GD_UNICOM GD_UNICOM_TOKEN <<< "$(create_node "gd-unicom" "203.0.113.11" "广东" "广州" "联通" 100)"
IFS='|' read -r BJ_TELECOM BJ_TELECOM_TOKEN <<< "$(create_node "bj-telecom" "203.0.113.12" "北京" "北京" "电信" 100)"
IFS='|' read -r GD_LOW GD_LOW_TOKEN <<< "$(create_node "gd-telecom-low" "203.0.113.13" "广东" "深圳" "电信" 10)"
NODE_IDS+=("$GD_TELECOM" "$GD_UNICOM" "$BJ_TELECOM" "$GD_LOW")

beat "gd-telecom" "203.0.113.10" "$GD_TELECOM_TOKEN"
beat "gd-unicom" "203.0.113.11" "$GD_UNICOM_TOKEN"
beat "bj-telecom" "203.0.113.12" "$BJ_TELECOM_TOKEN"
beat "gd-telecom-low" "203.0.113.13" "$GD_LOW_TOKEN"

echo "== node metadata =="
LIST=$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes")
check "node exposes public_ip" "$(printf '%s' "$LIST" | jq -r '.[] | select(.name == "gd-telecom") | .public_ip')" "203.0.113.10"
check "node exposes province" "$(printf '%s' "$LIST" | jq -r '.[] | select(.name == "gd-telecom") | .province')" "广东"
check "node exposes weight" "$(printf '%s' "$LIST" | jq -r '.[] | select(.name == "gd-telecom") | .weight')" "100"
ONLINE=$(printf '%s' "$LIST" | jq '[.[] | select(.name == "gd-telecom" or .name == "gd-unicom" or .name == "bj-telecom" or .name == "gd-telecom-low") | select(.status == "online")] | length')
check "created nodes online" "$ONLINE" "4"

sched() {
  local ip=$1
  curl -s -G "http://127.0.0.1:$CONTROL_PORT/api/v1/schedule" \
    --data-urlencode "domain=cdn.schedule.test" --data-urlencode "ip=$ip"
}

echo "== Geo/ISP scoring =="
R=$(sched "203.0.113.9")
check "Guangdong telecom picks gd-telecom" "$(printf '%s' "$R" | jq -r '.primary.name')" "gd-telecom"
check "scheduler returns ttl" "$(printf '%s' "$R" | jq -r '.ttl')" "30"
check "client province resolved" "$(printf '%s' "$R" | jq -r '.client.province')" "广东"
check "backup is another node" "$(printf '%s' "$R" | jq -r '.backup.name != .primary.name')" "true"

R=$(sched "198.51.100.7")
check "Beijing picks bj-telecom" "$(printf '%s' "$R" | jq -r '.primary.name')" "bj-telecom"

R=$(sched "192.0.2.7")
check "Guangdong unicom prefers gd-unicom" "$(printf '%s' "$R" | jq -r '.primary.name')" "gd-unicom"

R=$(curl -s -G "http://127.0.0.1:$CONTROL_PORT/api/v1/schedule" \
  --data-urlencode "domain=cdn.schedule.test" --data-urlencode "province=北京" --data-urlencode "isp=电信")
check "explicit geo override works" "$(printf '%s' "$R" | jq -r '.primary.name')" "bj-telecom"

echo "== admin test endpoint =="
T=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/schedule/test" -d '{"province":"广东","isp":"联通"}')
check "admin test returns gd-unicom" "$(printf '%s' "$T" | jq -r '.primary.name')" "gd-unicom"

echo "== disabled node excluded =="
api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes/$BJ_TELECOM/status" -d '{"enabled":false}' >/dev/null
R=$(sched "198.51.100.7")
if [[ "$(printf '%s' "$R" | jq -r '.primary.name')" != "bj-telecom" ]]; then
  pass "disabled node is not scheduled"
else
  fail "disabled node is not scheduled"
fi

echo "== PowerDNS pipe sample =="
PIPE_OUT=$(printf 'HELO\t1\nQ\tcdn.schedule.test\tIN\tA\t-1\t203.0.113.9\n' \
  | CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" AGENT_TOKEN="" \
    bash tools/dns/powerdns-pipe.sh)
contains_pipe() { if [[ "$PIPE_OUT" == *"$1"* ]]; then pass "$2"; else fail "$2"; fi; }
contains_pipe "OK" "pipe backend handshake"
contains_pipe "DATA" "pipe backend returns DATA"
contains_pipe "203.0.113.10" "pipe backend returns scheduled IP"

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL SCHEDULE CHECKS PASSED"
else
  echo "$FAILED SCHEDULE CHECK(S) FAILED (logs: $LOG_DIR)"
  exit 1
fi
