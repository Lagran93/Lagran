#!/usr/bin/env bash
# Backup origin regression: create/list/update/clear + config propagation.
#
#   bash tests/integration/backup-origin.sh
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18420}"
DOMAIN="backup-$$.test"
LOG_DIR="${LOG_DIR:-/tmp/lagran-backup}"
mkdir -p "$LOG_DIR"

PIDS=()
FAILED=0
TOKEN=""
DOMAIN_ID=""
NODE_ID=""

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }
check() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }

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

api() { curl -s -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' "$@"; }

echo "== start control =="
CONTROL_BIND="127.0.0.1:$CONTROL_PORT" AGENT_TOKEN= ./target/debug/lagran-control >"$LOG_DIR/control.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null && break; sleep 0.5; done
curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null || { echo "control did not start"; exit 1; }

TOKEN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r '.token // empty')
[[ -n "$TOKEN" ]] || { echo "login failed"; exit 1; }

NODE_NAME="backup-node-$$"
NODE=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d "{\"name\":\"$NODE_NAME\",\"region\":\"test\",\"agent_url\":\"http://127.0.0.1:1\"}")
NODE_ID=$(printf '%s' "$NODE" | jq -r '.id // empty')
NODE_TOKEN=$(printf '%s' "$NODE" | jq -r '.token // empty')
[[ -n "$NODE_TOKEN" ]] || { echo "node token failed: $NODE"; exit 1; }
AGENT=(-H "x-lagran-agent-token: $NODE_TOKEN")

echo "== create with backup origin =="
CREATE=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" \
  -d "{\"name\":\"$DOMAIN\",\"origin_host\":\"127.0.0.1\",\"origin_port\":19430,\"origin_proto\":\"http\",\"backup_origin_host\":\"backup.example.com\",\"backup_origin_port\":8443,\"backup_origin_proto\":\"https\"}")
DOMAIN_ID=$(printf '%s' "$CREATE" | jq -r '.id // empty')
[[ -n "$DOMAIN_ID" ]] || { echo "create failed: $CREATE"; exit 1; }
check "create returns backup host" "$(printf '%s' "$CREATE" | jq -r '.backup_origin_host')" "backup.example.com"
check "create returns backup port" "$(printf '%s' "$CREATE" | jq -r '.backup_origin_port')" "8443"
check "create returns backup proto" "$(printf '%s' "$CREATE" | jq -r '.backup_origin_proto')" "https"

echo "== list exposes backup origin =="
LIST=$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/domains")
check "list backup host" "$(printf '%s' "$LIST" | jq -r --arg id "$DOMAIN_ID" '.[] | select(.id == $id) | .backup_origin_host')" "backup.example.com"
check "list backup port" "$(printf '%s' "$LIST" | jq -r --arg id "$DOMAIN_ID" '.[] | select(.id == $id) | .backup_origin_port')" "8443"

echo "== update backup origin =="
UPD=$(api -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID" \
  -d '{"backup_origin_host":"backup2.example.com","backup_origin_port":9443,"backup_origin_proto":"https"}')
check "update returns new host" "$(printf '%s' "$UPD" | jq -r '.backup_origin_host')" "backup2.example.com"
check "update returns new port" "$(printf '%s' "$UPD" | jq -r '.backup_origin_port')" "9443"
check "origin unchanged" "$(printf '%s' "$UPD" | jq -r '.origin_host')" "127.0.0.1"

echo "== port defaults by protocol =="
UPD=$(api -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID" \
  -d '{"backup_origin_host":"backup3.example.com","backup_origin_port":0,"backup_origin_proto":"https"}')
check "https defaults to 443" "$(printf '%s' "$UPD" | jq -r '.backup_origin_port')" "443"
UPD=$(api -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID" \
  -d '{"backup_origin_host":"backup4.example.com","backup_origin_port":0,"backup_origin_proto":"http"}')
check "http defaults to 80" "$(printf '%s' "$UPD" | jq -r '.backup_origin_port')" "80"

echo "== invalid protocol rejected =="
CODE=$(curl -s -o "$LOG_DIR/err" -w '%{http_code}' -X PUT \
  "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID" \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"backup_origin_host":"x.example.com","backup_origin_port":80,"backup_origin_proto":"ftp"}')
check "ftp backup proto rejected" "$CODE" "400"

echo "== config delivery =="
CONFIG=$(curl -s "${AGENT[@]}" "http://127.0.0.1:$CONTROL_PORT/api/v1/config/$DOMAIN")
check "config carries backup origin" "$(printf '%s' "$CONFIG" | jq -r '.backup_origin.host')" "backup4.example.com"
check "config backup port" "$(printf '%s' "$CONFIG" | jq -r '.backup_origin.port')" "80"

echo "== clear backup origin =="
UPD=$(api -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID" \
  -d '{"backup_origin_host":""}')
check "clear returns empty host" "$(printf '%s' "$UPD" | jq -r '.backup_origin_host')" ""
check "clear resets port" "$(printf '%s' "$UPD" | jq -r '.backup_origin_port')" "0"
CONFIG=$(curl -s "${AGENT[@]}" "http://127.0.0.1:$CONTROL_PORT/api/v1/config/$DOMAIN")
check "config omits backup origin after clear" "$(printf '%s' "$CONFIG" | jq -r '.backup_origin')" "null"

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL BACKUP ORIGIN CHECKS PASSED"
else
  echo "$FAILED BACKUP ORIGIN CHECK(S) FAILED (logs: $LOG_DIR)"
  exit 1
fi
