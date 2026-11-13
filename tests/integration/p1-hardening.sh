#!/usr/bin/env bash
# P1 control-plane hardening regression:
#   * /metrics requires a token when METRICS_TOKEN/AGENT_TOKEN is configured;
#   * disabling a node revokes its agent token immediately;
#   * group-based permissions are sticky: removing the last group does not
#     silently grant every module.
#
#   bash tests/integration/p1-hardening.sh
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18760}"
LOG_DIR="${LOG_DIR:-/tmp/lagran-p1-hardening}"
mkdir -p "$LOG_DIR"
METRICS_TOKEN="metrics-secret-$$"
GROUP_NAME="p1-group-$$"

PIDS=()
TOKEN=""
FAILED=0
psa() { printf '%s' "$1" | jq -r "$2"; }
pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }
check() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }
contains() { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 (missing '$3')"; fi; }

cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

CONTROL_BIND="127.0.0.1:$CONTROL_PORT" CAPTCHA_ENABLED=false METRICS_TOKEN="$METRICS_TOKEN" \
  ./target/debug/lagran-control >"$LOG_DIR/control.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 80); do curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null && break; sleep 0.5; done
curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null || {
  echo "control failed"; tail -20 "$LOG_DIR/control.log"; exit 1;
}

echo "== /metrics authentication =="
CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CONTROL_PORT/metrics")
check "anonymous scrape is rejected" "$CODE" "401"
CODE=$(curl -s -o "$LOG_DIR/metrics.txt" -w '%{http_code}' \
  -H "authorization: Bearer $METRICS_TOKEN" "http://127.0.0.1:$CONTROL_PORT/metrics")
check "token scrape is accepted" "$CODE" "200"
contains "metrics body is a Prometheus exposition" "$(cat "$LOG_DIR/metrics.txt")" "lagran_control_up"

TOKEN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r '.token // empty')
[[ -n "$TOKEN" ]] || { echo "login failed"; exit 1; }
AUTH="authorization: Bearer $TOKEN"

echo "== disabled node loses agent access =="
NODE=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"p1-node-$$\",\"region\":\"test\",\"agent_url\":\"http://127.0.0.1:9\"}")
NODE_ID=$(printf '%s' "$NODE" | jq -r '.node.id // empty')
NODE_TOKEN=$(printf '%s' "$NODE" | jq -r '.token // empty')
[[ -n "$NODE_ID" && -n "$NODE_TOKEN" ]] || { echo "node create failed: $NODE"; exit 1; }

CODE=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "x-lagran-agent-token: $NODE_TOKEN" "http://127.0.0.1:$CONTROL_PORT/api/v1/config")
check "active node can fetch config" "$CODE" "200"

CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes/$NODE_ID/status" -H "$AUTH" \
  -H 'content-type: application/json' -d '{"enabled":false}')
check "node disabled" "$CODE" "200"

CODE=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "x-lagran-agent-token: $NODE_TOKEN" "http://127.0.0.1:$CONTROL_PORT/api/v1/config")
check "disabled node token is revoked" "$CODE" "401"

echo "== group permissions are sticky =="
USER_EMAIL="p1-group-user-$$@example.test"
USER=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/users" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"email\":\"$USER_EMAIL\",\"password\":\"p1-pass-123\",\"role\":\"user\"}")
USER_ID=$(printf '%s' "$USER" | jq -r '.id // empty')
[[ -n "$USER_ID" ]] || { echo "user create failed: $USER"; exit 1; }
UTOKEN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d "{\"email\":\"$USER_EMAIL\",\"password\":\"p1-pass-123\"}" | jq -r '.token // empty')
[[ -n "$UTOKEN" ]] || { echo "user login failed"; exit 1; }
UAUTH="authorization: Bearer $UTOKEN"

CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "$UAUTH" "http://127.0.0.1:$CONTROL_PORT/api/v1/domains")
check "user without groups keeps legacy access" "$CODE" "200"

GROUP=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/groups" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"$GROUP_NAME\",\"permissions\":[\"domain:read\"]}")
GROUP_ID=$(printf '%s' "$GROUP" | jq -r '.id // empty')
[[ -n "$GROUP_ID" ]] || { echo "group create failed: $GROUP"; exit 1; }
curl -s -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/groups/$GROUP_ID/members" -H "$AUTH" \
  -H 'content-type: application/json' -d "{\"user_ids\":[\"$USER_ID\"]}" >/dev/null

CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "$UAUTH" "http://127.0.0.1:$CONTROL_PORT/api/v1/domains")
check "granted module is allowed" "$CODE" "200"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "$UAUTH" "http://127.0.0.1:$CONTROL_PORT/api/v1/stats/summary")
check "ungranted module is denied" "$CODE" "403"

# Remove the user from every group. The restriction must stick even though the
# effective permission set is now empty.
curl -s -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/groups/$GROUP_ID/members" -H "$AUTH" \
  -H 'content-type: application/json' -d '{"user_ids":[]}' >/dev/null
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "$UAUTH" "http://127.0.0.1:$CONTROL_PORT/api/v1/domains")
check "removing the last group does not restore access" "$CODE" "403"

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL P1 CONTROL HARDENING CHECKS PASSED"
else
  echo "$FAILED P1 CONTROL CHECK(S) FAILED (logs: $LOG_DIR)"
  exit 1
fi
