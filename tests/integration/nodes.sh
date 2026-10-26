#!/usr/bin/env bash
# Edge node management end-to-end:
# pre-registration → install command → per-node token auth → online →
# disable/enable → edit → delete (token revoked).
#
#   bash tests/integration/nodes.sh
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18390}"
EDGE_PORT="${EDGE_PORT:-18391}"
ORIGIN_PORT="${ORIGIN_PORT:-19391}"
NODE_NAME="${NODE_NAME:-e2e-node-$$}"
LOG_DIR="${LOG_DIR:-/tmp/lagran-nodes}"
mkdir -p "$LOG_DIR"

PIDS=()
FAILED=0
TOKEN=""
NODE_ID=""
NODE_TOKEN=""
DOMAIN_ID=""

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }
check() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }
contains() { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 (missing '$3')"; fi; }
not_contains() { if [[ "$2" != *"$3"* ]]; then pass "$1"; else fail "$1 (unexpected '$3')"; fi; }

cleanup() {
  if [[ -n "$TOKEN" && -n "$NODE_ID" ]]; then
    curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes/$NODE_ID" \
      -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
  fi
  if [[ -n "$TOKEN" && -n "$DOMAIN_ID" ]]; then
    curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID" \
      -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
  fi
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

api() { curl -s -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' "$@"; }

echo "== build mock origin =="
MOCK_BIN="$ROOT/target/mock-origin"
if [[ ! -x "$MOCK_BIN" || tools/mock-origin/origin.rs -nt "$MOCK_BIN" ]]; then
  rustc -O tools/mock-origin/origin.rs -o "$MOCK_BIN" || { echo "mock origin build failed"; exit 1; }
fi
"$MOCK_BIN" "$ORIGIN_PORT" >"$LOG_DIR/origin.log" 2>&1 &
PIDS+=($!)

echo "== start control (global token + public url) =="
AGENT_TOKEN=global-secret \
CONTROL_PUBLIC_URL="http://127.0.0.1:$CONTROL_PORT" \
CONTROL_BIND="127.0.0.1:$CONTROL_PORT" \
./target/debug/lagran-control >"$LOG_DIR/control.log" 2>&1 &
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
[[ -n "$TOKEN" ]] || { echo "login failed"; exit 1; }

echo "== create a domain served through this node =="
DOMAIN="e2e-node-$$.test"
curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"$DOMAIN\",\"origin_host\":\"127.0.0.1\",\"origin_port\":$ORIGIN_PORT,\"origin_proto\":\"http\"}" >/dev/null
DOMAIN_ID=$(curl -s -H "authorization: Bearer $TOKEN" "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" \
  | jq -r --arg n "$DOMAIN" '.[] | select(.name == $n) | .id')
[[ -n "$DOMAIN_ID" ]] || { echo "domain creation failed"; exit 1; }

echo "== pre-register node =="
CREATE=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" \
  -d "{\"name\":\"$NODE_NAME\",\"region\":\"test-region\",\"country\":\"hk\",\"agent_url\":\"http://127.0.0.1:$EDGE_PORT\"}")
NODE_ID=$(printf '%s' "$CREATE" | jq -r '.node.id // empty')
NODE_TOKEN=$(printf '%s' "$CREATE" | jq -r '.token // empty')
STATUS=$(printf '%s' "$CREATE" | jq -r '.node.status // empty')
check "node created as pending" "$STATUS" "pending"
check "node country is normalized" "$(printf '%s' "$CREATE" | jq -r '.node.country')" "HK"
check "node token is 64 hex chars" "${#NODE_TOKEN}" "64"
if printf '%s' "$NODE_TOKEN" | grep -qE '^[0-9a-f]{64}$'; then
  pass "node token looks random"
else
  fail "node token looks random"
fi
contains "binary command carries control url" "$(printf '%s' "$CREATE" | jq -r '.commands.binary')" \
  "CONTROL_URL=http://127.0.0.1:$CONTROL_PORT"
contains "binary command carries node id" "$(printf '%s' "$CREATE" | jq -r '.commands.binary')" \
  "NODE_ID=$NODE_NAME"
contains "binary command carries admin listener" "$(printf '%s' "$CREATE" | jq -r '.commands.binary')" \
  "EDGE_ADMIN_LISTEN=0.0.0.0:8081"
contains "binary command uses data port 80" "$(printf '%s' "$CREATE" | jq -r '.commands.binary')" \
  "EDGE_LISTEN=0.0.0.0:80"
contains "docker command publishes data port" "$(printf '%s' "$CREATE" | jq -r '.commands.docker')" \
  "-p 80:80"
contains "docker command publishes admin port" "$(printf '%s' "$CREATE" | jq -r '.commands.docker')" \
  "-p 8081:8081"
contains "docker command carries token" "$(printf '%s' "$CREATE" | jq -r '.commands.docker')" "$NODE_TOKEN"

LIST=$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes")
if printf '%s' "$LIST" | jq -e '.[0] | has("token")' >/dev/null 2>&1; then
  fail "node list does not leak token"
else
  pass "node list does not leak token"
fi
contains "node list flags token presence" "$LIST" '"has_token":true'

echo "== unregistered / cross-node heartbeat is rejected =="
BEFORE_COUNT=$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" | jq 'length')

GLOBAL_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes/heartbeat" \
  -H 'content-type: application/json' \
  -H 'x-lagran-agent-token: global-secret' \
  -d "{\"node_id\":\"$NODE_NAME\"}")
check "global token cannot heartbeat as edge" "$GLOBAL_CODE" "401"

GLOBAL_CFG=$(curl -s -o /dev/null -w '%{http_code}' \
  "http://127.0.0.1:$CONTROL_PORT/api/v1/config" \
  -H 'x-lagran-agent-token: global-secret')
check "global token cannot fetch edge config" "$GLOBAL_CFG" "401"

CROSS_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes/heartbeat" \
  -H 'content-type: application/json' \
  -H "x-lagran-agent-token: $NODE_TOKEN" \
  -d '{"node_id":"another-node"}')
check "node token cannot heartbeat as another node" "$CROSS_CODE" "403"

UNREG_NAME="unregistered-$$"
UNREG_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes/heartbeat" \
  -H 'content-type: application/json' \
  -H "x-lagran-agent-token: $NODE_TOKEN" \
  -d "{\"node_id\":\"$UNREG_NAME\"}")
check "unregistered node is rejected" "$UNREG_CODE" "403"

AFTER_COUNT=$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" | jq 'length')
check "heartbeat does not auto-create nodes" "$AFTER_COUNT" "$BEFORE_COUNT"

echo "== start edge with per-node token (global token differs) =="
CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
NODE_ID="$NODE_NAME" \
NODE_REGION="test-region" \
AGENT_URL="http://127.0.0.1:$EDGE_PORT" \
AGENT_TOKEN="$NODE_TOKEN" \
EDGE_LISTEN="127.0.0.1:$EDGE_PORT" \
ORIGIN_URL="http://127.0.0.1:$ORIGIN_PORT" \
HEARTBEAT_INTERVAL=2 \
CACHE_BACKEND=memory \
./target/debug/lagran-edge >"$LOG_DIR/edge.log" 2>&1 &
EDGE_PID=$!
PIDS+=($EDGE_PID)

for _ in $(seq 1 60); do
  curl -sf "http://127.0.0.1:$EDGE_PORT/__lagran/health" >/dev/null && break
  sleep 0.5
done

echo "== node goes online =="
ONLINE=""
for _ in $(seq 1 30); do
  ONLINE=$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" | jq -r --arg id "$NODE_ID" \
    '.[] | select(.id == $id) | .status')
  [[ "$ONLINE" == "online" ]] && break
  sleep 0.5
done
check "node online after heartbeat" "$ONLINE" "online"

NODE_JSON=$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" | jq -r --arg id "$NODE_ID" \
  '.[] | select(.id == $id)')
VERSION=$(printf '%s' "$NODE_JSON" | jq -r '.version')
if [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]]; then
  pass "heartbeat reports version ($VERSION)"
else
  fail "heartbeat reports version (got '$VERSION')"
fi
CPU=$(printf '%s' "$NODE_JSON" | jq -r '.cpu_usage // "null"')
if [[ "$CPU" != "null" ]]; then pass "heartbeat reports cpu ($CPU)"; else fail "heartbeat reports cpu"; fi

CODE=""
for _ in $(seq 1 40); do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/cached")
  [[ "$CODE" == "200" ]] && break
  sleep 0.5
done
check "node serves traffic while enabled" "$CODE" "200"

echo "== disable / enable =="
api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes/$NODE_ID/status" -d '{"enabled":false}' >/dev/null
DISABLED=""
for _ in $(seq 1 20); do
  CODE=$(curl -s -o "$LOG_DIR/body" -w '%{http_code}' -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/cached")
  [[ "$CODE" == "503" ]] && break
  sleep 0.5
done
check "disabled node returns 503" "$CODE" "503"
contains "disabled page copy" "$(cat "$LOG_DIR/body")" "节点已停用"
STILL=$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" | jq -r --arg id "$NODE_ID" \
  '.[] | select(.id == $id) | .status')
check "heartbeat keeps disabled status" "$STILL" "disabled"

api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes/$NODE_ID/status" -d '{"enabled":true}' >/dev/null
for _ in $(seq 1 20); do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/cached")
  [[ "$CODE" == "200" ]] && break
  sleep 0.5
done
check "re-enabled node serves again" "$CODE" "200"

echo "== edit node =="
UPD=$(api -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes/$NODE_ID" \
  -d '{"region":"edited-region","agent_url":"http://127.0.0.1:18391"}')
check "region updated" "$(printf '%s' "$UPD" | jq -r '.region')" "edited-region"
sleep 3
AFTER=$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" | jq -r --arg id "$NODE_ID" \
  '.[] | select(.id == $id) | .region')
check "heartbeat does not overwrite edited region" "$AFTER" "edited-region"

echo "== per-node token auth =="
BAD=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes/heartbeat" \
  -H 'content-type: application/json' -H 'x-lagran-agent-token: wrong' -d '{}')
check "bogus agent token rejected" "$BAD" "401"

echo "== delete revokes token =="
api -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes/$NODE_ID" >/dev/null
sleep 3
GONE=$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" | jq --arg id "$NODE_ID" '[.[] | select(.id == $id)] | length')
check "deleted node stays deleted (token revoked)" "$GONE" "0"
NODE_ID=""

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL NODE CHECKS PASSED"
else
  echo "$FAILED NODE CHECK(S) FAILED (logs: $LOG_DIR)"
  exit 1
fi
