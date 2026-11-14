#!/usr/bin/env bash
# P2 control-plane hardening regression:
#   * alert channels cannot reach loopback/metadata addresses (SSRF);
#   * login limiting is failure-based and has a per-IP dimension;
#   * access-log ingest drops a bad timestamp instead of poisoning the batch,
#     and attributes rows to the token's node, not the payload;
#   * prefetch requests are capped and deduplicated;
#   * origin diagnostics refuse metadata/loopback targets;
#   * issued JWTs carry and require iss/aud.
#
#   bash tests/integration/p2-hardening.sh
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18770}"
LOG_DIR="${LOG_DIR:-/tmp/lagran-p2-hardening}"
mkdir -p "$LOG_DIR"

PIDS=()
FAILED=0
TOKEN=""
pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }
check() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }
contains() { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 (missing '$3')"; fi; }

cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

CONTROL_BIND="127.0.0.1:$CONTROL_PORT" CAPTCHA_ENABLED=false ./target/debug/lagran-control \
  >"$LOG_DIR/control.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 80); do curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null && break; sleep 0.5; done
curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null || {
  echo "control failed"; tail -20 "$LOG_DIR/control.log"; exit 1;
}
BASE="http://127.0.0.1:$CONTROL_PORT"

TOKEN=$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r '.token // empty')
[[ -n "$TOKEN" ]] || { echo "admin login failed"; exit 1; }
AUTH="authorization: Bearer $TOKEN"

echo "== token claims =="
PAYLOAD=$(printf '%s' "$TOKEN" | cut -d. -f2)
CLAIMS=$(python3 -c 'import base64,json,sys; s=sys.argv[1]; print(json.dumps(json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))))' "$PAYLOAD")
check "token issuer" "$(printf '%s' "$CLAIMS" | jq -r '.iss')" "lagran-control"
check "token audience" "$(printf '%s' "$CLAIMS" | jq -r '.aud')" "lagran-console"

echo "== alert channel SSRF guard =="
CH=$(curl -s -X POST "$BASE/api/v1/alert-channels" -H "$AUTH" -H 'content-type: application/json' \
  -d "{\"name\":\"p2-ssrf-$$\",\"kind\":\"webhook\",\"config\":{\"url\":\"http://169.254.169.254/latest/meta-data\"}}")
CH_ID=$(printf '%s' "$CH" | jq -r '.id // empty')
[[ -n "$CH_ID" ]] || { echo "channel create failed: $CH"; exit 1; }
RESP=$(curl -s -X POST "$BASE/api/v1/alert-channels/$CH_ID/test" -H "$AUTH")
check "metadata webhook rejected" "$(printf '%s' "$RESP" | jq -r '.success')" "false"
contains "rejection names the address" "$(printf '%s' "$RESP" | jq -r '.message')" "disallowed address"

echo "== failure-based login limiting =="
EMAIL="p2-login-$$@example.test"
PASSWORD="p2-pass-123"
curl -s -X POST "$BASE/api/v1/users" -H "$AUTH" -H 'content-type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"role\":\"user\"}" >/dev/null
for _ in $(seq 1 5); do
  curl -s -o /dev/null -X POST "$BASE/api/v1/auth/login" -H 'content-type: application/json' \
    -d "{\"email\":\"$EMAIL\",\"password\":\"wrong\"}"
done
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/auth/login" \
  -H 'content-type: application/json' -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
check "success after five failures is allowed" "$CODE" "200"

for _ in $(seq 1 20); do
  curl -s -o /dev/null -X POST "$BASE/api/v1/auth/login" -H 'content-type: application/json' \
    -d "{\"email\":\"$EMAIL\",\"password\":\"wrong\"}"
done
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/auth/login" \
  -H 'content-type: application/json' -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
check "account is throttled after sustained failures" "$CODE" "429"

echo "== access-log ingest =="
NODE_NAME="p2-log-node-$$"
NODE=$(curl -s -X POST "$BASE/api/v1/nodes" -H "$AUTH" -H 'content-type: application/json' \
  -d "{\"name\":\"$NODE_NAME\",\"region\":\"test\",\"agent_url\":\"http://127.0.0.1:9\"}")
NODE_TOKEN=$(printf '%s' "$NODE" | jq -r '.token // empty')
[[ -n "$NODE_TOKEN" ]] || { echo "node create failed: $NODE"; exit 1; }
LOG_HOST="p2-log-$$.test"
BODY=$(jq -n --arg host "$LOG_HOST" --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{
  entries: [
    {ts:"not-a-timestamp", host:$host, path:"/bad-ts", status:200, node_id:"spoofed"},
    {ts:$now, path:"/hostless", status:200},
    {ts:$now, host:$host, path:"/good", status:200, node_id:"spoofed"},
    {ts:"2099-01-01T00:00:00Z", host:$host, path:"/future", status:200, node_id:"spoofed"}
  ]
}')
ACK=$(curl -s -X POST "$BASE/api/v1/access-logs/report" -H "x-lagran-agent-token: $NODE_TOKEN" \
  -H 'content-type: application/json' -d "$BODY")
check "bad timestamp does not poison the batch" "$(printf '%s' "$ACK" | jq -r '.accepted')" "2"
ROWS=$(curl -s -H "$AUTH" "$BASE/api/v1/access-logs?host=$LOG_HOST&limit=10")
check "only valid rows were stored" "$(printf '%s' "$ROWS" | jq 'length')" "2"
check "row is attributed to the token's node" "$(printf '%s' "$ROWS" | jq -r '.[0].node_id')" "$NODE_NAME"
check "future timestamp is clamped" "$(printf '%s' "$ROWS" | jq -r '[.[] | select(.path == "/future")] | length')" "1"

echo "== prefetch caps =="
DOMAIN="p2-pre-$$.test"
DID=$(curl -s -X POST "$BASE/api/v1/domains" -H "$AUTH" -H 'content-type: application/json' \
  -d "{\"name\":\"$DOMAIN\",\"origin_host\":\"127.0.0.1\",\"origin_port\":19090,\"origin_proto\":\"http\"}" \
  | jq -r '.id // empty')
[[ -n "$DID" ]] || { echo "domain create failed"; exit 1; }
PATHS=$(python3 -c 'import json; print(json.dumps([f"/p{i}" for i in range(501)]))')
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/prefetch" -H "$AUTH" \
  -H 'content-type: application/json' -d "{\"domain\":\"$DOMAIN\",\"paths\":$PATHS}")
check "more than 500 paths is refused" "$CODE" "413"
RESP=$(curl -s -X POST "$BASE/api/v1/prefetch" -H "$AUTH" -H 'content-type: application/json' \
  -d "{\"domain\":\"$DOMAIN\",\"paths\":[\"/a\",\"/a\",\"/b\"]}")
check "duplicate paths are deduplicated" "$(printf '%s' "$RESP" | jq -r '.created')" "2"

echo "== origin probe guard =="
METADATA_DOMAIN="p2-meta-$$.test"
MID=$(curl -s -X POST "$BASE/api/v1/domains" -H "$AUTH" -H 'content-type: application/json' \
  -d "{\"name\":\"$METADATA_DOMAIN\",\"origin_host\":\"169.254.169.254\",\"origin_port\":80,\"origin_proto\":\"http\"}" \
  | jq -r '.id // empty')
[[ -n "$MID" ]] || { echo "metadata domain create failed"; exit 1; }
DIAG=$(curl -s -X POST "$BASE/api/v1/domains/$MID/diagnose" -H "$AUTH")
contains "metadata origin is not probed" "$(printf '%s' "$DIAG")" "源站地址不可探测"
if printf '%s' "$DIAG" | grep -q 'Connection refused'; then
  fail "diagnostic leaked the OS error"
else
  pass "diagnostic does not leak OS errors"
fi

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL P2 CONTROL HARDENING CHECKS PASSED"
else
  echo "$FAILED P2 CHECK(S) FAILED (logs: $LOG_DIR)"
  exit 1
fi
