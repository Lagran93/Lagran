#!/usr/bin/env bash
# P2 control-plane hardening regression:
#   * alert channels cannot reach loopback/metadata addresses (SSRF);
#   * registration is limited per client IP, so one source cannot create
#     unlimited accounts by varying the email address (SEC-NEW-02);
#   * repeated invalid agent tokens are answered from a negative cache instead of
#     hitting PostgreSQL on every request (SEC-NEW-03);
#   * login limiting is failure-based and has a per-IP dimension;
#   * access-log ingest drops a bad timestamp instead of poisoning the batch,
#     and attributes rows to the token's node, not the payload;
#   * prefetch requests are capped and deduplicated, and prefetch listings are
#     tenant-filtered in SQL (SEC-NEW-05);
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
# Filled in by the SEC-NEW-05 case; `cleanup` needs them under `set -u`.
SEC05_FLOOD=""
pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }
check() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }
contains() { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 (missing '$3')"; fi; }

cleanup() {
  # The SEC-NEW-05 case queues 120 warm-up paths and leaves a recurring schedule
  # behind. Prefetch claims are FIFO at 20 tasks per 15 s round, so a leftover
  # backlog starves the next suite's warm-up until its poll window expires
  # (`cache-diagnostics.sh` failed exactly that way). Remove what this run created.
  if [[ -n "${TOKEN:-}" && -n "${SEC05_FLOOD:-}" ]]; then
    local ids id
    ids=$(curl -s -H "authorization: Bearer $TOKEN"       "http://127.0.0.1:$CONTROL_PORT/api/v1/prefetch/schedules"       | jq -r --arg d "$SEC05_FLOOD" '.[] | select(.domain == $d) | .id' 2>/dev/null)
    for id in $ids; do
      curl -s -X DELETE         "http://127.0.0.1:$CONTROL_PORT/api/v1/prefetch/schedules/$id"         -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
    done
  fi
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

CONTROL_BIND="127.0.0.1:$CONTROL_PORT" CAPTCHA_ENABLED=false ALLOW_REGISTER=true ./target/debug/lagran-control \
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

echo "== registration IP rate limit (SEC-NEW-02) =="
# The per-email bucket cannot bound account creation: every fresh address is a
# fresh bucket. Burn the per-IP budget with distinct addresses and require the
# next attempt from the same source to be refused.
REG_LIMITED=0
for n in $(seq 1 15); do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/auth/register" \
    -H 'content-type: application/json' \
    -d "{\"email\":\"p2-bot-$n-$$@example.test\",\"password\":\"Str0ng-Passw0rd!$n\"}")
  if [[ "$CODE" == "429" ]]; then REG_LIMITED=$((REG_LIMITED + 1)); fi
done
if [[ "$REG_LIMITED" -gt 0 ]]; then
  pass "distinct emails from one IP are rate limited"
else
  fail "15 distinct registrations from one IP were never rate limited"
fi

# A different client IP (via the default trusted loopback proxy) is unaffected.
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/auth/register" \
  -H 'content-type: application/json' -H 'x-forwarded-for: 203.0.113.88' \
  -d "{\"email\":\"p2-other-$$@example.test\",\"password\":\"Str0ng-Passw0rd!x\"}")
check "another client IP can still register" "$CODE" "201"

echo "== agent token negative cache (SEC-NEW-03) =="
# The agent routes accept a per-node token without a session, so a random token is
# attacker input. Replays of one bad token must not turn into one query each.
BOGUS="not-a-node-token-$$"
for _ in $(seq 1 20); do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/nodes/heartbeat" \
    -H 'content-type: application/json' -H "x-lagran-agent-token: $BOGUS" \
    -d '{"node_id":"x"}')
done
check "invalid agent token is rejected" "$CODE" "401"

# A real node token must still authenticate, including immediately after
# creation (the window the negative cache could have broken).
NEWNODE=$(curl -s -X POST "$BASE/api/v1/nodes" -H "$AUTH" -H 'content-type: application/json' \
  -d "{\"name\":\"sec03-node-$$\",\"region\":\"test\",\"agent_url\":\"http://127.0.0.1:9\"}")
NEWTOKEN=$(printf '%s' "$NEWNODE" | jq -r '.token // empty')
NEWNAME=$(printf '%s' "$NEWNODE" | jq -r '.node.name // empty')
[[ -n "$NEWTOKEN" ]] || { echo "node create failed: $NEWNODE"; exit 1; }
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/nodes/heartbeat" \
  -H 'content-type: application/json' -H "x-lagran-agent-token: $NEWTOKEN" \
  -d "{\"node_id\":\"$NEWNAME\"}")
check "freshly created token authenticates immediately" "$CODE" "200"

echo "== prefetch tenant isolation (SEC-NEW-05) =="
# A tenant that queues more paths than the console window must not blank other
# tenants' progress view. The old listing read the newest rows for *every* tenant
# and dropped the unauthorized ones in memory, so the flood pushed the other
# tenants out of the window even though their tasks were still queued/running.
SEC05_EMAIL="p2-sec05-$$@example.test"
SEC05_PASSWORD="p2-pass-123"
curl -s -X POST "$BASE/api/v1/users" -H "$AUTH" -H 'content-type: application/json' \
  -d "{\"email\":\"$SEC05_EMAIL\",\"password\":\"$SEC05_PASSWORD\",\"role\":\"user\"}" >/dev/null
SEC05_TOKEN=$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'content-type: application/json' \
  -d "{\"email\":\"$SEC05_EMAIL\",\"password\":\"$SEC05_PASSWORD\"}" | jq -r '.token // empty')
[[ -n "$SEC05_TOKEN" ]] || { echo "SEC-NEW-05: tenant login failed"; exit 1; }
SEC05_AUTH="authorization: Bearer $SEC05_TOKEN"
SEC05_PROJECT=$(curl -s -X POST "$BASE/api/v1/projects" -H "$SEC05_AUTH" \
  -H 'content-type: application/json' -d "{\"name\":\"p2-sec05-$$\"}" | jq -r '.id // empty')
[[ -n "$SEC05_PROJECT" ]] || { echo "SEC-NEW-05: tenant project create failed"; exit 1; }

# The tenant's domain lives in its own project; the admin creates it on the
# tenant's behalf, exactly like the console's project picker does.
SEC05_DOMAIN="p2-sec05-tenant-$$.test"
curl -s -X POST "$BASE/api/v1/domains" -H "$AUTH" -H 'content-type: application/json' \
  -d "{\"name\":\"$SEC05_DOMAIN\",\"origin_host\":\"127.0.0.1\",\"origin_port\":19090,\"origin_proto\":\"http\",\"project_id\":\"$SEC05_PROJECT\"}" >/dev/null

# Tenant task first (oldest row), then an admin flood of >100 newer rows.
curl -s -X POST "$BASE/api/v1/prefetch" -H "$SEC05_AUTH" -H 'content-type: application/json' \
  -d "{\"domain\":\"$SEC05_DOMAIN\",\"paths\":[\"/tenant\"]}" >/dev/null
SEC05_FLOOD="p2-sec05-admin-$$.test"
curl -s -X POST "$BASE/api/v1/domains" -H "$AUTH" -H 'content-type: application/json' \
  -d "{\"name\":\"$SEC05_FLOOD\",\"origin_host\":\"127.0.0.1\",\"origin_port\":19090,\"origin_proto\":\"http\"}" >/dev/null
FLOOD_PATHS=$(python3 -c 'import json; print(json.dumps([f"/flood{i}" for i in range(120)]))')
curl -s -X POST "$BASE/api/v1/prefetch" -H "$AUTH" -H 'content-type: application/json' \
  -d "{\"domain\":\"$SEC05_FLOOD\",\"paths\":$FLOOD_PATHS}" >/dev/null

TASKS=$(curl -s -H "$SEC05_AUTH" "$BASE/api/v1/prefetch/tasks")
check "tenant still sees its own prefetch task" "$(printf '%s' "$TASKS" | jq 'length')" "1"
check "tenant task is attributed to its domain" \
  "$(printf '%s' "$TASKS" | jq -r '.[0].domain')" "$SEC05_DOMAIN"
V1=$(curl -s -H "$SEC05_AUTH" "$BASE/api/v1/prefetch")
check "v1 listing returns only the tenant's domain" \
  "$(printf '%s' "$V1" | jq -r '[.[].domain] | unique | join(",")')" "$SEC05_DOMAIN"

# Schedules follow the same rule: other tenants' scheduling data must not be
# returned at all.
curl -s -X POST "$BASE/api/v1/prefetch/schedules" -H "$AUTH" -H 'content-type: application/json' \
  -d "{\"domain\":\"$SEC05_FLOOD\",\"paths\":[\"/sched\"],\"interval_minutes\":60}" >/dev/null
SCHEDULES=$(curl -s -H "$SEC05_AUTH" "$BASE/api/v1/prefetch/schedules")
check "tenant sees no foreign prefetch schedules" "$(printf '%s' "$SCHEDULES" | jq 'length')" "0"

# The admin view is unchanged (unfiltered). The tenant's row is outside the
# admin's own newest-100 window here — the flood is newer by construction — so
# assert the flood itself is visible instead.
ADMIN_TASKS=$(curl -s -H "$AUTH" "$BASE/api/v1/prefetch/tasks")
check "admin listing is still unfiltered" \
  "$(printf '%s' "$ADMIN_TASKS" | jq --arg d "$SEC05_FLOOD" '[.[] | select(.domain == $d)] | length > 0')" "true"

echo "== drain queued warm-ups =="
# The flood above queues 121 tasks. Claims are FIFO at 20 per 15 s round, so
# exiting with them still pending poisons the next suite's prefetch queue.
DRAINED=0
for _ in $(seq 1 90); do
  LEFT=$(curl -s -H "$AUTH" "$BASE/api/v1/prefetch/tasks" \
    | jq --arg d "$SEC05_FLOOD" '[.[] | select(.domain == $d and .status == "pending")] | length' 2>/dev/null)
  [[ "${LEFT:-1}" == "0" ]] && { DRAINED=1; break; }
  sleep 2.5
done
check "queued warm-up tasks drain before the suite exits" "$DRAINED" "1"

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL P2 CONTROL HARDENING CHECKS PASSED"
else
  echo "$FAILED P2 CHECK(S) FAILED (logs: $LOG_DIR)"
  exit 1
fi
