#!/usr/bin/env bash
# Asynchronous certificate issuance regression:
#   * POST /certs/issue answers 202 with a job id instead of holding the request
#     for the whole issuance (the finding was a browser/proxy timeout on a
#     synchronous ACME exchange);
#   * a duplicate POST for the same (domain, provider) reuses the in-flight job
#     instead of opening a second ACME order;
#   * GET /certs/jobs/:id reports progress while running and the outcome after,
#     and GET /certs/jobs lists only active jobs;
#   * a slow/unreachable edge does not fail the issuance (fan-out failures are
#     logged, the certificate is still stored);
#   * the issued certificate really lands in the certificate list;
#   * client errors (empty domain, unknown provider) stay synchronous 4xx.
#
# The "still running" window is produced deterministically with a stub edge: a
# node registered as online whose agent endpoint accepts the TCP connection and
# never answers, so the dev challenge fan-out blocks on the agent timeout. No
# real ACME server is contacted (the test uses `provider: dev`).
#
#   bash tests/integration/cert-jobs.sh
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18690}"
STUB_PORT="${STUB_PORT:-18699}"
LOG_DIR="${LOG_DIR:-/tmp/lagran-cert-jobs}"
mkdir -p "$LOG_DIR"
DOMAIN="cert-jobs-$$.test"
NODE_NAME="cert-jobs-node-$$"

PIDS=()
FAILED=0
TOKEN=""
DOMAIN_ID=""
NODE_ID=""
CERT_ID=""

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }
check() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }
contains() { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 (missing '$3' in '$2')"; fi; }

cleanup() {
  [[ -n "$CERT_ID" ]] && curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/certs/$CERT_ID" \
    -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
  [[ -n "$NODE_ID" ]] && curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes/$NODE_ID" \
    -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
  [[ -n "$DOMAIN_ID" ]] && curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID" \
    -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

# Stub edge: accept the connection and hold it, never send a response.
python3 -c '
import socket, sys
sk = socket.socket()
sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sk.bind(("127.0.0.1", int(sys.argv[1])))
sk.listen(64)
held = []
while True:
    conn, _ = sk.accept()
    held.append(conn)
' "$STUB_PORT" &
PIDS+=($!)

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

DOMAIN_ID=$(curl -s -X POST "$BASE/api/v1/domains" -H "$AUTH" -H 'content-type: application/json' \
  -d "{\"name\":\"$DOMAIN\",\"origin_host\":\"127.0.0.1\",\"origin_port\":19090,\"origin_proto\":\"http\"}" \
  | jq -r '.id // empty')
[[ -n "$DOMAIN_ID" ]] || { echo "domain create failed"; exit 1; }

CREATE=$(curl -s -X POST "$BASE/api/v1/nodes" -H "$AUTH" -H 'content-type: application/json' \
  -d "{\"name\":\"$NODE_NAME\",\"region\":\"test-region\",\"country\":\"hk\",\"agent_url\":\"http://127.0.0.1:$STUB_PORT\"}")
NODE_ID=$(printf '%s' "$CREATE" | jq -r '.node.id // empty')
NODE_TOKEN=$(printf '%s' "$CREATE" | jq -r '.token // empty')
[[ -n "$NODE_ID" && -n "$NODE_TOKEN" ]] || { echo "node create failed: $CREATE"; exit 1; }
curl -s -X POST "$BASE/api/v1/nodes/heartbeat" -H 'content-type: application/json' \
  -H "x-lagran-agent-token: $NODE_TOKEN" -d "{\"node_id\":\"$NODE_NAME\"}" >/dev/null
ONLINE=$(curl -s "$BASE/api/v1/nodes" -H "$AUTH" | jq -r --arg id "$NODE_ID" '.[] | select(.id == $id) | .status')
check "stub edge is online (fan-out will block on it)" "$ONLINE" "online"

issue() { # <provider> <domain> -> http code in $LOG_DIR/issue.json
  jq -n --arg d "$2" --arg p "$1" '{domain_name:$d, provider:$p, push_to_edges:false}' \
  | curl -s -o "$LOG_DIR/issue.json" -w '%{http_code}' -X POST "$BASE/api/v1/certs/issue" \
      -H "$AUTH" -H 'content-type: application/json' --data @-
}

echo "== issuance is queued, not performed inline =="
START_MS=$(date +%s%N)
CODE=$(issue dev "$DOMAIN")
ELAPSED_MS=$(( ($(date +%s%N) - START_MS) / 1000000 ))
check "POST /certs/issue returns 202" "$CODE" "202"
JOB_ID=$(jq -r '.job_id // empty' "$LOG_DIR/issue.json")
[[ -n "$JOB_ID" ]] && pass "response carries a job id" || fail "response carries a job id"
check "initial status is pending" "$(jq -r '.status // empty' "$LOG_DIR/issue.json")" "pending"
check "poll_url points at the job" "$(jq -r '.poll_url // empty' "$LOG_DIR/issue.json")" "/api/v1/certs/jobs/$JOB_ID"
check "job is not marked reused" "$(jq -r '.reused' "$LOG_DIR/issue.json")" "false"
# Generous bound: the finding is that the request waits for the issuance at all,
# not that the control plane is slow.
if (( ELAPSED_MS < 3000 )); then
  pass "request returns immediately (${ELAPSED_MS}ms)"
else
  fail "request returns immediately (took ${ELAPSED_MS}ms)"
fi

echo "== an in-flight job is reused instead of opening a second order =="
CODE=$(issue dev "$DOMAIN")
check "duplicate POST is also 202" "$CODE" "202"
check "duplicate POST reuses the same job" "$(jq -r '.job_id // empty' "$LOG_DIR/issue.json")" "$JOB_ID"
check "duplicate POST reports reused" "$(jq -r '.reused' "$LOG_DIR/issue.json")" "true"

echo "== the job reports progress while it runs =="
sleep 0.5
RUNNING=$(curl -s "$BASE/api/v1/certs/jobs/$JOB_ID" -H "$AUTH")
check "running job reports running" "$(printf '%s' "$RUNNING" | jq -r '.status')" "running"
contains "running job reports its stage" "$(printf '%s' "$RUNNING" | jq -r '.message')" "challenge"
ACTIVE=$(curl -s "$BASE/api/v1/certs/jobs" -H "$AUTH")
check "in-flight job is listed as active" \
  "$(printf '%s' "$ACTIVE" | jq --arg id "$JOB_ID" '[.jobs[] | select(.id == $id)] | length')" "1"

echo "== the job finishes even though the stub edge times out =="
STATUS=""
for _ in $(seq 1 60); do
  curl -s "$BASE/api/v1/certs/jobs/$JOB_ID" -H "$AUTH" >"$LOG_DIR/job.json"
  STATUS=$(jq -r '.status // empty' "$LOG_DIR/job.json")
  [[ "$STATUS" == "succeeded" || "$STATUS" == "failed" ]] && break
  sleep 0.5
done
if [[ "$STATUS" == "succeeded" ]]; then
  pass "job reaches succeeded despite the unreachable edge"
elif [[ "$STATUS" == "failed" ]]; then
  fail "job reaches succeeded (failed: $(jq -r '.message' "$LOG_DIR/job.json"))"
else
  fail "job reaches succeeded (timed out at '$STATUS')"
fi
CERT_ID=$(jq -r '.cert_id // empty' "$LOG_DIR/job.json")
[[ -n "$CERT_ID" ]] && pass "job records the certificate id" || fail "job records the certificate id"
check "job keeps the domain" "$(jq -r '.domain_name' "$LOG_DIR/job.json")" "$DOMAIN"
contains "job reports the issuer" "$(jq -r '.issuer // empty' "$LOG_DIR/job.json")" "Lagran Dev CA"
check "no edge received the certificate" "$(jq -r '.edges_pushed' "$LOG_DIR/job.json")" "0"

echo "== the issued certificate is visible to the rest of the API =="
CERTS=$(curl -s "$BASE/api/v1/certs" -H "$AUTH")
check "certificate list contains the new cert" \
  "$(printf '%s' "$CERTS" | jq --arg d "$DOMAIN" '[.[] | select(.domain_name == $d and .status == "active")] | length')" "1"
check "certificate id from the job is the published one" \
  "$(printf '%s' "$CERTS" | jq -r --arg d "$DOMAIN" '[.[] | select(.domain_name == $d)][0].id')" "$CERT_ID"

echo "== finished jobs leave the active list but stay pollable =="
JOBS=$(curl -s "$BASE/api/v1/certs/jobs" -H "$AUTH")
check "finished job is not listed as active" \
  "$(printf '%s' "$JOBS" | jq --arg id "$JOB_ID" '[.jobs[] | select(.id == $id)] | length')" "0"
check "job snapshot survives for polling" \
  "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/v1/certs/jobs/$JOB_ID" -H "$AUTH")" "200"

echo "== client errors stay synchronous =="
CODE=$(issue "not-a-ca" "$DOMAIN")
check "unknown provider is rejected" "$CODE" "400"
CODE=$(issue dev "")
check "empty domain is rejected" "$CODE" "400"

echo "== unknown jobs answer 404, not 500 =="
check "random job id is not found" \
  "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/v1/certs/jobs/$(cat /proc/sys/kernel/random/uuid)" -H "$AUTH")" "404"

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL CERT JOB CHECKS PASSED"
else
  echo "$FAILED CERT JOB CHECK(S) FAILED (logs: $LOG_DIR)"
  exit 1
fi