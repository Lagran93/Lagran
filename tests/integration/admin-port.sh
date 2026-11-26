#!/usr/bin/env bash
# Edge data/admin listener separation:
# management endpoints must only answer on EDGE_ADMIN_LISTEN; the data port
# keeps CDN traffic, WAF challenge verify and ACME HTTP-01.
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

DATA_PORT="${DATA_PORT:-18101}"
ADMIN_PORT="${ADMIN_PORT:-18102}"
LOG_DIR="${LOG_DIR:-/tmp/lagran-admin-port}"
mkdir -p "$LOG_DIR"

PIDS=()
FAILED=0
pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }
check() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }

cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

EDGE_LISTEN="127.0.0.1:$DATA_PORT" \
EDGE_ADMIN_LISTEN="127.0.0.1:$ADMIN_PORT" \
EDGE_HTTPS_LISTEN= \
AGENT_URL="http://127.0.0.1:$ADMIN_PORT" \
AGENT_TOKEN=admin-port-token \
CONTROL_URL=http://127.0.0.1:1 \
NODE_ID=admin-port-test \
PUBLIC_IP=127.0.0.1 \
CACHE_BACKEND=memory \
CERT_DIR="$LOG_DIR/certs" \
RUST_LOG=edge=info \
./target/debug/lagran-edge >"$LOG_DIR/edge.log" 2>&1 &
PIDS+=($!)

# Pingora opens the data listener on its own thread after the admin listener, so
# waiting only for admin health made the first data-port request race startup.
for _ in $(seq 1 60); do
  ADMIN_READY=$(curl -s -o /dev/null -w '%{http_code}' --max-time 1 \
    "http://127.0.0.1:$ADMIN_PORT/__lagran/health")
  DATA_READY=$(curl -s -o /dev/null -w '%{http_code}' --max-time 1 \
    "http://127.0.0.1:$DATA_PORT/__lagran/health")
  [[ "$ADMIN_READY" == "200" && "$DATA_READY" == "200" ]] && break
  sleep 0.25
done

check "admin health" "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$ADMIN_PORT/__lagran/health")" "200"
check "data health" "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$DATA_PORT/__lagran/health")" "200"

# H1 regression: metrics list every tenant's domains and traffic, so the admin
# listener must not serve them anonymously even though health stays open.
echo "== metrics authentication =="
check "admin metrics rejects an anonymous scrape" \
  "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$ADMIN_PORT/__lagran/metrics")" "401"
check "admin metrics rejects a wrong token" \
  "$(curl -s -o /dev/null -w '%{http_code}' -H 'x-lagran-agent-token: wrong' \
    "http://127.0.0.1:$ADMIN_PORT/__lagran/metrics")" "401"
check "admin metrics accepts the node token" \
  "$(curl -s -o "$LOG_DIR/metrics.txt" -w '%{http_code}' \
    -H 'x-lagran-agent-token: admin-port-token' \
    "http://127.0.0.1:$ADMIN_PORT/__lagran/metrics")" "200"
check "admin metrics body is Prometheus text" \
  "$(grep -c '^lagran_edge_up 1' "$LOG_DIR/metrics.txt")" "1"
check "data port refuses management metrics" \
  "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$DATA_PORT/__lagran/metrics")" "405"

PUT=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  "http://127.0.0.1:$ADMIN_PORT/__lagran/acme/challenge" \
  -H 'x-lagran-agent-token: admin-port-token' \
  -H 'content-type: application/json' \
  -d '{"token":"admin-token","key_authorization":"admin-token.test"}')
check "admin accepts challenge push" "$PUT" "204"

GET=$(curl -s -o "$LOG_DIR/token" -w '%{http_code}' \
  -H 'Host: cdn.admin.test' \
  "http://127.0.0.1:$DATA_PORT/.well-known/acme-challenge/admin-token")
check "data serves ACME challenge" "$GET" "200"
check "data returns key authorization" "$(cat "$LOG_DIR/token")" "admin-token.test"

DATA_PURGE=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  "http://127.0.0.1:$DATA_PORT/__lagran/purge" \
  -H 'x-lagran-agent-token: admin-port-token' \
  -H 'content-type: application/json' \
  -d '{"domain":"cdn.admin.test","urls":[],"prefixes":[]}')
if [[ "$DATA_PURGE" == "200" || "$DATA_PURGE" == "204" ]]; then
  fail "data port must not handle management purge (got $DATA_PURGE)"
else
  pass "data port rejects management purge ($DATA_PURGE)"
fi

ADMIN_PURGE=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  "http://127.0.0.1:$ADMIN_PORT/__lagran/purge" \
  -H 'x-lagran-agent-token: admin-port-token' \
  -H 'content-type: application/json' \
  -d '{"domain":"cdn.admin.test","urls":[],"prefixes":[]}')
check "admin port handles purge" "$ADMIN_PURGE" "200"

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL ADMIN PORT CHECKS PASSED"
else
  echo "$FAILED ADMIN PORT CHECK(S) FAILED (logs: $LOG_DIR)"
  exit 1
fi
