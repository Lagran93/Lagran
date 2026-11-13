#!/usr/bin/env bash
# Purge scope regression: a URL purge must not wipe the domain, other domains or
# other tenants, and `purge_all` must stay admin-only.
#
#   bash tests/integration/purge-scope.sh
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18580}"
EDGE_PORT="${EDGE_PORT:-18581}"
ADMIN_PORT="${ADMIN_PORT:-18582}"
ORIGIN_PORT="${ORIGIN_PORT:-19580}"
DOMAIN_A="purge-a-$$.test"
DOMAIN_B="purge-b-$$.test"
DOMAIN_USER="purge-u-$$.test"
LOG_DIR="${LOG_DIR:-/tmp/lagran-purge-scope}"
mkdir -p "$LOG_DIR"

PIDS=()
FAILED=0
TOKEN=""
ADMIN_TOKEN=""
IDS=()

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }
check() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }
contains() { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 (missing '$3')"; fi; }

cleanup() {
  for id in "${IDS[@]:-}"; do
    [[ -n "$id" ]] && curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$id" \
      -H "authorization: Bearer $ADMIN_TOKEN" >/dev/null 2>&1
  done
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

hdr() {
  local host=$1 path=$2
  curl -s -o /dev/null -D - -H "Host: $host" "http://127.0.0.1:$EDGE_PORT$path" | tr -d '\r'
}

echo "== build mock origin =="
MOCK_BIN="$ROOT/target/mock-origin"
if [[ ! -x "$MOCK_BIN" || tools/mock-origin/origin.rs -nt "$MOCK_BIN" ]]; then
  rustc -O tools/mock-origin/origin.rs -o "$MOCK_BIN" >/dev/null 2>&1 || exit 1
fi
"$MOCK_BIN" "$ORIGIN_PORT" >"$LOG_DIR/origin.log" 2>&1 &
PIDS+=($!)

CONTROL_BIND="127.0.0.1:$CONTROL_PORT" CAPTCHA_ENABLED=false ./target/debug/lagran-control \
  >"$LOG_DIR/control.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 80); do curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null && break; sleep 0.5; done
curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null || { echo "control failed"; exit 1; }

ADMIN_TOKEN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r '.token // empty')
[[ -n "$ADMIN_TOKEN" ]] || { echo "admin login failed"; exit 1; }
AUTH="authorization: Bearer $ADMIN_TOKEN"

create_domain() {
  local name=$1
  local body
  body=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" -H "$AUTH" \
    -H 'content-type: application/json' \
    -d "{\"name\":\"$name\",\"origin_host\":\"127.0.0.1\",\"origin_port\":$ORIGIN_PORT,\"origin_proto\":\"http\"}")
  printf '%s' "$body" | jq -r '.id // empty'
}

DOMAIN_A_ID=$(create_domain "$DOMAIN_A")
DOMAIN_B_ID=$(create_domain "$DOMAIN_B")
[[ -n "$DOMAIN_A_ID" && -n "$DOMAIN_B_ID" ]] || { echo "domain create failed"; exit 1; }
IDS+=("$DOMAIN_A_ID" "$DOMAIN_B_ID")

# A normal user who owns a domain of their own: purge_all must still be denied.
USER_EMAIL="purge-user-$$@example.test"
curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/users" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"email\":\"$USER_EMAIL\",\"password\":\"purge-pass-123\",\"role\":\"user\"}" >/dev/null
USER_TOKEN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d "{\"email\":\"$USER_EMAIL\",\"password\":\"purge-pass-123\"}" | jq -r '.token // empty')
[[ -n "$USER_TOKEN" ]] || { echo "user login failed"; exit 1; }
USER_DOMAIN_ID=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" \
  -H "authorization: Bearer $USER_TOKEN" -H 'content-type: application/json' \
  -d "{\"name\":\"$DOMAIN_USER\",\"origin_host\":\"127.0.0.1\",\"origin_port\":$ORIGIN_PORT,\"origin_proto\":\"http\"}" \
  | jq -r '.id // empty')
[[ -n "$USER_DOMAIN_ID" ]] || { echo "user domain failed"; exit 1; }
IDS+=("$USER_DOMAIN_ID")

NODE=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"purge-edge-$$\",\"region\":\"test\",\"agent_url\":\"http://127.0.0.1:$ADMIN_PORT\"}")
NODE_TOKEN=$(printf '%s' "$NODE" | jq -r '.token // empty')
[[ -n "$NODE_TOKEN" ]] || { echo "node failed: $NODE"; exit 1; }

echo "== start edge =="
CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
EDGE_LISTEN="127.0.0.1:$EDGE_PORT" \
EDGE_ADMIN_LISTEN="127.0.0.1:$ADMIN_PORT" \
AGENT_URL="http://127.0.0.1:$ADMIN_PORT" \
AGENT_TOKEN="$NODE_TOKEN" \
NODE_ID="purge-edge-$$" \
EDGE_HTTPS_LISTEN="" \
CACHE_BACKEND=memory \
CACHE_TTL=60 \
CONFIG_SYNC_INTERVAL_SECS=5 \
ACCESS_LOG_REPORT=false \
WAF_REPORT=false \
RUST_LOG=warn \
./target/debug/lagran-edge >"$LOG_DIR/edge.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 80); do curl -sf "http://127.0.0.1:$ADMIN_PORT/__lagran/health" >/dev/null && break; sleep 0.5; done

SYNCED=0
for _ in $(seq 1 60); do
  [[ "$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $DOMAIN_A" "http://127.0.0.1:$EDGE_PORT/cached")" == "200" ]] && { SYNCED=1; break; }
  sleep 0.5
done
check "edge synced domains" "$SYNCED" "1"

warm() { hdr "$1" "$2" >/dev/null; hdr "$1" "$2" >/dev/null; }
echo "== warm objects =="
warm "$DOMAIN_A" "/cached"
warm "$DOMAIN_A" "/assets/app.css"
warm "$DOMAIN_B" "/cached"
contains "A /cached HIT" "$(hdr "$DOMAIN_A" /cached)" "x-cache: HIT"
contains "A /assets/app.css HIT" "$(hdr "$DOMAIN_A" /assets/app.css)" "x-cache: HIT"
contains "B /cached HIT" "$(hdr "$DOMAIN_B" /cached)" "x-cache: HIT"

purge_edge() {
  curl -s -X POST "http://127.0.0.1:$ADMIN_PORT/__lagran/purge" \
    -H "x-lagran-agent-token: $NODE_TOKEN" -H 'content-type: application/json' -d "$1"
}

echo "== purge one URL on A =="
RESP=$(purge_edge "{\"domain\":\"$DOMAIN_A\",\"urls\":[\"http://$DOMAIN_A/cached\"]}")
echo "  $RESP"
contains "purge reported one entry" "$RESP" '"purged_count":1'
contains "A /cached is a miss" "$(hdr "$DOMAIN_A" /cached)" "x-cache: MISS"
contains "A /assets/app.css is untouched" "$(hdr "$DOMAIN_A" /assets/app.css)" "x-cache: HIT"
contains "B /cached is untouched" "$(hdr "$DOMAIN_B" /cached)" "x-cache: HIT"

warm "$DOMAIN_A" "/cached"
echo "== prefix purge stops at a path boundary =="
purge_edge "{\"domain\":\"$DOMAIN_A\",\"prefixes\":[\"/asset\"]}" >/dev/null
contains "partial segment /asset does not purge /assets/app.css" \
  "$(hdr "$DOMAIN_A" /assets/app.css)" "x-cache: HIT"
purge_edge "{\"domain\":\"$DOMAIN_A\",\"prefixes\":[\"/assets\"]}" >/dev/null
contains "A /assets/app.css purged by /assets" "$(hdr "$DOMAIN_A" /assets/app.css)" "x-cache: MISS"
contains "A /cached untouched by prefix purge" "$(hdr "$DOMAIN_A" /cached)" "x-cache: HIT"

echo "== purge_all stays admin-only =="
CODE=$(curl -s -o "$LOG_DIR/user-purge.json" -w '%{http_code}' -X POST \
  "http://127.0.0.1:$CONTROL_PORT/api/v1/purge" -H "authorization: Bearer $USER_TOKEN" \
  -H 'content-type: application/json' \
  -d "{\"domain\":\"$DOMAIN_USER\",\"purge_all\":true}")
check "normal user purge_all is forbidden" "$CODE" "403"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  "http://127.0.0.1:$CONTROL_PORT/api/v1/purge" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"domain\":\"$DOMAIN_A\",\"purge_all\":true}")
check "admin purge_all is allowed" "$CODE" "200"

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL PURGE SCOPE CHECKS PASSED"
else
  echo "$FAILED PURGE SCOPE CHECK(S) FAILED (logs: $LOG_DIR)"
  tail -20 "$LOG_DIR/edge.log"
  exit 1
fi
