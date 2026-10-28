#!/usr/bin/env bash
# End-to-end smoke test: control + edge + mock origin.
#
#   bash tests/integration/smoke.sh
#
# Requires: postgres reachable via DATABASE_URL, cargo-built binaries in
# target/debug, curl, jq, rustc.
set -uo pipefail

source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18080}"
EDGE_PORT="${EDGE_PORT:-18081}"
ORIGIN_PORT="${ORIGIN_PORT:-19090}"
DOMAIN="${DOMAIN:-smoke.lagran.test}"
DOMAIN2="${DOMAIN2:-smoke2.lagran.test}"
DOWN="${DOWN:-down.lagran.test}"
LOG_DIR="${LOG_DIR:-/tmp/lagran-smoke}"
mkdir -p "$LOG_DIR"

PIDS=()
FAILED=0
pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }
check() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }
contains() { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 (missing '$3' in: ${2:0:200})"; fi; }
cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

jget() { printf '%s' "$1" | jq -r "$2"; }

echo "== build mock origin =="
MOCK_BIN="$ROOT/target/mock-origin"
if [[ ! -x "$MOCK_BIN" || tools/mock-origin/origin.rs -nt "$MOCK_BIN" ]]; then
  rustc -O tools/mock-origin/origin.rs -o "$MOCK_BIN" || { echo "failed to build mock origin"; exit 1; }
fi

echo "== starting mock origin =="
"$MOCK_BIN" "$ORIGIN_PORT" >"$LOG_DIR/origin.log" 2>&1 &
PIDS+=($!)

CONTROL_BIND="127.0.0.1:$CONTROL_PORT" ./target/debug/lagran-control >"$LOG_DIR/control.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 60); do
  curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null && break
  sleep 0.5
done
if ! curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null; then
  echo "control did not become healthy; see $LOG_DIR/control.log"
  tail -20 "$LOG_DIR/control.log"
  exit 1
fi

echo "== login =="
LOGIN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}')
TOKEN=$(jget "$LOGIN" '.token // empty')
AUTH="authorization: Bearer $TOKEN"
check "login returns token" "$([[ -n "$TOKEN" ]] && echo yes)" "yes"

echo "== access control =="
CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes")
check "GET /nodes without token is rejected" "$CODE" "401"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH" "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes")
check "GET /nodes as admin" "$CODE" "200"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CONTROL_PORT/api/v1/config")
check "edge config requires agent token" "$CODE" "401"

echo "== pre-register smoke edge =="
EDGE_NODE_NAME="smoke-edge-$$"
EDGE_NODE=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"$EDGE_NODE_NAME\",\"region\":\"test\",\"agent_url\":\"http://127.0.0.1:$EDGE_PORT\"}")
EDGE_NODE_TOKEN=$(printf '%s' "$EDGE_NODE" | jq -r '.token // empty')
check "edge node token created" "$([[ -n "$EDGE_NODE_TOKEN" ]] && echo yes)" "yes"

echo "== create smoke domain =="
CREATE=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"$DOMAIN\",\"origin_host\":\"127.0.0.1\",\"origin_port\":$ORIGIN_PORT,\"origin_proto\":\"http\"}")
DOMAIN_ID=$(jget "$CREATE" '.id // empty')
if [[ -z "${DOMAIN_ID:-}" ]]; then
  DOMAINS=$(curl -s -H "$AUTH" "http://127.0.0.1:$CONTROL_PORT/api/v1/domains")
  DOMAIN_ID=$(printf '%s' "$DOMAINS" | jq -r --arg n "$DOMAIN" '.[] | select(.name == $n) | .id')
fi
check "domain id resolved" "$([[ -n "$DOMAIN_ID" ]] && echo yes)" "yes"

CREATE2=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"$DOMAIN2\",\"origin_host\":\"127.0.0.1\",\"origin_port\":$ORIGIN_PORT,\"origin_proto\":\"http\"}")
DOMAIN2_ID=$(jget "$CREATE2" '.id // empty')
if [[ -z "${DOMAIN2_ID:-}" ]]; then
  DOMAINS=$(curl -s -H "$AUTH" "http://127.0.0.1:$CONTROL_PORT/api/v1/domains")
  DOMAIN2_ID=$(printf '%s' "$DOMAINS" | jq -r --arg n "$DOMAIN2" '.[] | select(.name == $n) | .id')
fi
check "second domain id resolved" "$([[ -n "$DOMAIN2_ID" ]] && echo yes)" "yes"

# A domain whose origin port is closed: used for the origin-failure page.
curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"$DOWN\",\"origin_host\":\"127.0.0.1\",\"origin_port\":1,\"origin_proto\":\"http\"}" >/dev/null

# Remove rules left by a previous run so repeated runs stay deterministic.
for id in $(curl -s -H "$AUTH" "http://127.0.0.1:$CONTROL_PORT/api/v1/rules" \
  | jq -r --arg a "$DOMAIN_ID" --arg b "$DOMAIN2_ID" '.[] | select(.domain_id == $a or .domain_id == $b) | .id'); do
  curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/rules/$id" -H "$AUTH" >/dev/null
done

# bypass rule on /cached only for the second domain: proves rules are per-domain
curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/rules" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"domain_id\":\"$DOMAIN2_ID\",\"path_pattern\":\"/cached\",\"action\":\"bypass\"}" >/dev/null

# bypass rule for /api/* and a TTL+SWR rule for /cached
curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/rules" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"domain_id\":\"$DOMAIN_ID\",\"path_pattern\":\"/api/*\",\"action\":\"bypass\"}" >/dev/null
curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/rules" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"domain_id\":\"$DOMAIN_ID\",\"path_pattern\":\"/cached\",\"ttl_seconds\":120,\"swr_seconds\":30}" >/dev/null

echo "== starting edge (waiting for config sync) =="
# Fresh cache location so a previous run can never satisfy the MISS assertions.
CACHE_DIR="$LOG_DIR/disk-cache-$$"
rm -rf "$CACHE_DIR"
CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
EDGE_ADMIN_LISTEN= \
EDGE_LISTEN="127.0.0.1:$EDGE_PORT" \
AGENT_URL="http://127.0.0.1:$EDGE_PORT" \
AGENT_TOKEN="$EDGE_NODE_TOKEN" \
NODE_ID="$EDGE_NODE_NAME" \
CACHE_BACKEND="${CACHE_BACKEND:-disk}" \
DISK_CACHE_DIR="$CACHE_DIR" \
./target/debug/lagran-edge >"$LOG_DIR/edge.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 80); do
  curl -sf "http://127.0.0.1:$EDGE_PORT/__lagran/health" >/dev/null && break
  sleep 0.5
done
check "edge health" "$(curl -s "http://127.0.0.1:$EDGE_PORT/__lagran/health")" "ok"

# Wait until the edge knows the domain (config sync runs every 15s).
for _ in $(seq 1 40); do
  OUT=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/")
  [[ "$OUT" == "200" ]] && break
  sleep 0.5
done

echo "== cache behaviour =="
H1=$(curl -s -D - -o /dev/null -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/cached")
contains "first /cached is MISS" "$H1" "x-cache: MISS"
H2=$(curl -s -D - -o /dev/null -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/cached")
contains "second /cached is HIT" "$H2" "x-cache: HIT"
contains "hit carries Age" "$(printf '%s' "$H2" | tr '[:upper:]' '[:lower:]')" "age:"

ETAG=$(printf '%s' "$H2" | awk 'tolower($1)=="etag:" {print $2}' | tr -d '\r')
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $DOMAIN" -H "If-None-Match: $ETAG" "http://127.0.0.1:$EDGE_PORT/cached")
check "conditional request returns 304" "$CODE" "304"

RANGE_HDR=$(curl -s -D - -o /dev/null -H "Host: $DOMAIN" -H 'Range: bytes=0-3' "http://127.0.0.1:$EDGE_PORT/cached")
contains "range request is served 206/partial" "$RANGE_HDR" "206 Partial Content"
contains "range request carries content-range" "$(printf '%s' "$RANGE_HDR" | tr '[:upper:]' '[:lower:]')" "content-range:"

SWR1=$(curl -s -D - -o /dev/null -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/swr")
contains "swr first request is MISS" "$SWR1" "x-cache: MISS"
sleep 2
SWR2=$(curl -s -D "$LOG_DIR/swr2.h" -o /dev/null -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/swr" && cat "$LOG_DIR/swr2.h")
contains "swr stale window serves STALE" "$(printf '%s' "$SWR2" | tr '[:upper:]' '[:lower:]')" "x-cache: stale"

H3=$(curl -s -D - -o /dev/null -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/nostore")
H4=$(curl -s -D - -o /dev/null -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/nostore")
contains "no-store first MISS" "$H3" "x-cache: MISS"
contains "no-store second MISS" "$H4" "x-cache: MISS"

H5A=$(curl -s -D - -o /dev/null -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/private")
H5B=$(curl -s -D - -o /dev/null -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/private")
contains "private first MISS" "$H5A" "x-cache: MISS"
contains "private is never stored" "$H5B" "x-cache: MISS"

H5C=$(curl -s -D - -o /dev/null -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/expires")
H5D=$(curl -s -D - -o /dev/null -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/expires")
contains "expires first MISS" "$H5C" "x-cache: MISS"
contains "expires TTL honoured (HIT)" "$H5D" "x-cache: HIT"

echo "== vary: accept-language =="
curl -s -D "$LOG_DIR/vary_en.h" -o "$LOG_DIR/vary_en.b" -H "Host: $DOMAIN" -H 'Accept-Language: en-US,en;q=0.9' "http://127.0.0.1:$EDGE_PORT/vary" >/dev/null
curl -s -D "$LOG_DIR/vary_zh.h" -o "$LOG_DIR/vary_zh.b" -H "Host: $DOMAIN" -H 'Accept-Language: zh-CN,zh;q=0.9' "http://127.0.0.1:$EDGE_PORT/vary" >/dev/null
curl -s -D "$LOG_DIR/vary_en2.h" -o "$LOG_DIR/vary_en2.b" -H "Host: $DOMAIN" -H 'Accept-Language: en-US,en;q=0.9' "http://127.0.0.1:$EDGE_PORT/vary" >/dev/null
contains "accept-language en is separate MISS" "$(tr '[:upper:]' '[:lower:]' < "$LOG_DIR/vary_en.h")" "x-cache: miss"
contains "accept-language zh does not reuse en" "$(tr '[:upper:]' '[:lower:]' < "$LOG_DIR/vary_zh.h")" "x-cache: miss"
contains "accept-language en caches independently" "$(tr '[:upper:]' '[:lower:]' < "$LOG_DIR/vary_en2.h")" "x-cache: hit"
contains "en body preserved" "$(cat "$LOG_DIR/vary_en2.b")" "lang=en-US,en;q=0.9"
contains "zh body is not en" "$(cat "$LOG_DIR/vary_zh.b")" "lang=zh-CN,zh;q=0.9"

echo "== per-domain rule isolation =="
H7=$(curl -s -D - -o /dev/null -H "Host: $DOMAIN2" "http://127.0.0.1:$EDGE_PORT/cached")
contains "second domain bypass rule applies there" "$H7" "x-cache: BYPASS"
H8=$(curl -s -D - -o /dev/null -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/cached")
contains "first domain still HIT (no cross-domain pollution)" "$H8" "x-cache: HIT"

echo "== head shares GET cache =="
HEAD_CACHED=$(curl -s -D - -o /dev/null -X HEAD -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/cached" | tr '[:upper:]' '[:lower:]')
contains "HEAD hits the GET cache entry" "$HEAD_CACHED" "x-cache: hit"

echo "== etag is content-based =="
curl -s -D "$LOG_DIR/etag1_miss.h" -o /dev/null -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/etag" >/dev/null
curl -s -D "$LOG_DIR/etag1_hit.h" -o /dev/null -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/etag" >/dev/null
ETAG1=$(tr -d '\r' < "$LOG_DIR/etag1_hit.h" | awk 'tolower($1)=="etag:" {print $2}')
curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/purge" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"domain\":\"$DOMAIN\",\"prefixes\":[\"/etag\"]}" >/dev/null
curl -s -D "$LOG_DIR/etag2_miss.h" -o /dev/null -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/etag" >/dev/null
curl -s -D "$LOG_DIR/etag2_hit.h" -o /dev/null -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/etag" >/dev/null
ETAG2=$(tr -d '\r' < "$LOG_DIR/etag2_hit.h" | awk 'tolower($1)=="etag:" {print $2}')
check "etag is present on cache hit" "$([[ -n "$ETAG1" && -n "$ETAG2" ]] && echo yes)" "yes"
if [[ "$ETAG1" != "$ETAG2" ]]; then
  pass "etag changes when body changes"
else
  fail "etag changes when body changes (same '$ETAG1')"
fi

echo "== bypass rule + POST forwarding =="
H5=$(curl -s -D - -o /dev/null -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/api/data")
contains "rule bypass is labelled BYPASS" "$H5" "x-cache: BYPASS"
POST_BODY=$(curl -s -X POST -H "Host: $DOMAIN" -H 'content-type: text/plain' -H 'x-custom: yes' \
  --data 'ping' "http://127.0.0.1:$EDGE_PORT/echo")
contains "POST method forwarded" "$POST_BODY" '"method":"POST"'
contains "POST body forwarded" "$POST_BODY" '"echo":"ping"'
contains "custom header forwarded" "$POST_BODY" '"x_custom":"yes"'
contains "POST labelled DYNAMIC" "$(curl -s -D - -o /dev/null -X POST -H "Host: $DOMAIN" --data x "http://127.0.0.1:$EDGE_PORT/echo")" "x-cache: DYNAMIC"
POST_CC=$(curl -s -X POST -H "Host: $DOMAIN" -H 'content-type: text/plain' -H 'Cache-Control: no-store' \
  --data 'cc' "http://127.0.0.1:$EDGE_PORT/echo")
contains "dynamic request keeps Cache-Control" "$POST_CC" '"cache_control":"no-store"'

echo "== large body streaming =="
dd if=/dev/zero bs=1048576 count=1 2>/dev/null | tr '\0' 'x' > "$LOG_DIR/large.bin"
BIG_BODY=$(curl -s -X POST -H "Host: $DOMAIN" -H 'content-type: application/octet-stream' \
  --data-binary "@$LOG_DIR/large.bin" "http://127.0.0.1:$EDGE_PORT/echo")
contains "1MiB upload arrives at origin" "$BIG_BODY" '"bytes":1048576'

echo "== websocket upgrade =="
WS_H=$(curl -s -D - -o /dev/null --max-time 2 \
  -H "Host: $DOMAIN" \
  -H 'Connection: Upgrade' \
  -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' \
  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  "http://127.0.0.1:$EDGE_PORT/ws" 2>/dev/null || true)
contains "websocket upgrade reaches origin tunnel" "$WS_H" "101 Switching Protocols"

echo "== purge =="
PURGE=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/purge" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"domain\":\"$DOMAIN\",\"prefixes\":[\"/cached\"]}")
contains "purge dispatched" "$PURGE" '"success":true'
H6=$(curl -s -D - -o /dev/null -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/cached")
contains "after purge it is MISS again" "$H6" "x-cache: MISS"

echo "== origin failure page =="
curl -s -D "$LOG_DIR/down.hdr" -o "$LOG_DIR/down.html" -H "Host: $DOWN" \
  "http://127.0.0.1:$EDGE_PORT/some-missing-asset.js" -w '%{http_code}' >"$LOG_DIR/down.code" || true
DOWN_CODE=$(cat "$LOG_DIR/down.code")
if [[ "$DOWN_CODE" == "502" || "$DOWN_CODE" == "503" ]]; then
  pass "origin-down returns 502/503 (got $DOWN_CODE)"
else
  fail "origin-down status (got $DOWN_CODE)"
fi
grep -qi '^content-type: text/html' "$LOG_DIR/down.hdr" && pass "error page is HTML" || fail "error page content-type"
grep -q '源站' "$LOG_DIR/down.html" && pass "error page explains the origin problem" || fail "error page text"
grep -qi '^x-lagran-error: ORIGIN_' "$LOG_DIR/down.hdr" && pass "error page carries ORIGIN_* code" || fail "x-lagran-error header"
grep -qi '^cache-control: no-store' "$LOG_DIR/down.hdr" && pass "error page is no-store" || fail "error page cache-control"
grep -q "$DOWN" "$LOG_DIR/down.html" && pass "error page names the domain" || fail "error page domain"

echo "== multi-tenant isolation =="
REG=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/register" \
  -H 'content-type: application/json' \
  -d "{\"email\":\"smoke-$$@lagran.dev\",\"password\":\"smoke123\",\"name\":\"Smoke\"}")
UTOKEN=$(jget "$REG" '.token // empty')
UAUTH="authorization: Bearer $UTOKEN"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "$UAUTH" "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes")
check "non-admin cannot list nodes" "$CODE" "403"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "$UAUTH" "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID")
check "other tenant cannot read domain" "$CODE" "404"
COUNT=$(curl -s -H "$UAUTH" "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" | jq 'length')
check "new user sees no domains" "$COUNT" "0"
NEW=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" -H "$UAUTH" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"tenant-$$.lagran.test\",\"origin_host\":\"127.0.0.1\",\"origin_port\":$ORIGIN_PORT}")
contains "new user domain auto-assigned to personal project" "$NEW" '"project_id":"'
MINE=$(curl -s -H "$UAUTH" "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" | jq 'length')
check "new user now sees exactly one domain" "$MINE" "1"

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL SMOKE CHECKS PASSED"
else
  echo "$FAILED SMOKE CHECK(S) FAILED (logs: $LOG_DIR)"
  exit 1
fi
