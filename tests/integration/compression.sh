#!/usr/bin/env bash
# Downstream compression negotiation: gzip, zstd, deflate.
#
#   bash tests/integration/compression.sh
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true
unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY no_proxy NO_PROXY

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18400}"
EDGE_PORT="${EDGE_PORT:-18401}"
ORIGIN_PORT="${ORIGIN_PORT:-19400}"
DOMAIN="${DOMAIN:-compress-$$.test}"
LOG_DIR="${LOG_DIR:-/tmp/lagran-compression}"
mkdir -p "$LOG_DIR"

PIDS=()
FAILED=0
TOKEN=""
DOMAIN_ID=""
pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }
check() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }
contains() { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 (missing '$3')"; fi; }
header() { tr -d '\r' <"$LOG_DIR/h" | awk -F': ' -v k="$1" 'tolower($1)==k{print $2}' | head -1; }

cleanup() {
  if [[ -n "$TOKEN" && -n "$DOMAIN_ID" ]]; then
    curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID" \
      -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
  fi
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

request() { # <accept-encoding> [curl args...]
  local accept=$1
  shift
  curl -s --max-time 20 -o "$LOG_DIR/body" -D "$LOG_DIR/h" -w '%{http_code}' \
    -H "Host: $DOMAIN" -H "Accept-Encoding: $accept" "$@" \
    "http://127.0.0.1:$EDGE_PORT/html-large"
}

echo "== build mock origin =="
MOCK_BIN="$ROOT/target/mock-origin"
if [[ ! -x "$MOCK_BIN" || tools/mock-origin/origin.rs -nt "$MOCK_BIN" ]]; then
  rustc -O tools/mock-origin/origin.rs -o "$MOCK_BIN" || { echo "mock origin build failed"; exit 1; }
fi
"$MOCK_BIN" "$ORIGIN_PORT" >"$LOG_DIR/origin.log" 2>&1 &
PIDS+=($!)
CONTROL_BIND="127.0.0.1:$CONTROL_PORT" CAPTCHA_ENABLED=false ./target/debug/lagran-control >"$LOG_DIR/control.log" 2>&1 &
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
AUTH="authorization: Bearer $TOKEN"
[[ -n "$TOKEN" ]] || { echo "login failed"; exit 1; }

curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"$DOMAIN\",\"origin_host\":\"127.0.0.1\",\"origin_port\":$ORIGIN_PORT,\"origin_proto\":\"http\"}" >/dev/null
DOMAIN_ID=$(curl -s -H "$AUTH" "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" \
  | jq -r --arg n "$DOMAIN" '.[] | select(.name == $n) | .id')
[[ -n "$DOMAIN_ID" ]] || { echo "domain not found"; exit 1; }

NODE=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"compress-edge-$$\",\"region\":\"test\",\"agent_url\":\"http://127.0.0.1:$EDGE_PORT\"}")
NODE_TOKEN=$(printf '%s' "$NODE" | jq -r '.token // empty')
[[ -n "$NODE_TOKEN" ]] || { echo "node failed: $NODE"; exit 1; }

echo "== start edge (gzip,zstd,deflate) =="
CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
EDGE_LISTEN="127.0.0.1:$EDGE_PORT" \
EDGE_ADMIN_LISTEN= \
AGENT_URL="http://127.0.0.1:$EDGE_PORT" \
AGENT_TOKEN="$NODE_TOKEN" \
NODE_ID="compress-edge-$$" \
CACHE_BACKEND=memory CACHE_TTL=60 \
EDGE_COMPRESSION=on \
EDGE_COMPRESSION_ALGORITHMS=gzip,zstd,deflate \
EDGE_COMPRESSION_MIN_BYTES=100 \
RUST_LOG=lagran_edge=warn,edge=warn \
./target/debug/lagran-edge >"$LOG_DIR/edge.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 80); do
  curl -sf "http://127.0.0.1:$EDGE_PORT/__lagran/health" >/dev/null && break
  sleep 0.5
done

CODE=""
for _ in $(seq 1 40); do
  CODE=$(request identity)
  [[ "$CODE" == "200" ]] && break
  sleep 0.5
done
check "edge synced domain" "$CODE" "200"
check "identity request is not encoded" "$(header content-encoding)" ""

echo "== gzip =="
CODE=$(request gzip)
check "gzip status" "$CODE" "200"
check "gzip content-encoding" "$(header content-encoding)" "gzip"
python3 - "$LOG_DIR/body" "$LOG_DIR/plain" <<'PY'
import gzip, sys
open(sys.argv[2], "wb").write(gzip.decompress(open(sys.argv[1], "rb").read()))
PY
contains "gzip body decodes" "$(cat "$LOG_DIR/plain")" "downstream-compression-test"

echo "== zstd =="
CODE=$(request zstd)
check "zstd status" "$CODE" "200"
check "zstd content-encoding" "$(header content-encoding)" "zstd"
# curl in this environment is built with zstd; --compressed must decode it.
CODE=$(request zstd --compressed)
check "zstd --compressed status" "$CODE" "200"
contains "zstd body decodes" "$(cat "$LOG_DIR/body")" "downstream-compression-test"

echo "== deflate =="
CODE=$(request deflate)
check "deflate status" "$CODE" "200"
check "deflate content-encoding" "$(header content-encoding)" "deflate"
python3 - "$LOG_DIR/body" "$LOG_DIR/plain" <<'PY'
import sys, zlib
open(sys.argv[2], "wb").write(zlib.decompress(open(sys.argv[1], "rb").read()))
PY
contains "deflate body decodes" "$(cat "$LOG_DIR/plain")" "downstream-compression-test"

echo "== quality and wildcard negotiation =="
CODE=$(request 'gzip;q=0.5, zstd;q=0.9')
check "higher zstd quality wins" "$(header content-encoding)" "zstd"
CODE=$(request 'gzip;q=0, *')
check "wildcard falls back to zstd" "$(header content-encoding)" "zstd"
CODE=$(request 'gzip;q=0')
check "explicit gzip refusal sends identity" "$(header content-encoding)" ""

echo "== cache hit keeps encoding negotiation =="
CODE=$(request gzip)
check "cached gzip request still 200" "$CODE" "200"
check "cached gzip content-encoding" "$(header content-encoding)" "gzip"

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL COMPRESSION CHECKS PASSED"
else
  echo "$FAILED COMPRESSION CHECK(S) FAILED (logs: $LOG_DIR)"
  exit 1
fi
