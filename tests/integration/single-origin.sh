#!/usr/bin/env bash
# Single-origin mode: an edge with no control-plane config serves every Host from
# ORIGIN_URL through the Pingora plan (native), not the legacy in-process engine.
#
# This is the regression guard for 阶段 3 剩余项 2 (option A): the fallback used to
# be `LegacyFallback::SingleOrigin`; it is now a static default registry entry, so
# the request must carry `x-lagran-datapath: pingora` and the legacy counters must
# stay at zero.
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

EDGE_PORT="${EDGE_PORT:-18622}"
ORIGIN_PORT="${ORIGIN_PORT:-19600}"
LOG_DIR="${LOG_DIR:-/tmp/lagran-single-origin}"
mkdir -p "$LOG_DIR"

PIDS=()
FAILED=0
HOST_A="alpha-$$.test"
HOST_B="beta-$$.example"

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }
check() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }
contains() { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 (missing '$3' in '$2')"; fi; }

cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

hdr() { tr -d '\r' <"$LOG_DIR/h" | awk -F': ' -v k="$1" 'tolower($1)==k{print $2}' | head -1; }
# get <host> <path> [extra curl args] -> status code; headers in $LOG_DIR/h, body in $LOG_DIR/b
get() {
  local host=$1 path=$2
  shift 2
  curl -s -H "Host: $host" "$@" -D "$LOG_DIR/h" -o "$LOG_DIR/b" -w '%{http_code}' --max-time 10 \
    "http://127.0.0.1:$EDGE_PORT$path"
}
metrics_body() {
  curl -s -H "x-lagran-agent-token: $AGENT_TOKEN" --max-time 5 \
    "http://127.0.0.1:$EDGE_PORT/__lagran/metrics"
}

MOCK_BIN="$ROOT/target/mock-origin"
if [[ ! -x "$MOCK_BIN" || tools/mock-origin/origin.rs -nt "$MOCK_BIN" ]]; then
  rustc -O tools/mock-origin/origin.rs -o "$MOCK_BIN" || { echo "mock origin build failed"; exit 1; }
fi
"$MOCK_BIN" "$ORIGIN_PORT" >"$LOG_DIR/origin.log" 2>&1 & PIDS+=($!)

echo "== start edge (no control plane) =="
# CONTROL_URL points at a closed port on purpose: the point of this suite is a
# registry that never fills. Pointing it at the default 127.0.0.1:8080 would let a
# control plane left running by another suite repopulate the registry and hide
# the fallback under test.
AGENT_TOKEN="single-origin-token"
CONTROL_URL="http://127.0.0.1:9" \
NODE_ID="single-origin-$$" AGENT_TOKEN="$AGENT_TOKEN" \
ORIGIN_URL="http://127.0.0.1:$ORIGIN_PORT" \
EDGE_LISTEN="127.0.0.1:$EDGE_PORT" EDGE_ADMIN_LISTEN= EDGE_HTTPS_LISTEN= \
CACHE_TTL=60 CACHE_BACKEND=memory CERT_DIR="$LOG_DIR/certs" \
./target/debug/lagran-edge >"$LOG_DIR/edge.log" 2>&1 & PIDS+=($!)
for _ in $(seq 1 80); do
  curl -sf "http://127.0.0.1:$EDGE_PORT/__lagran/health" >/dev/null && break
  sleep 0.25
done

echo "== any Host is served from ORIGIN_URL =="
CODE=$(get "$HOST_A" "/cached")
check "unregistered Host returns 200" "$CODE" "200"
contains "body comes from the configured origin" "$(cat "$LOG_DIR/b")" "hello from origin"
check "single-origin request is served by Pingora" "$(hdr x-lagran-datapath)" "pingora"
check "first request is a native MISS" "$(hdr x-cache)" "MISS"

get "$HOST_A" "/cached" >/dev/null
check "second request is a native HIT" "$(hdr x-cache)" "HIT"

CODE=$(get "$HOST_B" "/cached")
check "a second, different Host also returns 200" "$CODE" "200"
check "the second Host uses Pingora too" "$(hdr x-lagran-datapath)" "pingora"

echo "== no legacy fallback remains =="
metrics_body >"$LOG_DIR/metrics.txt"
check "fallback reasons are down to six" \
  "$(grep -c 'lagran_edge_legacy_fallback_total{reason=' "$LOG_DIR/metrics.txt")" "6"
check "single_origin reason is gone" \
  "$(grep -c 'reason="single_origin"' "$LOG_DIR/metrics.txt")" "0"
check "no request left the Pingora data plane" \
  "$(awk '/^lagran_edge_legacy_fallback_total/ {sum += $2} END {print sum + 0}' "$LOG_DIR/metrics.txt")" "0"

if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL SINGLE ORIGIN CHECKS PASSED"
else
  echo "SINGLE ORIGIN CHECKS FAILED ($FAILED)"
  echo "logs: $LOG_DIR"
  exit 1
fi
