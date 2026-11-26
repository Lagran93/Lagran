#!/usr/bin/env bash
# Focused re-run of the cases that the first pass got wrong (dynamic POST Host,
# /metrics auth) plus the infra benches that failed (pgbench wrapper, redis
# parser). Keeps the edge-results.tsv / dns-results.tsv produced by run_all.sh
# untouched and regenerates only hey-results.tsv / pgbench-results.tsv /
# redis-results.tsv.
#
#   bash tools/load-test/run_part2.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1
source "$HOME/.cargo/env" 2>/dev/null || true

TS="$(date +%Y%m%d-%H%M%S)"
WORK="${WORK:-$ROOT/docs/reviews/2026-11-26-load-test}"
mkdir -p "$WORK/raw"

CONTROL_PORT="${CONTROL_PORT:-18080}"
EDGE_PORT="${EDGE_PORT:-18081}"
EDGE_ADMIN_PORT="${EDGE_ADMIN_PORT:-18082}"
ORIGIN_PORT="${ORIGIN_PORT:-19090}"
DOMAIN="loadtest2-${TS}.lagran.test"
GLOBAL_AGENT_TOKEN="lagran-agent-global-secret"
BIN="${BIN:-$ROOT/target/release}"

PIDS=()
source "$ROOT/tools/load-test/lib.sh"
source "$ROOT/tools/load-test/cases_edge.sh"
source "$ROOT/tools/load-test/cases_control.sh"
source "$ROOT/tools/load-test/cases_infra.sh"

cleanup() {
  log "teardown: stopping ${#PIDS[@]} background processes"
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null || true
}
trap cleanup EXIT

pkill -x lagran-edge 2>/dev/null; pkill -x lagran-control 2>/dev/null; pkill -f 'target/mock-origin' 2>/dev/null; sleep 1

"$ROOT/target/mock-origin" "$ORIGIN_PORT" >"$WORK/raw/origin2.log" 2>&1 &
PIDS+=($!)

CAPTCHA_ENABLED=false CONTROL_BIND="127.0.0.1:$CONTROL_PORT" RUST_LOG=warn \
  "$BIN/lagran-control" >"$WORK/raw/control2.log" 2>&1 &
PIDS+=($!)
wait_http "http://127.0.0.1:$CONTROL_PORT/health" 120 || { log "control not healthy"; exit 1; }

TOKEN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r '.token // empty')
[ -n "$TOKEN" ] || { log "login failed"; exit 1; }
AUTH="Authorization: Bearer $TOKEN"

NODE_NAME="loadtest2-edge-${TS}"
NODE=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" -H "$AUTH" -H 'content-type: application/json' \
  -d "{\"name\":\"$NODE_NAME\",\"region\":\"loadtest\",\"agent_url\":\"http://127.0.0.1:$EDGE_ADMIN_PORT\"}")
NODE_TOKEN=$(echo "$NODE" | jq -r '.token // empty')
[ -n "$NODE_TOKEN" ] || { log "node create failed: $NODE"; exit 1; }

DOM=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" -H "$AUTH" -H 'content-type: application/json' \
  -d "{\"name\":\"$DOMAIN\",\"origin_host\":\"127.0.0.1\",\"origin_port\":$ORIGIN_PORT,\"origin_proto\":\"http\"}")
DOMAIN_ID=$(echo "$DOM" | jq -r '.id // empty')
[ -n "$DOMAIN_ID" ] || { log "domain create failed: $DOM"; exit 1; }

CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
EDGE_LISTEN="127.0.0.1:$EDGE_PORT" EDGE_ADMIN_LISTEN="127.0.0.1:$EDGE_ADMIN_PORT" \
AGENT_URL="http://127.0.0.1:$EDGE_ADMIN_PORT" AGENT_TOKEN="$NODE_TOKEN" \
NODE_ID="$NODE_NAME" NODE_REGION="loadtest" ORIGIN_URL="http://127.0.0.1:$ORIGIN_PORT" \
CACHE_BACKEND="memory" CACHE_CAPACITY="200000" CACHE_TTL="60" MAX_CACHEABLE_BODY="8388608" \
LARGE_CACHE_ENABLED="true" LARGE_CACHE_DIR="$WORK/large-cache2" \
LARGE_CACHE_MIN_OBJECT_BYTES="262144" EDGE_COMPRESSION="true" \
ACCESS_LOG_REPORT="false" WAF_REPORT="false" RUST_LOG="warn" \
  "$BIN/lagran-edge" >"$WORK/raw/edge2.log" 2>&1 &
EDGE_PID=$!
PIDS+=($EDGE_PID)
wait_http "http://127.0.0.1:$EDGE_ADMIN_PORT/__lagran/health" 120 || { log "edge not healthy"; exit 1; }
for _ in $(seq 1 120); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/cached")" = "200" ] && break
  sleep 0.5
done
log "edge serving $DOMAIN"

# ---- regenerate hey-results.tsv (dynamic POST + control plane) ----
: > "$WORK/hey-results.tsv"
printf 'label\trps\tavg_s\tp50\tp90\tp99\tstatus\n' > "$WORK/hey-results.tsv"

log "edge: dynamic POST forwarding (/echo) with -host"
run_hey "dynamic-post-c32" "http://127.0.0.1:$EDGE_PORT/echo" 15 32 \
  -host "$DOMAIN" -m POST -H "content-type: text/plain" -d 'ping'

log "=== CONTROL PLANE API ==="
run_control_cases

# ---- infra ----
log "=== INFRA: pgbench / redis ==="
run_pgbench
run_redis_bench

log "PART2 DONE — results in $WORK"
