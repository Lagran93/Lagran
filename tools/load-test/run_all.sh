#!/usr/bin/env bash
# Lagran CDN comprehensive load test driver.
#
#   bash tools/load-test/run_all.sh
#
# Brings up a mock origin + control plane + edge + authoritative DNS on
# dedicated ports, provisions a throwaway node/domain, then runs the edge,
# control-plane, database, cache and DNS load matrices. Raw logs and TSV rows
# land in docs/reviews/2026-11-26-load-test/. Everything is torn down on exit.
#
# Assumes: PostgreSQL reachable via the repo .env DATABASE_URL, Redis on 6379,
# and debug binaries already built (cargo build -p control -p edge -p lagran-dns).
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
DNS_PORT="${DNS_PORT:-15353}"
DOMAIN="loadtest-${TS}.lagran.test"
GLOBAL_AGENT_TOKEN="lagran-agent-global-secret"
BIN="${BIN:-$ROOT/target/release}"
[ -x "$BIN/lagran-edge" ] || { echo "missing $BIN/lagran-edge — run: cargo build --release -p control -p edge -p lagran-dns" >&2; exit 1; }

PIDS=()
source "$ROOT/tools/load-test/lib.sh"
source "$ROOT/tools/load-test/cases_edge.sh"
source "$ROOT/tools/load-test/cases_control.sh"
source "$ROOT/tools/load-test/cases_infra.sh"
source "$ROOT/tools/load-test/cases_dns.sh"

cleanup() {
  log "teardown: stopping ${#PIDS[@]} background processes"
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null || true
}
trap cleanup EXIT

log "work dir: $WORK"

# ---- environment snapshot -------------------------------------------------
{
  echo "timestamp: $(date -u +%FT%TZ)"
  echo "commit: $(git rev-parse --short HEAD 2>/dev/null) ($(git log -1 --format=%s 2>/dev/null))"
  echo "kernel: $(uname -r)"
  echo "cpu: $(nproc) vCPU | $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ *//')"
  echo "mem: $(free -h | awk '/^Mem:/{print $2" total, "$7" available"}')"
  echo "rustc: $(rustc --version)"
  echo "wrk: $(wrk --version 2>&1 | head -1)"
  echo "hey: $(hey 2>&1 | head -1)"
  echo "pgbench: $(pgbench --version 2>&1)"
  echo "redis-benchmark: $(redis-benchmark --version 2>&1 | head -1)"
  echo "perf: $(perf --version 2>&1)"
  echo "edge binary: $(stat -c '%y' "$BIN/lagran-edge" 2>/dev/null | cut -d. -f1)"
  echo "control binary: $(stat -c '%y' "$BIN/lagran-control" 2>/dev/null | cut -d. -f1)"
} > "$WORK/env.txt"

# ---- mock origin ----------------------------------------------------------
MOCK_BIN="$ROOT/target/mock-origin"
if [[ ! -x "$MOCK_BIN" || tools/mock-origin/origin.rs -nt "$MOCK_BIN" ]]; then
  log "building mock origin"
  rustc -O tools/mock-origin/origin.rs -o "$MOCK_BIN" || { log "mock origin build failed"; exit 1; }
fi
"$MOCK_BIN" "$ORIGIN_PORT" >"$WORK/raw/origin.log" 2>&1 &
PIDS+=($!)

# ---- control plane --------------------------------------------------------
log "starting control plane on 127.0.0.1:$CONTROL_PORT"
CAPTCHA_ENABLED=false CONTROL_BIND="127.0.0.1:$CONTROL_PORT" RUST_LOG=warn \
  "$BIN/lagran-control" >"$WORK/raw/control.log" 2>&1 &
PIDS+=($!)
wait_http "http://127.0.0.1:$CONTROL_PORT/health" 120 || { log "control not healthy"; tail -25 "$WORK/raw/control.log"; exit 1; }
log "control up"

TOKEN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r '.token // empty')
[ -n "$TOKEN" ] || { log "login failed"; exit 1; }
AUTH="Authorization: Bearer $TOKEN"
log "logged in as demo"

# ---- provision node + domain ---------------------------------------------
NODE_NAME="loadtest-edge-${TS}"
NODE=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" -H "$AUTH" -H 'content-type: application/json' \
  -d "{\"name\":\"$NODE_NAME\",\"region\":\"loadtest\",\"agent_url\":\"http://127.0.0.1:$EDGE_ADMIN_PORT\"}")
NODE_TOKEN=$(echo "$NODE" | jq -r '.token // empty')
[ -n "$NODE_TOKEN" ] || { log "node create failed: $NODE"; exit 1; }

DOM=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" -H "$AUTH" -H 'content-type: application/json' \
  -d "{\"name\":\"$DOMAIN\",\"origin_host\":\"127.0.0.1\",\"origin_port\":$ORIGIN_PORT,\"origin_proto\":\"http\"}")
DOMAIN_ID=$(echo "$DOM" | jq -r '.id // empty')
[ -n "$DOMAIN_ID" ] || { log "domain create failed: $DOM"; exit 1; }
log "provisioned node=$NODE_NAME domain=$DOMAIN id=$DOMAIN_ID"

# ---- edge -----------------------------------------------------------------
log "starting edge on 127.0.0.1:$EDGE_PORT (admin $EDGE_ADMIN_PORT)"
CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
EDGE_LISTEN="127.0.0.1:$EDGE_PORT" \
EDGE_ADMIN_LISTEN="127.0.0.1:$EDGE_ADMIN_PORT" \
AGENT_URL="http://127.0.0.1:$EDGE_ADMIN_PORT" \
AGENT_TOKEN="$NODE_TOKEN" \
NODE_ID="$NODE_NAME" NODE_REGION="loadtest" \
ORIGIN_URL="http://127.0.0.1:$ORIGIN_PORT" \
CACHE_BACKEND="memory" CACHE_CAPACITY="200000" CACHE_TTL="60" \
MAX_CACHEABLE_BODY="8388608" \
LARGE_CACHE_ENABLED="true" LARGE_CACHE_DIR="$WORK/large-cache" \
LARGE_CACHE_MIN_OBJECT_BYTES="262144" LARGE_CACHE_MAX_BYTES="21474836480" \
LARGE_CACHE_MIN_FREE_BYTES="536870912" \
EDGE_COMPRESSION="true" \
ACCESS_LOG_REPORT="false" WAF_REPORT="false" \
RUST_LOG="warn" \
  "$BIN/lagran-edge" >"$WORK/raw/edge.log" 2>&1 &
EDGE_PID=$!
PIDS+=($EDGE_PID)

wait_http "http://127.0.0.1:$EDGE_ADMIN_PORT/__lagran/health" 120 || { log "edge not healthy"; tail -25 "$WORK/raw/edge.log"; exit 1; }
log "edge up pid=$EDGE_PID"

log "waiting for edge to learn $DOMAIN"
ok=0
for _ in $(seq 1 120); do
  code=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/cached")
  [ "$code" = "200" ] && { ok=1; break; }
  sleep 0.5
done
[ "$ok" = "1" ] || { log "edge never served $DOMAIN"; tail -30 "$WORK/raw/edge.log"; exit 1; }
log "edge serving $DOMAIN"

# ---- EDGE data plane ------------------------------------------------------
log "=== EDGE DATA PLANE ==="
run_edge_cases
run_edge_perf
curl -s -H "X-Lagran-Agent-Token: $NODE_TOKEN" "http://127.0.0.1:$EDGE_ADMIN_PORT/__lagran/metrics" > "$WORK/raw/edge-metrics.txt" 2>/dev/null || true

# ---- WAF ------------------------------------------------------------------
log "=== WAF (enable + deny rule) ==="
curl -s -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/waf" -H "$AUTH" -H 'content-type: application/json' \
  -d '{"enabled":true,"mode":"block","security_level":"off","challenge_difficulty":4,"challenge_ttl_secs":1800}' >/dev/null
curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/waf/rules" -H "$AUTH" -H 'content-type: application/json' \
  -d '{"name":"block-loadtest","field":"path","operator":"contains","value":"blockme","action":"block","priority":1,"enabled":true}' >/dev/null
ok=0
for _ in $(seq 1 120); do
  code=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/blockme")
  [ "$code" = "403" ] && { ok=1; break; }
  sleep 0.5
done
log "waf deny rule active=$ok (403 expected)"
run_edge_waf

# ---- CONTROL PLANE --------------------------------------------------------
log "=== CONTROL PLANE API ==="
run_control_cases
curl -s "http://127.0.0.1:$CONTROL_PORT/metrics" > "$WORK/raw/control-metrics.txt" 2>/dev/null || true

# ---- INFRA ----------------------------------------------------------------
log "=== INFRA: pgbench / redis ==="
run_pgbench
run_redis_bench

# ---- DNS ------------------------------------------------------------------
log "=== DNS ==="
start_dns
run_dns_cases

log "DONE — results in $WORK"
