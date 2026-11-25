#!/usr/bin/env bash
# Stage 4: strict (client-requested) revalidation is resolved inside Pingora.
#
# A `no-cache` / `max-age=0` GET used to fall back to the legacy engine for six
# cases (computed validator, no validator, no origin, origin error/timeout,
# non-2xx, 304-but-unstorable). This suite exercises the three cases that can be
# driven from a fixture — computed validator, origin 500, origin timeout — and
# asserts the response still comes from the Pingora data plane and the
# `strict_revalidation` fallback counter never moves.
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18720}"
EDGE_PORT="${EDGE_PORT:-18721}"
ORIGIN_PORT="${ORIGIN_PORT:-19700}"
DOMAIN="strict-reval-$$.test"
LOG_DIR="${LOG_DIR:-/tmp/lagran-strict-reval}"
mkdir -p "$LOG_DIR"

PIDS=()
FAILED=0
TOKEN=""
DOMAIN_ID=""

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }
check() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }

cleanup() {
  if [[ -n "$TOKEN" && -n "$DOMAIN_ID" ]]; then
    curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID" \
      -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
  fi
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

hdr() { tr -d '\r' <"$LOG_DIR/h" | awk -F': ' -v k="$1" 'tolower($1)==k{print $2}' | head -1; }
# get <path> [extra curl args] -> status code; headers in $LOG_DIR/h, body in $LOG_DIR/b
get() {
  local path=$1
  shift
  curl -s -H "Host: $DOMAIN" "$@" -D "$LOG_DIR/h" -o "$LOG_DIR/b" -w '%{http_code}' --max-time 15 \
    "http://127.0.0.1:$EDGE_PORT$path"
}
metrics_body() {
  curl -s -H "x-lagran-agent-token: $NODE_TOKEN" --max-time 5 \
    "http://127.0.0.1:$EDGE_PORT/__lagran/metrics"
}
fb() { # <reason> -> current counter value, or 0 when absent
  metrics_body \
    | awk -v key="lagran_edge_legacy_fallback_total{reason=\"$1\"}" \
        '$1 == key { print $2; found = 1 } END { if (!found) print 0 }'
}

MOCK_BIN="$ROOT/target/mock-origin"
if [[ ! -x "$MOCK_BIN" || tools/mock-origin/origin.rs -nt "$MOCK_BIN" ]]; then
  rustc -O tools/mock-origin/origin.rs -o "$MOCK_BIN" || { echo "mock origin build failed"; exit 1; }
fi
"$MOCK_BIN" "$ORIGIN_PORT" >"$LOG_DIR/origin.log" 2>&1 & PIDS+=($!)

echo "== start control =="
CONTROL_BIND="127.0.0.1:$CONTROL_PORT" AGENT_TOKEN= ALERT_EVAL_SECS=60 \
  CAPTCHA_ENABLED=false ./target/debug/lagran-control >"$LOG_DIR/control.log" 2>&1 & PIDS+=($!)
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null && break; sleep 0.5; done
TOKEN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r .token)
[[ -n "$TOKEN" ]] || { echo "login failed"; exit 1; }

CREATED=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d "{\"name\":\"$DOMAIN\",\"origin_host\":\"127.0.0.1\",\"origin_port\":$ORIGIN_PORT,\"origin_proto\":\"http\"}")
DOMAIN_ID=$(printf '%s' "$CREATED" | jq -r .id)
[[ -n "$DOMAIN_ID" && "$DOMAIN_ID" != "null" ]] || { echo "domain failed: $CREATED"; exit 1; }

NODE=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d "{\"name\":\"strict-reval-$$-node\",\"region\":\"test\",\"agent_url\":\"http://127.0.0.1:$EDGE_PORT\"}")
NODE_TOKEN=$(printf '%s' "$NODE" | jq -r .token)
[[ -n "$NODE_TOKEN" && "$NODE_TOKEN" != "null" ]] || { echo "node failed: $NODE"; exit 1; }

echo "== start edge (short origin read timeout) =="
# 1.5 s read timeout so the stalled conditional GET in the timeout case fails fast.
CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
NODE_ID="strict-reval-$$-node" AGENT_TOKEN="$NODE_TOKEN" \
EDGE_LISTEN="127.0.0.1:$EDGE_PORT" EDGE_ADMIN_LISTEN= EDGE_HTTPS_LISTEN= \
CACHE_TTL=60 CACHE_BACKEND=memory ORIGIN_READ_TIMEOUT_MS=1500 \
CERT_DIR="$LOG_DIR/certs" ./target/debug/lagran-edge >"$LOG_DIR/edge.log" 2>&1 & PIDS+=($!)
for _ in $(seq 1 80); do curl -sf "http://127.0.0.1:$EDGE_PORT/__lagran/health" >/dev/null && break; sleep 0.25; done
SYNCED=0
for _ in $(seq 1 40); do
  get "/assets/no-validator.css" >/dev/null
  [[ "$(hdr x-cache)" == "MISS" || "$(hdr x-cache)" == "HIT" ]] && { SYNCED=1; break; }
  sleep 0.5
done
check "edge synced" "$SYNCED" "1"

STRICT_BEFORE=$(fb strict_revalidation)

echo "== computed validator =="
CODE=$(get "/assets/no-validator.css" -H 'Cache-Control: no-cache')
check "computed validator returns 200" "$CODE" "200"
check "computed validator is served by Pingora" "$(hdr x-lagran-datapath)" "pingora"
check "computed validator refills natively (MISS)" "$(hdr x-cache)" "MISS"

echo "== origin 500 on the conditional request =="
get "/flaky" >/dev/null
check "flaky warmup is cached" "$(hdr x-cache)" "MISS"
CODE=$(get "/flaky" -H 'Cache-Control: no-cache')
check "origin 500 is passed through, not a legacy fallback" "$CODE" "500"
check "origin 500 is served by Pingora" "$(hdr x-lagran-datapath)" "pingora"

echo "== origin timeout on the conditional request =="
get "/slow-flaky" >/dev/null
check "slow-flaky warmup is cached" "$(hdr x-cache)" "MISS"
CODE=$(get "/slow-flaky" -H 'Cache-Control: no-cache')
check "origin timeout returns 504" "$CODE" "504"
check "origin timeout is served by Pingora" "$(hdr x-lagran-datapath)" "pingora"
check "origin timeout names the error" "$(hdr x-lagran-error)" "ORIGIN_TIMEOUT"

echo "== no legacy fallback =="
STRICT_AFTER=$(fb strict_revalidation)
check "strict_revalidation counter never moved" "$STRICT_AFTER" "$STRICT_BEFORE"

if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL STRICT REVALIDATION CHECKS PASSED"
else
  echo "STRICT REVALIDATION CHECKS FAILED ($FAILED)"
  echo "logs: $LOG_DIR"
  exit 1
fi
