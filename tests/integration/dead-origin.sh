#!/usr/bin/env bash
# Dead/misconfigured primary origin without backup must return 502, not panic.
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1
CONTROL_PORT="${CONTROL_PORT:-18520}"
EDGE_PORT="${EDGE_PORT:-18522}"
ADMIN_PORT="${ADMIN_PORT:-18523}"
LOG_DIR="${LOG_DIR:-/tmp/lagran-dead-origin}"
mkdir -p "$LOG_DIR"
PIDS=(); TOKEN=""; NODE_ID=""; DOMAIN_ID=""
cleanup() {
  if [[ -n "$TOKEN" && -n "$DOMAIN_ID" ]]; then
    curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID" -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
  fi
  if [[ -n "$TOKEN" && -n "$NODE_ID" ]]; then
    curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes/$NODE_ID" -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
  fi
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT
CONTROL_BIND="127.0.0.1:$CONTROL_PORT" AGENT_TOKEN= ./target/debug/lagran-control >"$LOG_DIR/control.log" 2>&1 & PIDS+=($!)
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null && break; sleep .2; done
TOKEN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" -H 'content-type: application/json' -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r '.token // empty')
NODE_NAME="dead-origin-$RANDOM"
NODE=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' -d "{\"name\":\"$NODE_NAME\",\"region\":\"test\",\"agent_url\":\"http://127.0.0.1:$ADMIN_PORT\"}")
NODE_ID=$(printf '%s' "$NODE" | jq -r '.id // empty')
NODE_TOKEN=$(printf '%s' "$NODE" | jq -r '.token // empty')
DOMAIN="dead-origin-$RANDOM.test"
CREATE=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' -d "{\"name\":\"$DOMAIN\",\"origin_host\":\"a.lagran.test\",\"origin_port\":443,\"origin_proto\":\"https\",\"ssl_enabled\":false}")
DOMAIN_ID=$(printf '%s' "$CREATE" | jq -r '.id // empty')
[[ -n "$DOMAIN_ID" ]] || { echo "domain create failed: $CREATE"; exit 1; }
EDGE_LISTEN="127.0.0.1:$EDGE_PORT" EDGE_ADMIN_LISTEN="127.0.0.1:$ADMIN_PORT" EDGE_HTTPS_LISTEN= \
AGENT_URL="http://127.0.0.1:$ADMIN_PORT" AGENT_TOKEN="$NODE_TOKEN" CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
NODE_ID="$NODE_NAME" PUBLIC_IP=127.0.0.1 ORIGIN_URL="https://a.lagran.test:443" \
CACHE_BACKEND=memory CERT_DIR="$LOG_DIR/certs" ./target/debug/lagran-edge >"$LOG_DIR/edge.log" 2>&1 & PIDS+=($!)
for _ in $(seq 1 80); do curl -sf "http://127.0.0.1:$EDGE_PORT/__lagran/health" >/dev/null && break; sleep .25; done
sleep 2
CODE=$(curl -s -o "$LOG_DIR/body" -w '%{http_code}' -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/")
sleep 1
if [[ "$CODE" == "502" && -s "$LOG_DIR/body" ]] && kill -0 "${PIDS[1]}" 2>/dev/null; then
  echo "ALL DEAD ORIGIN CHECKS PASSED"
else
  echo "DEAD ORIGIN CHECK FAILED (code=$CODE, process_alive=$(kill -0 "${PIDS[1]}" 2>/dev/null && echo yes || echo no))"
  echo "logs: $LOG_DIR"
  exit 1
fi
