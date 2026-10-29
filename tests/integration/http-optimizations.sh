#!/usr/bin/env bash
# Control-plane HTTP optimizations: config/cert ETag/304, metrics batch,
# gzip access-log/WAF ingest.
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

PORT="${CONTROL_PORT:-18560}"
LOG_DIR="${LOG_DIR:-/tmp/lagran-http-opt}"
mkdir -p "$LOG_DIR"
PIDS=()
FAILED=0
TOKEN=""
NODE_ID=""
DOMAIN_ID=""
pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }
check() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }
cleanup() {
  if [[ -n "$TOKEN" && -n "$DOMAIN_ID" ]]; then
    curl -s -X DELETE "http://127.0.0.1:$PORT/api/v1/domains/$DOMAIN_ID" \
      -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
  fi
  if [[ -n "$TOKEN" && -n "$NODE_ID" ]]; then
    curl -s -X DELETE "http://127.0.0.1:$PORT/api/v1/nodes/$NODE_ID" \
      -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
  fi
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

CONTROL_BIND="127.0.0.1:$PORT" AGENT_TOKEN= CAPTCHA_ENABLED=false ./target/debug/lagran-control \
  >"$LOG_DIR/control.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$PORT/health" >/dev/null && break; sleep .2; done

TOKEN=$(curl -s -X POST "http://127.0.0.1:$PORT/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r '.token // empty')
[[ -n "$TOKEN" ]] || { echo "login failed"; exit 1; }
AUTH="authorization: Bearer $TOKEN"

NODE_NAME="http-opt-$RANDOM"
NODE=$(curl -s -X POST "http://127.0.0.1:$PORT/api/v1/nodes" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"$NODE_NAME\",\"region\":\"test\"}")
NODE_ID=$(printf '%s' "$NODE" | jq -r '.id // empty')
NODE_TOKEN=$(printf '%s' "$NODE" | jq -r '.token // empty')
[[ -n "$NODE_TOKEN" ]] || { echo "node create failed: $NODE"; exit 1; }
AGENT="x-lagran-agent-token: $NODE_TOKEN"

DOMAIN="http-opt-$RANDOM.test"
CREATE=$(curl -s -X POST "http://127.0.0.1:$PORT/api/v1/domains" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"$DOMAIN\",\"origin_host\":\"127.0.0.1\",\"origin_port\":8080,\"origin_proto\":\"http\",\"ssl_enabled\":false}")
DOMAIN_ID=$(printf '%s' "$CREATE" | jq -r '.id // empty')
[[ -n "$DOMAIN_ID" ]] || { echo "domain create failed: $CREATE"; exit 1; }

echo "== config ETag =="
curl -s -D "$LOG_DIR/config.h" -o "$LOG_DIR/config.json" \
  -H "$AGENT" "http://127.0.0.1:$PORT/api/v1/config"
ETAG=$(awk 'tolower($1)=="etag:" {print $2}' "$LOG_DIR/config.h" | tr -d '\r' | head -1)
check "config has ETag" "$([[ -n "$ETAG" ]] && echo yes || echo no)" "yes"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "$AGENT" \
  -H "If-None-Match: $ETAG" "http://127.0.0.1:$PORT/api/v1/config")
check "config returns 304" "$CODE" "304"

echo "== cert ETag =="
curl -s -D "$LOG_DIR/cert.h" -o /dev/null -H "$AGENT" \
  "http://127.0.0.1:$PORT/api/v1/certs/edge-sync"
ETAG2=$(awk 'tolower($1)=="etag:" {print $2}' "$LOG_DIR/cert.h" | tr -d '\r' | head -1)
check "cert has ETag" "$([[ -n "$ETAG2" ]] && echo yes || echo no)" "yes"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "$AGENT" \
  -H "If-None-Match: $ETAG2" "http://127.0.0.1:$PORT/api/v1/certs/edge-sync")
check "cert returns 304" "$CODE" "304"

echo "== metrics batch =="
BATCH=$(curl -s -X POST "http://127.0.0.1:$PORT/api/v1/metrics/report/batch" \
  -H "$AGENT" -H 'content-type: application/json' \
  -d "{\"items\":[{\"node_id\":\"$NODE_NAME\",\"domain\":\"$DOMAIN\",\"requests\":2,\"cache_hits\":1,\"cache_misses\":1,\"bytes_sent\":10},{\"node_id\":\"$NODE_NAME\",\"domain\":\"$DOMAIN\",\"requests\":3,\"cache_hits\":0,\"cache_misses\":3,\"bytes_sent\":20}]}")
check "metrics batch accepted" "$(printf '%s' "$BATCH" | jq -r '.accepted')" "2"

echo "== gzip access logs =="
printf '{"entries":[{"ts":"2026-01-01T00:00:00Z","node_id":"%s","client_ip":"127.0.0.1","method":"GET","host":"%s","path":"/","status":200,"bytes":1,"latency_ms":1,"cache_status":"MISS"}]}' \
  "$NODE_NAME" "$DOMAIN" | gzip -c > "$LOG_DIR/access.json.gz"
ACC=$(curl -s -X POST "http://127.0.0.1:$PORT/api/v1/access-logs/report" \
  -H "$AGENT" -H 'content-type: application/json' -H 'content-encoding: gzip' \
  -D "$LOG_DIR/acc.h" -o "$LOG_DIR/acc.b" -w '%{http_code}' \
  --data-binary "@$LOG_DIR/access.json.gz")
check "gzip access log accepted" "$(jq -r '.accepted' "$LOG_DIR/acc.b")" "1"

echo "== gzip WAF events =="
printf '{"events":[{"domain":"%s","node_id":"%s","client_ip":"127.0.0.1","method":"GET","path":"/x","action":"block","category":"sqli","rule_name":"test"}]}' \
  "$DOMAIN" "$NODE_NAME" | gzip -c > "$LOG_DIR/waf.json.gz"
WAF=$(curl -s -X POST "http://127.0.0.1:$PORT/api/v1/waf/events" \
  -H "$AGENT" -H 'content-type: application/json' -H 'content-encoding: gzip' \
  --data-binary "@$LOG_DIR/waf.json.gz")
check "gzip WAF event accepted" "$(printf '%s' "$WAF" | jq -r '.accepted')" "1"

if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL HTTP OPTIMIZATION CHECKS PASSED"
else
  echo "$FAILED HTTP OPTIMIZATION CHECK(S) FAILED (logs: $LOG_DIR)"
  exit 1
fi
