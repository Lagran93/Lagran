#!/usr/bin/env bash
# Alerting: channel CRUD/test, origin-unhealthy rule, webhook delivery,
# resolution and Prometheus alert gauges.
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18470}"
WEBHOOK_PORT="${WEBHOOK_PORT:-19495}"
LOG_DIR="${LOG_DIR:-/tmp/lagran-alerts}"
mkdir -p "$LOG_DIR"

PIDS=()
FAILED=0
TOKEN=""
CHANNEL_ID=""
RULE_ID=""
DOMAIN="alert-$$.test"

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }
check() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }
contains() { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 (missing '$3')"; fi; }

cleanup() {
  if [[ -n "$TOKEN" && -n "$CHANNEL_ID" ]]; then
    curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/alert-channels/$CHANNEL_ID" \
      -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
  fi
  if [[ -n "$TOKEN" && -n "$RULE_ID" ]]; then
    curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/alert-rules/$RULE_ID" \
      -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
  fi
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

api() { curl -s -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' "$@"; }
agent() { curl -s -H "x-lagran-agent-token: $NODE_TOKEN" -H 'content-type: application/json' "$@"; }

MOCK_BIN="$ROOT/target/mock-origin"
if [[ ! -x "$MOCK_BIN" || tools/mock-origin/origin.rs -nt "$MOCK_BIN" ]]; then
  rustc -O tools/mock-origin/origin.rs -o "$MOCK_BIN" || { echo "mock origin build failed"; exit 1; }
fi
"$MOCK_BIN" "$WEBHOOK_PORT" >"$LOG_DIR/webhook.log" 2>&1 & PIDS+=($!)

echo "== start control =="
CONTROL_BIND="127.0.0.1:$CONTROL_PORT" AGENT_TOKEN=test-global ALERT_EVAL_SECS=2 RUST_LOG=debug \
  CAPTCHA_ENABLED=false ./target/debug/lagran-control >"$LOG_DIR/control.log" 2>&1 & PIDS+=($!)
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null && break; sleep 0.5; done
curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null || { echo "control did not start"; exit 1; }

TOKEN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r '.token // empty')
[[ -n "$TOKEN" ]] || { echo "login failed"; exit 1; }

echo "== channel validation =="
BAD=$(api -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/alert-channels" \
  -d '{"name":"bad","kind":"email","config":{"smtp_host":"","from":"","to":[]}}')
check "invalid email channel rejected" "$BAD" "400"
BAD=$(api -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/alert-channels" \
  -d '{"name":"bad","kind":"telegram","config":{}}')
check "invalid telegram channel rejected" "$BAD" "400"

CH=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/alert-channels" \
  -d "{\"name\":\"webhook-$$\",\"kind\":\"webhook\",\"config\":{\"url\":\"http://127.0.0.1:$WEBHOOK_PORT/hook\",\"secret\":\"test-secret\"}}")
CHANNEL_ID=$(printf '%s' "$CH" | jq -r '.id // empty')
check "webhook channel created" "$(printf '%s' "$CH" | jq -r '.kind')" "webhook"
[[ -n "$CHANNEL_ID" ]] || { echo "channel failed: $CH"; exit 1; }
contains "webhook secret is masked" "$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/alert-channels" | jq -c .)" "••••••••"
TEST=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/alert-channels/$CHANNEL_ID/test")
check "webhook test delivered" "$(printf '%s' "$TEST" | jq -r '.success')" "true"

echo "== rule =="
RULE=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/alert-rules" \
  -d "{\"name\":\"origin-unhealthy-$$\",\"metric\":\"origin_unhealthy\",\"threshold\":1,\"window_minutes\":5,\"channel_ids\":[\"$CHANNEL_ID\"],\"cooldown_seconds\":0}")
RULE_ID=$(printf '%s' "$RULE" | jq -r '.id // empty')
check "rule created" "$(printf '%s' "$RULE" | jq -r '.metric')" "origin_unhealthy"
check "rule carries channel" "$(printf '%s' "$RULE" | jq -r '.channel_ids | length')" "1"
[[ -n "$RULE_ID" ]] || { echo "rule failed: $RULE"; exit 1; }

NODE=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" \
  -d "{\"name\":\"alert-edge-$$\",\"region\":\"test\",\"agent_url\":\"http://127.0.0.1:1\"}")
NODE_TOKEN=$(printf '%s' "$NODE" | jq -r '.token // empty')
[[ -n "$NODE_TOKEN" ]] || { echo "node failed: $NODE"; exit 1; }

agent -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/origin-health/report" \
  -d "{\"domain_name\":\"$DOMAIN\",\"origin_url\":\"http://127.0.0.1:1\",\"healthy\":false,\"latency_ms\":10,\"error\":\"connection refused\"}" >/dev/null

FIRING=0
for _ in $(seq 1 20); do
  EVENTS=$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/alert-events?limit=500")
  if printf '%s' "$EVENTS" | jq -e --arg d "$DOMAIN" '.[] | select(.fingerprint | contains($d)) | select(.status=="firing")' >/dev/null; then
    FIRING=1
    break
  fi
  sleep 0.5
done
check "origin rule fires" "$FIRING" "1"
NOTIFIED="false"
for _ in $(seq 1 20); do
  NOTIFIED=$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/alert-events?limit=500" | \
    jq -r --arg d "$DOMAIN" '.[] | select(.fingerprint | contains($d)) | .notified' | head -1)
  [[ "$NOTIFIED" == "true" ]] && break
  sleep 0.5
done
check "webhook notification delivered" "$NOTIFIED" "true"
check "summary counts firing" "$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/alerts/summary" | jq -r '.firing > 0')" "true"

agent -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/origin-health/report" \
  -d "{\"domain_name\":\"$DOMAIN\",\"origin_url\":\"http://127.0.0.1:1\",\"healthy\":true,\"latency_ms\":5}" >/dev/null

RESOLVED=0
for _ in $(seq 1 20); do
  if api "http://127.0.0.1:$CONTROL_PORT/api/v1/alert-events?limit=500" | jq -e --arg d "$DOMAIN" \
    '.[] | select(.fingerprint | contains($d)) | select(.status=="resolved")' >/dev/null; then
    RESOLVED=1
    break
  fi
  sleep 0.5
done
check "origin rule resolves" "$RESOLVED" "1"

echo "== prometheus =="
METRICS=$(curl -s "http://127.0.0.1:$CONTROL_PORT/metrics")
contains "metrics exposes alert gauge" "$METRICS" "lagran_alerts_firing"
contains "metrics exposes channel gauge" "$METRICS" "lagran_alert_channels_enabled"
contains "metrics exposes origin health" "$METRICS" "lagran_origin_health"

if (( FAILED > 0 )); then
  echo "ALERT CHECKS FAILED: $FAILED"
  exit 1
fi
echo "ALL ALERT CHECKS PASSED"
