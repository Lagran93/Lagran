#!/usr/bin/env bash
# HTTPS origin regression: self-signed origin + SSL_CERT_FILE trust.
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18500}"
EDGE_PORT="${EDGE_PORT:-18502}"
ADMIN_PORT="${ADMIN_PORT:-18503}"
ORIGIN_PORT="${ORIGIN_PORT:-19450}"
LOG_DIR="${LOG_DIR:-/tmp/lagran-https-origin}"
mkdir -p "$LOG_DIR"

PIDS=()
TOKEN=""
NODE_ID=""
DOMAIN_ID=""

cleanup() {
  if [[ -n "$TOKEN" && -n "$DOMAIN_ID" ]]; then
    curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID" \
      -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
  fi
  if [[ -n "$TOKEN" && -n "$NODE_ID" ]]; then
    curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes/$NODE_ID" \
      -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
  fi
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$LOG_DIR/key.pem" -out "$LOG_DIR/cert.pem" \
  -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1' >/dev/null 2>&1
openssl s_server -accept "$ORIGIN_PORT" -cert "$LOG_DIR/cert.pem" \
  -key "$LOG_DIR/key.pem" -www >"$LOG_DIR/origin.log" 2>&1 &
PIDS+=($!)

CONTROL_BIND="127.0.0.1:$CONTROL_PORT" AGENT_TOKEN= CAPTCHA_ENABLED=false ./target/debug/lagran-control \
  >"$LOG_DIR/control.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 60); do
  curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null && break
  sleep 0.2
done

TOKEN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r '.token // empty')
[[ -n "$TOKEN" ]] || { echo "login failed"; exit 1; }

NODE_NAME="https-origin-$RANDOM"
NODE=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d "{\"name\":\"$NODE_NAME\",\"region\":\"test\",\"agent_url\":\"http://127.0.0.1:$ADMIN_PORT\"}")
NODE_ID=$(printf '%s' "$NODE" | jq -r '.id // empty')
NODE_TOKEN=$(printf '%s' "$NODE" | jq -r '.token // empty')
[[ -n "$NODE_TOKEN" ]] || { echo "node create failed: $NODE"; exit 1; }

DOMAIN="https-origin-$RANDOM.test"
CREATE=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d "{\"name\":\"$DOMAIN\",\"origin_host\":\"127.0.0.1\",\"origin_port\":$ORIGIN_PORT,\"origin_proto\":\"https\",\"ssl_enabled\":false}")
DOMAIN_ID=$(printf '%s' "$CREATE" | jq -r '.id // empty')
[[ -n "$DOMAIN_ID" ]] || { echo "domain create failed: $CREATE"; exit 1; }

EDGE_LISTEN="127.0.0.1:$EDGE_PORT" \
EDGE_ADMIN_LISTEN="127.0.0.1:$ADMIN_PORT" \
EDGE_HTTPS_LISTEN= \
AGENT_URL="http://127.0.0.1:$ADMIN_PORT" \
AGENT_TOKEN="$NODE_TOKEN" \
CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
NODE_ID="$NODE_NAME" \
PUBLIC_IP=127.0.0.1 \
ORIGIN_URL="https://127.0.0.1:$ORIGIN_PORT" \
CACHE_BACKEND=memory \
CERT_DIR="$LOG_DIR/certs" \
SSL_CERT_FILE="$LOG_DIR/cert.pem" \
./target/debug/lagran-edge >"$LOG_DIR/edge.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 80); do
  curl -sf "http://127.0.0.1:$EDGE_PORT/__lagran/health" >/dev/null && break
  sleep 0.25
done
sleep 1
CODE=$(curl -s -o "$LOG_DIR/body" -w '%{http_code}' -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT/")
if [[ "$CODE" == "200" ]] && grep -qi 's_server' "$LOG_DIR/body"; then
  echo "ALL HTTPS ORIGIN CHECKS PASSED"
else
  echo "HTTPS ORIGIN CHECK FAILED (code=$CODE)"
  echo "logs: $LOG_DIR"
  exit 1
fi
