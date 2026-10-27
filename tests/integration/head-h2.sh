#!/usr/bin/env bash
# HEAD Content-Length by protocol: HTTP/2 real length, HTTP/1.1 zero.
#
#   bash tests/integration/head-h2.sh
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18470}"
EDGE_PORT="${EDGE_PORT:-18471}"
HTTPS_PORT="${HTTPS_PORT:-18472}"
ORIGIN_PORT="${ORIGIN_PORT:-19470}"
DOMAIN="head-h2-$$.test"
LOG_DIR="${LOG_DIR:-/tmp/lagran-head-h2}"
mkdir -p "$LOG_DIR"
CERT_DIR="$LOG_DIR/certs"
mkdir -p "$CERT_DIR"

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

command -v openssl >/dev/null || { echo "openssl required"; exit 1; }
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$CERT_DIR/$DOMAIN.key" -out "$CERT_DIR/$DOMAIN.crt" \
  -subj "/CN=$DOMAIN" -addext "subjectAltName=DNS:$DOMAIN" >/dev/null 2>&1 || {
  echo "cert generation failed"; exit 1;
}

MOCK_BIN="$ROOT/target/mock-origin"
if [[ ! -x "$MOCK_BIN" || tools/mock-origin/origin.rs -nt "$MOCK_BIN" ]]; then
  rustc -O tools/mock-origin/origin.rs -o "$MOCK_BIN" >/dev/null 2>&1 || exit 1
fi
"$MOCK_BIN" "$ORIGIN_PORT" >"$LOG_DIR/origin.log" 2>&1 &
PIDS+=($!)

CONTROL_BIND="127.0.0.1:$CONTROL_PORT" AGENT_TOKEN=test-global \
  ./target/debug/lagran-control >"$LOG_DIR/control.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 80); do curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null && break; sleep 0.5; done
curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null || { echo "control failed"; exit 1; }

TOKEN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r '.token // empty')
[[ -n "$TOKEN" ]] || { echo "login failed"; exit 1; }

CREATE=$(curl -s -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" \
  -d "{\"name\":\"$DOMAIN\",\"origin_host\":\"127.0.0.1\",\"origin_port\":$ORIGIN_PORT,\"origin_proto\":\"http\"}")
DOMAIN_ID=$(printf '%s' "$CREATE" | jq -r '.id // empty')
[[ -n "$DOMAIN_ID" ]] || { echo "domain failed: $CREATE"; exit 1; }

NODE=$(curl -s -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" \
  -d "{\"name\":\"head-h2-$$\",\"region\":\"test\",\"agent_url\":\"http://127.0.0.1:$EDGE_PORT\"}")
NODE_TOKEN=$(printf '%s' "$NODE" | jq -r '.token // empty')
[[ -n "$NODE_TOKEN" ]] || { echo "node failed: $NODE"; exit 1; }

CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
NODE_ID="head-h2-$$" \
AGENT_TOKEN="$NODE_TOKEN" \
EDGE_LISTEN="127.0.0.1:$EDGE_PORT" \
EDGE_HTTPS_LISTEN="127.0.0.1:$HTTPS_PORT" \
CERT_DIR="$CERT_DIR" \
CACHE_BACKEND=memory CACHE_TTL=60 \
./target/debug/lagran-edge >"$LOG_DIR/edge.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 80); do curl -sf "http://127.0.0.1:$EDGE_PORT/__lagran/health" >/dev/null && break; sleep 0.5; done

SYNCED=0
for _ in $(seq 1 40); do
  CODE=$(curl -s -H "Host: $DOMAIN" -o /dev/null -w '%{http_code}' "http://127.0.0.1:$EDGE_PORT/head")
  [[ "$CODE" == "200" ]] && { SYNCED=1; break; }
  sleep 0.5
done
check "edge synced domain" "$SYNCED" "1"

echo "== HTTP/2 HEAD =="
CODE=$(curl -sk -I --http2 --resolve "$DOMAIN:$HTTPS_PORT:127.0.0.1" \
  -D "$LOG_DIR/h" -o /dev/null -w '%{http_code}' "https://$DOMAIN:$HTTPS_PORT/head")
check "H2 HEAD status" "$CODE" "200"
check "H2 HEAD reported length" "$(hdr content-length)" "17"

echo "== HTTP/1.1 HEAD =="
CODE=$(curl -sk -I --http1.1 --resolve "$DOMAIN:$HTTPS_PORT:127.0.0.1" \
  -D "$LOG_DIR/h" -o /dev/null -w '%{http_code}' "https://$DOMAIN:$HTTPS_PORT/head")
check "H1 HEAD status" "$CODE" "200"
check "H1 HEAD keeps zero length" "$(hdr content-length)" "0"

echo "== cold HEAD (handler path) =="
CODE=$(curl -sk -I --http2 --resolve "$DOMAIN:$HTTPS_PORT:127.0.0.1" \
  -D "$LOG_DIR/h" -o /dev/null -w '%{http_code}' "https://$DOMAIN:$HTTPS_PORT/head-cold-h2")
check "H2 cold HEAD status" "$CODE" "200"
check "H2 cold HEAD length" "$(hdr content-length)" "17"
CODE=$(curl -sk -I --http1.1 --resolve "$DOMAIN:$HTTPS_PORT:127.0.0.1" \
  -D "$LOG_DIR/h" -o /dev/null -w '%{http_code}' "https://$DOMAIN:$HTTPS_PORT/head-cold-h1")
check "H1 cold HEAD status" "$CODE" "200"
check "H1 cold HEAD keeps zero length" "$(hdr content-length)" "0"

BODY=$(curl -sk --http2 --resolve "$DOMAIN:$HTTPS_PORT:127.0.0.1" "https://$DOMAIN:$HTTPS_PORT/head")
check "GET after HEAD has full body" "$BODY" "hello from origin"

if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL HEAD H2 CHECKS PASSED"
else
  echo "$FAILED HEAD H2 CHECK(S) FAILED (logs: $LOG_DIR)"
  exit 1
fi
