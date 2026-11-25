#!/usr/bin/env bash
# HEAD Content-Length by protocol: HTTP/2 real length, HTTP/1.1 zero.
#
#   bash tests/integration/head-h2.sh
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

# Developer shells often export http_proxy/https_proxy. curl then turns every
# HTTPS request into a CONNECT tunnel, where `--resolve` is ignored: the proxy
# dials the real DNS name instead of 127.0.0.1 and the handshake dies with
# "unexpected eof while reading" (curl reports 000). openssl s_client ignores
# proxies, which is why the chain check passed while every request failed.
# These tests only talk to loopback, so no proxy is ever wanted.
unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY no_proxy NO_PROXY

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
# A real chain: leaf + intermediate. The edge used to install only the leaf, so
# clients without a cached intermediate failed the handshake; the test below
# verifies the chain as an untrusting client would.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.crt" -subj "/CN=Test CA" >/dev/null 2>&1 || {
  echo "CA generation failed"; exit 1;
}
openssl req -newkey rsa:2048 -nodes \
  -keyout "$CERT_DIR/$DOMAIN.key" -out "$CERT_DIR/$DOMAIN.csr" \
  -subj "/CN=$DOMAIN" -addext "subjectAltName=DNS:$DOMAIN" >/dev/null 2>&1 || {
  echo "leaf request failed"; exit 1;
}
openssl x509 -req -in "$CERT_DIR/$DOMAIN.csr" -CA "$CERT_DIR/ca.crt" \
  -CAkey "$CERT_DIR/ca.key" -CAcreateserial -days 1 -copy_extensions copy \
  -out "$CERT_DIR/$DOMAIN.leaf.crt" >/dev/null 2>&1 || {
  echo "leaf signing failed"; exit 1;
}
cat "$CERT_DIR/$DOMAIN.leaf.crt" "$CERT_DIR/ca.crt" >"$CERT_DIR/$DOMAIN.crt"

MOCK_BIN="$ROOT/target/mock-origin"
if [[ ! -x "$MOCK_BIN" || tools/mock-origin/origin.rs -nt "$MOCK_BIN" ]]; then
  rustc -O tools/mock-origin/origin.rs -o "$MOCK_BIN" >/dev/null 2>&1 || exit 1
fi
"$MOCK_BIN" "$ORIGIN_PORT" >"$LOG_DIR/origin.log" 2>&1 &
PIDS+=($!)

CONTROL_BIND="127.0.0.1:$CONTROL_PORT" AGENT_TOKEN=test-global \
  CAPTCHA_ENABLED=false ./target/debug/lagran-control >"$LOG_DIR/control.log" 2>&1 &
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
EDGE_ADMIN_LISTEN= \
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

echo "== TLS chain =="
VERIFY=$(echo | openssl s_client -connect "127.0.0.1:$HTTPS_PORT" -servername "$DOMAIN" \
  -CAfile "$CERT_DIR/ca.crt" 2>/dev/null | grep 'Verify return code' | tail -1 \
  | sed 's/^[[:space:]]*//')
check "TLS chain verifies against the issuing CA" "$VERIFY" "Verify return code: 0 (ok)"

echo "== HTTP/2 HEAD =="
CODE=$(curl -sk -I --http2 --resolve "$DOMAIN:$HTTPS_PORT:127.0.0.1" \
  -D "$LOG_DIR/h" -o /dev/null -w '%{http_code}' "https://$DOMAIN:$HTTPS_PORT/head")
check "H2 HEAD status" "$CODE" "200"
check "H2 HEAD reported length" "$(hdr content-length)" "17"
check "H2 HEAD is served by Pingora" "$(hdr x-lagran-datapath)" "pingora"

echo "== HTTP/1.1 HEAD =="
CODE=$(curl -sk -I --http1.1 --resolve "$DOMAIN:$HTTPS_PORT:127.0.0.1" \
  -D "$LOG_DIR/h" -o /dev/null -w '%{http_code}' "https://$DOMAIN:$HTTPS_PORT/head")
check "H1 HEAD status" "$CODE" "200"
check "H1 HEAD reported length" "$(hdr content-length)" "17"
check "H1 HEAD is served by Pingora" "$(hdr x-lagran-datapath)" "pingora"

echo "== cold HEAD (handler path) =="
CODE=$(curl -sk -I --http2 --resolve "$DOMAIN:$HTTPS_PORT:127.0.0.1" \
  -D "$LOG_DIR/h" -o /dev/null -w '%{http_code}' "https://$DOMAIN:$HTTPS_PORT/head-cold-h2")
check "H2 cold HEAD status" "$CODE" "200"
check "H2 cold HEAD length" "$(hdr content-length)" "17"
check "H2 cold HEAD is served by Pingora" "$(hdr x-lagran-datapath)" "pingora"
CODE=$(curl -sk -I --http1.1 --resolve "$DOMAIN:$HTTPS_PORT:127.0.0.1" \
  -D "$LOG_DIR/h" -o /dev/null -w '%{http_code}' "https://$DOMAIN:$HTTPS_PORT/head-cold-h1")
check "H1 cold HEAD status" "$CODE" "200"
check "H1 cold HEAD length" "$(hdr content-length)" "17"
check "H1 cold HEAD is served by Pingora" "$(hdr x-lagran-datapath)" "pingora"

echo "== HEAD above MAX_CACHEABLE_BODY (16 MiB) =="
CODE=$(curl -sk -I --http1.1 --resolve "$DOMAIN:$HTTPS_PORT:127.0.0.1" \
  -D "$LOG_DIR/h" -o /dev/null -w '%{http_code}' "https://$DOMAIN:$HTTPS_PORT/huge")
check "huge HEAD status" "$CODE" "200"
check "huge HEAD length" "$(hdr content-length)" "16777216"
if grep -q 'origin failed' "$LOG_DIR/edge.log"; then
  fail "huge HEAD was reported as an origin failure"
else
  pass "huge HEAD did not mark the origin unhealthy"
fi

echo "== keepalive HEAD x2 =="
# Two HEADs on one connection must not hang: HEAD carries the real length but no
# body, so a client that waits for those bytes would stall until the timeout.
# One `-o` per URL keeps `-I` from printing the second response's headers into
# the `-w` stream; only the code/num_connects pairs are compared.
KEEP=$(curl -sk -I --http1.1 --resolve "$DOMAIN:$HTTPS_PORT:127.0.0.1" \
  -o /dev/null -o /dev/null -w '%{http_code}/%{num_connects} ' \
  "https://$DOMAIN:$HTTPS_PORT/head" "https://$DOMAIN:$HTTPS_PORT/head" 2>/dev/null)
KEEP=$(printf '%s' "$KEEP" | grep -oE '[0-9]{3}/[0-9]+' | tr '
' ' ')
check "second HEAD reuses the first connection" "$KEEP" "200/1 200/0 "

BODY=$(curl -sk --http2 --resolve "$DOMAIN:$HTTPS_PORT:127.0.0.1" "https://$DOMAIN:$HTTPS_PORT/head")
check "GET after HEAD has full body" "$BODY" "hello from origin"

if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL HEAD H2 CHECKS PASSED"
else
  echo "$FAILED HEAD H2 CHECK(S) FAILED (logs: $LOG_DIR)"
  exit 1
fi
