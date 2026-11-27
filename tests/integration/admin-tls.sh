#!/usr/bin/env bash
# Management-port TLS with a private CA.
#
# Default: leaf certificate with DNS:localhost + IP:127.0.0.1.
# WILDCARD=1: leaf certificate for *.edge.test (plus the bare domain in SAN),
#             verifying one-label wildcard matching and that IP / two-label
#             names are rejected.
#
#   bash tests/integration/admin-tls.sh
#   WILDCARD=1 bash tests/integration/admin-tls.sh
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

# Developer shells often export http(s)_proxy. Every request here targets
# loopback, but curl would still hand it to the proxy: a plaintext request then
# comes back as the proxy's 502 instead of failing at the TLS listener, and a
# CONNECT tunnel hides the certificate error we want to assert. No proxy wanted.
unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY no_proxy NO_PROXY

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

WILDCARD="${WILDCARD:-0}"
if [[ "$WILDCARD" == "1" ]]; then
  MODE="wildcard"
  LOG_DIR="${LOG_DIR:-/tmp/lagran-admin-tls-wildcard}"
else
  MODE="ip-san"
  LOG_DIR="${LOG_DIR:-/tmp/lagran-admin-tls}"
fi
DATA_PORT="${DATA_PORT:-18110}"
ADMIN_PORT="${ADMIN_PORT:-18111}"
NO_TLS_DATA_PORT="${NO_TLS_DATA_PORT:-18112}"
NO_TLS_ADMIN_PORT="${NO_TLS_ADMIN_PORT:-18113}"
mkdir -p "$LOG_DIR"

PIDS=()
FAILED=0
pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }
check() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }
contains() { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 (missing '$3')"; fi; }

cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

command -v openssl >/dev/null || { echo "openssl required"; exit 1; }

echo "== generate private CA + $MODE leaf =="
CA="$LOG_DIR/edge-admin-ca.crt"
CA_KEY="$LOG_DIR/edge-admin-ca.key"
CRT="$LOG_DIR/edge-01.crt"
KEY="$LOG_DIR/edge-01.key"
OTHER_CA="$LOG_DIR/other-ca.crt"
CSR="$LOG_DIR/edge-01.csr"
EXT="$LOG_DIR/edge-01.ext"

openssl genrsa -out "$CA_KEY" 2048 >/dev/null 2>&1 || { echo "CA key generation failed"; exit 1; }
openssl req -x509 -new -nodes -sha256 -days 2 -key "$CA_KEY" -out "$CA" \
  -subj "/CN=Lagran Test Admin CA" >/dev/null 2>&1 || { echo "CA generation failed"; exit 1; }
openssl genrsa -out "$KEY" 2048 >/dev/null 2>&1 || { echo "leaf key generation failed"; exit 1; }

ADMIN_CURL=()
if [[ "$WILDCARD" == "1" ]]; then
  CN="*.edge.test"
  SAN="subjectAltName=DNS:*.edge.test,DNS:edge.test"
  ADMIN_HOST="edge-01.edge.test"
  ADMIN_URL="https://$ADMIN_HOST:$ADMIN_PORT"
  SNI="$ADMIN_HOST"
  ADMIN_CURL=(--resolve "$ADMIN_HOST:$ADMIN_PORT:127.0.0.1")
else
  CN="localhost"
  SAN="subjectAltName=DNS:localhost,IP:127.0.0.1"
  ADMIN_HOST="127.0.0.1"
  ADMIN_URL="https://$ADMIN_HOST:$ADMIN_PORT"
  SNI="localhost"
fi

openssl req -new -key "$KEY" -out "$CSR" -subj "/CN=$CN" >/dev/null 2>&1 || {
  echo "CSR failed"; exit 1;
}
cat >"$EXT" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
$SAN
EOF
openssl x509 -req -in "$CSR" -CA "$CA" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$CRT" -days 2 -sha256 -extfile "$EXT" >/dev/null 2>&1 || {
  echo "leaf signing failed"; exit 1;
}
openssl genrsa -out "$LOG_DIR/other-ca.key" 2048 >/dev/null 2>&1
openssl req -x509 -new -nodes -sha256 -days 2 -key "$LOG_DIR/other-ca.key" -out "$OTHER_CA" \
  -subj "/CN=Other CA" >/dev/null 2>&1 || { echo "other CA generation failed"; exit 1; }

LEAF_SAN=$(openssl x509 -in "$CRT" -noout -text | grep -A1 "Subject Alternative Name" | tail -1)
if [[ "$WILDCARD" == "1" ]]; then
  contains "wildcard SAN contains *.edge.test" "$LEAF_SAN" "DNS:*.edge.test"
  contains "wildcard SAN also covers the bare domain" "$LEAF_SAN" "DNS:edge.test"
else
  contains "leaf SAN contains the admin IP" "$LEAF_SAN" "IP Address:127.0.0.1"
fi

echo "== start edge with TLS admin listener ($MODE) =="
EDGE_LISTEN="127.0.0.1:$DATA_PORT" \
  EDGE_ADMIN_LISTEN="127.0.0.1:$ADMIN_PORT" \
  EDGE_ADMIN_TLS_CERT="$CRT" \
  EDGE_ADMIN_TLS_KEY="$KEY" \
  EDGE_ADMIN_REQUIRE_TLS=true \
  EDGE_HTTPS_LISTEN= \
  AGENT_URL="$ADMIN_URL" \
  AGENT_TOKEN=admin-tls-token \
  CONTROL_URL=http://127.0.0.1:1 \
  NODE_ID=admin-tls-test \
  PUBLIC_IP=127.0.0.1 \
  CACHE_BACKEND=memory \
  CERT_DIR="$LOG_DIR/certs" \
  RUST_LOG=lagran_edge=warn,edge=warn \
  ./target/debug/lagran-edge >"$LOG_DIR/edge.log" 2>&1 &
PIDS+=($!)

READY=0
for _ in $(seq 1 80); do
  if curl -sf --cacert "$CA" "${ADMIN_CURL[@]}" "$ADMIN_URL/__lagran/health" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 0.25
done
if [[ "$READY" != "1" ]]; then
  echo "edge did not start with the TLS admin listener"
  tail -20 "$LOG_DIR/edge.log"
  exit 1
fi
pass "edge started with the TLS admin listener"

code() { # <out-file> <curl args...>
  local out=$1
  shift
  curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$@" -D "$out" || true
}

check "TLS admin health accepted with the private CA" \
  "$(code "$LOG_DIR/h1" --cacert "$CA" "${ADMIN_CURL[@]}" "$ADMIN_URL/__lagran/health")" "200"
check "TLS admin health rejected with a different CA" \
  "$(code "$LOG_DIR/h2" --cacert "$OTHER_CA" "${ADMIN_CURL[@]}" "$ADMIN_URL/__lagran/health")" "000"
check "plaintext HTTP is refused by the TLS listener" \
  "$(code "$LOG_DIR/h3" "http://127.0.0.1:$ADMIN_PORT/__lagran/health")" "000"
check "TLS metrics rejects an anonymous scrape" \
  "$(code "$LOG_DIR/h4" --cacert "$CA" "${ADMIN_CURL[@]}" "$ADMIN_URL/__lagran/metrics")" "401"
check "TLS metrics accepts the node token" \
  "$(code "$LOG_DIR/h5" --cacert "$CA" "${ADMIN_CURL[@]}" \
    -H 'x-lagran-agent-token: admin-tls-token' "$ADMIN_URL/__lagran/metrics")" "200"

VERIFY=$(echo | openssl s_client -connect "127.0.0.1:$ADMIN_PORT" -servername "$SNI" \
  -CAfile "$CA" 2>/dev/null | grep "Verify return code" | tail -1 | sed 's/^[[:space:]]*//')
check "openssl verifies the admin certificate chain" "$VERIFY" "Verify return code: 0 (ok)"

if [[ "$WILDCARD" == "1" ]]; then
  check "wildcard matches a one-label host" \
    "$(code "$LOG_DIR/hw1" --cacert "$CA" \
      --resolve "edge-01.edge.test:$ADMIN_PORT:127.0.0.1" \
      "https://edge-01.edge.test:$ADMIN_PORT/__lagran/health")" "200"
  check "bare domain is covered by its explicit SAN" \
    "$(code "$LOG_DIR/hw2" --cacert "$CA" \
      --resolve "edge.test:$ADMIN_PORT:127.0.0.1" \
      "https://edge.test:$ADMIN_PORT/__lagran/health")" "200"
  check "wildcard does not match a two-label host" \
    "$(code "$LOG_DIR/hw3" --cacert "$CA" \
      --resolve "a.edge-01.edge.test:$ADMIN_PORT:127.0.0.1" \
      "https://a.edge-01.edge.test:$ADMIN_PORT/__lagran/health")" "000"
  check "wildcard does not match an IP address" \
    "$(code "$LOG_DIR/hw4" --cacert "$CA" \
      "https://127.0.0.1:$ADMIN_PORT/__lagran/health")" "000"
fi

echo "== require TLS without a certificate must fail startup =="
NO_TLS=$(EDGE_LISTEN="127.0.0.1:$NO_TLS_DATA_PORT" \
  EDGE_ADMIN_LISTEN="127.0.0.1:$NO_TLS_ADMIN_PORT" \
  EDGE_ADMIN_REQUIRE_TLS=true \
  EDGE_HTTPS_LISTEN= AGENT_URL="http://127.0.0.1:$NO_TLS_ADMIN_PORT" \
  AGENT_TOKEN=admin-tls-token CONTROL_URL=http://127.0.0.1:1 \
  NODE_ID=admin-tls-no-cert PUBLIC_IP=127.0.0.1 CACHE_BACKEND=memory \
  CERT_DIR="$LOG_DIR/certs" RUST_LOG=lagran_edge=error,edge=error \
  timeout 10 ./target/debug/lagran-edge 2>&1)
contains "missing certificate is rejected at startup" \
  "$NO_TLS" "EDGE_ADMIN_REQUIRE_TLS=true requires EDGE_ADMIN_TLS_CERT"

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL ADMIN TLS ($MODE) CHECKS PASSED"
else
  echo "$FAILED ADMIN TLS ($MODE) CHECK(S) FAILED (logs: $LOG_DIR)"
  exit 1
fi
