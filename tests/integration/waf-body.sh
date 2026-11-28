#!/usr/bin/env bash
# WAF request-body inspection (edge P1):
#   * a JSON/form body is buffered, inspected, then forwarded byte-for-byte
#   * managed SQLi in a body is blocked
#   * a custom DSL `body contains "..."" rule is evaluated
#   * oversized bodies follow the configured policy (default `log` = forward)
#
# Body policy is configured through the control-plane WAF settings API (P2).
# The last phase restarts the edge with WAF_BODY_OVERSIZE_POLICY=block to cover
# the operator env override.
#
#   bash tests/integration/waf-body.sh
#
# Needs Postgres, cargo-built binaries and jq.
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true
# Loopback requests must not be routed through a developer proxy: it would
# answer 502/CONNECT instead of exercising the edge.
unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY no_proxy NO_PROXY

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18390}"
EDGE_PORT="${EDGE_PORT:-18391}"
ORIGIN_PORT="${ORIGIN_PORT:-19391}"
HTTPS_PORT="${HTTPS_PORT:-18392}"
DOMAIN="${DOMAIN:-waf-body-$$.test}"
LOG_DIR="${LOG_DIR:-/tmp/lagran-waf-body}"
CERT_DIR="$LOG_DIR/certs"
mkdir -p "$LOG_DIR" "$CERT_DIR"

PIDS=()
FAILED=0
TOKEN=""
DOMAIN_ID=""
pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }
check() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }
contains() { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 (missing '$3')"; fi; }

cleanup() {
  if [[ -n "$TOKEN" && -n "$DOMAIN_ID" ]]; then
    curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID" \
      -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
  fi
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

# body_request <payload> [curl args...] -> status, response in $LOG_DIR/body
body_request() {
  local payload=$1
  shift
  curl -s --max-time 20 -o "$LOG_DIR/body" -D "$LOG_DIR/headers" -w '%{http_code}' \
    -X POST -H "Host: $DOMAIN" -H 'content-type: application/json' \
    --data-binary "$payload" "$@" "http://127.0.0.1:$EDGE_PORT/api/echo"
}

echo "== build mock origin =="
MOCK_BIN="$ROOT/target/mock-origin"
if [[ ! -x "$MOCK_BIN" || tools/mock-origin/origin.rs -nt "$MOCK_BIN" ]]; then
  rustc -O tools/mock-origin/origin.rs -o "$MOCK_BIN" || { echo "mock origin build failed"; exit 1; }
fi

"$MOCK_BIN" "$ORIGIN_PORT" >"$LOG_DIR/origin.log" 2>&1 &
PIDS+=($!)
CONTROL_BIND="127.0.0.1:$CONTROL_PORT" CAPTCHA_ENABLED=false ./target/debug/lagran-control >"$LOG_DIR/control.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 60); do
  curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null && break
  sleep 0.5
done
curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null || {
  echo "control did not start"; tail -20 "$LOG_DIR/control.log"; exit 1
}

echo "== login + domain + WAF body config =="
TOKEN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r '.token // empty')
AUTH="authorization: Bearer $TOKEN"
[[ -n "$TOKEN" ]] || { echo "login failed"; exit 1; }

curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"$DOMAIN\",\"origin_host\":\"127.0.0.1\",\"origin_port\":$ORIGIN_PORT,\"origin_proto\":\"http\"}" >/dev/null
DOMAIN_ID=$(curl -s -H "$AUTH" "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" \
  | jq -r --arg n "$DOMAIN" '.[] | select(.name == $n) | .id')
[[ -n "$DOMAIN_ID" ]] || { echo "domain not found"; exit 1; }

BODY_SETTINGS='{"enabled":true,"max_bytes":1024,"methods":["POST","PUT","PATCH"],"content_types":["application/json","multipart/form-data"],"oversize_policy":"log","uninspectable_policy":"log","timeout_ms":1000,"inspect_unknown_length":true,"decompress_gzip":true,"decompress_brotli":true}'
curl -s -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/waf" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d '{"enabled":true,"mode":"block","sqli":true,"xss":true,"traversal":true,"scanners":true,"rce":true,"ssrf":true,"xxe":true,"log4shell":true,"crlf":true,"ssti":true,"nosql":true,"ldap":true,"java":true,"webshell":true,"protocol":true,"challenge_difficulty":2,"challenge_ttl_secs":300,"body":'"$BODY_SETTINGS"'}' >/dev/null

INVALID=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/waf" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d '{"body":{"methods":["GET"]}}')
check "invalid body.methods rejected" "$INVALID" "400"
SETTINGS=$(curl -s -H "$AUTH" "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/waf")
check "settings expose body.enabled" "$(printf '%s' "$SETTINGS" | jq -r '.body.enabled')" "true"
check "settings expose body.max_bytes" "$(printf '%s' "$SETTINGS" | jq -r '.body.max_bytes')" "1024"
curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/waf/rules" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d '{"name":"请求体黑名单","field":"path","operator":"contains","value":"evil-body","expr":"body contains \"evil-body\"","action":"block","priority":10}' >/dev/null

NODE=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"waf-body-edge-$$\",\"region\":\"test\",\"agent_url\":\"http://127.0.0.1:$EDGE_PORT\"}")
NODE_TOKEN=$(printf '%s' "$NODE" | jq -r '.token // empty')
[[ -n "$NODE_TOKEN" ]] || { echo "node failed: $NODE"; exit 1; }

echo "== start edge with per-domain body policy =="
CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
EDGE_LISTEN="127.0.0.1:$EDGE_PORT" \
EDGE_ADMIN_LISTEN= \
AGENT_URL="http://127.0.0.1:$EDGE_PORT" \
AGENT_TOKEN="$NODE_TOKEN" \
NODE_ID="waf-body-edge-$$" \
CACHE_BACKEND=memory \
CACHE_TTL=60 \
RUST_LOG=lagran_edge=debug,edge=debug \
./target/debug/lagran-edge >"$LOG_DIR/edge.log" 2>&1 &
EDGE_PID=$!
PIDS+=($!)

for _ in $(seq 1 80); do
  curl -sf "http://127.0.0.1:$EDGE_PORT/__lagran/health" >/dev/null && break
  sleep 0.5
done
CODE=""
for _ in $(seq 1 40); do
  CODE=$(body_request '{"hello":"world"}')
  [[ "$CODE" == "200" ]] && break
  sleep 0.5
done
check "edge synced domain" "$CODE" "200"

echo "== benign body is forwarded byte-for-byte =="
check "benign JSON accepted" "$CODE" "200"
check "origin received the exact body length" \
  "$(jq -r '.bytes' "$LOG_DIR/body" 2>/dev/null)" "17"
check "origin received the exact body bytes" \
  "$(jq -r '.echo' "$LOG_DIR/body" 2>/dev/null)" '{"hello":"world"}'

echo "== managed rules inspect the body =="
CODE=$(body_request '{"q":"'"'"' or 1=1"}')
check "SQLi in JSON body blocked" "$CODE" "403"
contains "block page is the WAF page" "$(cat "$LOG_DIR/body")" "安全拦截"

echo "== custom DSL body rule =="
CODE=$(body_request '{"x":"evil-body"}')
check "custom body rule blocked" "$CODE" "403"

echo "== chunked / gzip bodies are inspected =="
CHUNKED_OK=$(curl -s -o "$LOG_DIR/body" -w '%{http_code}' \
  -X POST -H "Host: $DOMAIN" -H 'content-type: application/json' \
  -H 'Transfer-Encoding: chunked' \
  --data-binary '{"hello":"chunked"}' \
  "http://127.0.0.1:$EDGE_PORT/api/echo")
check "benign chunked body is forwarded" "$CHUNKED_OK" "200"
check "origin received the chunked body unchanged" \
  "$(jq -r '.echo' "$LOG_DIR/body" 2>/dev/null)" '{"hello":"chunked"}'

python3 - "$LOG_DIR/chunked-evil.json" <<'PY'
import sys
open(sys.argv[1], "w").write('{"q":"\' or 1=1"}')
PY
CHUNKED=$(curl -s -o "$LOG_DIR/body" -D "$LOG_DIR/headers" -w '%{http_code}' \
  -X POST -H "Host: $DOMAIN" -H 'content-type: application/json' \
  -H 'Transfer-Encoding: chunked' \
  --data-binary @"$LOG_DIR/chunked-evil.json" \
  "http://127.0.0.1:$EDGE_PORT/api/echo")
check "SQLi in a chunked body blocked" "$CHUNKED" "403"

python3 - "$LOG_DIR/evil.json.gz" <<'PY'
import gzip, sys
open(sys.argv[1], "wb").write(gzip.compress(b'{"q":"\' or 1=1"}'))
PY
GZIP=$(curl -s -o "$LOG_DIR/body" -D "$LOG_DIR/headers" -w '%{http_code}' \
  -X POST -H "Host: $DOMAIN" -H 'content-type: application/json' \
  -H 'Content-Encoding: gzip' \
  --data-binary @"$LOG_DIR/evil.json.gz" \
  "http://127.0.0.1:$EDGE_PORT/api/echo")
check "SQLi in a gzip body blocked" "$GZIP" "403"

python3 - "$LOG_DIR/chunked-big.json" <<'PY'
import sys
open(sys.argv[1], "w").write('{"data":"' + "a" * 2048 + '"}')
PY
CHUNKED_BIG=$(curl -s -o "$LOG_DIR/body" -D "$LOG_DIR/headers" -w '%{http_code}' \
  -X POST -H "Host: $DOMAIN" -H 'content-type: application/json' \
  -H 'Transfer-Encoding: chunked' \
  --data-binary @"$LOG_DIR/chunked-big.json" \
  "http://127.0.0.1:$EDGE_PORT/api/echo")
check "oversized chunked body rejected (cannot replay)" "$CHUNKED_BIG" "413"

echo "== brotli / multipart / Expect: 100-continue =="
printf '%s' 'iweAeyJxIjoiJyBvciAxPTEifQM=' | base64 -d >"$LOG_DIR/evil.json.br"
BR=$(curl -s -o "$LOG_DIR/body" -D "$LOG_DIR/headers" -w '%{http_code}' \
  -X POST -H "Host: $DOMAIN" -H 'content-type: application/json' \
  -H 'Content-Encoding: br' --data-binary @"$LOG_DIR/evil.json.br" \
  "http://127.0.0.1:$EDGE_PORT/api/echo")
check "SQLi in a brotli body blocked" "$BR" "403"

python3 - "$LOG_DIR/evil.multipart" <<'PY'
import sys
boundary = "X"
payload = (
    f"--{boundary}\r\n"
    'Content-Disposition: form-data; name="q"\r\n'
    "\r\n"
    "' or 1=1\r\n"
    f"--{boundary}--\r\n"
)
open(sys.argv[1], "wb").write(payload.encode())
PY
MULTIPART=$(curl -s -o "$LOG_DIR/body" -D "$LOG_DIR/headers" -w '%{http_code}' \
  -X POST -H "Host: $DOMAIN" \
  -H 'content-type: multipart/form-data; boundary=X' \
  --data-binary @"$LOG_DIR/evil.multipart" \
  "http://127.0.0.1:$EDGE_PORT/api/echo")
check "SQLi in a multipart text part blocked" "$MULTIPART" "403"

EXPECT=$(curl -s -o "$LOG_DIR/body" -D "$LOG_DIR/headers" -w '%{http_code}' \
  -X POST -H "Host: $DOMAIN" -H 'content-type: application/json' \
  -H 'Expect: 100-continue' \
  --data-binary '{"q":"'\'' or 1=1"}' \
  "http://127.0.0.1:$EDGE_PORT/api/echo")
check "SQLi with Expect: 100-continue blocked" "$EXPECT" "403"
contains "edge sent 100 Continue" "$(cat "$LOG_DIR/headers")" "100 Continue"

echo "== oversize follows the configured policy =="
PADDING=$(printf 'a%.0s' $(seq 1 2048))
CODE=$(body_request "{\"data\":\"$PADDING\"}")
check "oversize body forwarded under log policy" "$CODE" "200"
contains "edge logged the uninspected body" "$(cat "$LOG_DIR/edge.log")" "WAF body inspection skipped"

echo "== body metrics are exported =="
METRICS_CODE=$(curl -s -o "$LOG_DIR/metrics" -w '%{http_code}' -H "x-lagran-agent-token: $NODE_TOKEN" \
  "http://127.0.0.1:$EDGE_PORT/__lagran/metrics")
METRICS=$(cat "$LOG_DIR/metrics")
check "metrics endpoint accepts the node token" "$METRICS_CODE" "200"
contains "metrics expose inspected counter" "$METRICS" "lagran_edge_waf_body_inspected_total"
contains "metrics expose blocked counter" "$METRICS" "lagran_edge_waf_body_blocked_total"
INSPECTED=$(printf '%s' "$METRICS" | awk '/^lagran_edge_waf_body_inspected_total /{print $2; exit}')
BLOCKED=$(printf '%s' "$METRICS" | awk '/^lagran_edge_waf_body_blocked_total /{print $2; exit}')
if [[ "${INSPECTED:-0}" -ge 2 && "${BLOCKED:-0}" -ge 2 ]]; then
  pass "body counters advanced (inspected=$INSPECTED blocked=$BLOCKED)"
else
  fail "body counters stale (inspected=${INSPECTED:-0} blocked=${BLOCKED:-0})"
fi

echo "== oversize block policy rejects before reading =="
kill "$EDGE_PID" 2>/dev/null
wait "$EDGE_PID" 2>/dev/null
CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
EDGE_LISTEN="127.0.0.1:$EDGE_PORT" \
EDGE_ADMIN_LISTEN= \
AGENT_URL="http://127.0.0.1:$EDGE_PORT" \
AGENT_TOKEN="$NODE_TOKEN" \
NODE_ID="waf-body-edge-$$" \
CACHE_BACKEND=memory \
CACHE_TTL=60 \
WAF_BODY_INSPECTION=true \
WAF_BODY_MAX_BYTES=1024 \
WAF_BODY_OVERSIZE_POLICY=block \
WAF_BODY_UNINSPECTABLE_POLICY=log \
RUST_LOG=lagran_edge=warn,edge=warn \
./target/debug/lagran-edge >>"$LOG_DIR/edge.log" 2>&1 &
EDGE_PID=$!
PIDS+=($!)
for _ in $(seq 1 80); do
  curl -sf "http://127.0.0.1:$EDGE_PORT/__lagran/health" >/dev/null && break
  sleep 0.5
done
CODE=""
for _ in $(seq 1 40); do
  CODE=$(body_request '{"hello":"world"}')
  [[ "$CODE" == "200" ]] && break
  sleep 0.5
done
PADDING=$(printf 'a%.0s' $(seq 1 2048))
CODE=$(body_request "{\"data\":\"$PADDING\"}")
check "oversize body rejected under block policy" "$CODE" "413"
contains "block policy explains the rejection" "$(cat "$LOG_DIR/body")" "request body rejected"

echo "== HTTP/2 + TLS end-to-end =="
command -v openssl >/dev/null || { echo "openssl required"; exit 1; }
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.crt" -subj "/CN=WAF Body Test CA" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -keyout "$CERT_DIR/$DOMAIN.key" -out "$CERT_DIR/$DOMAIN.csr" \
  -subj "/CN=$DOMAIN" -addext "subjectAltName=DNS:$DOMAIN" >/dev/null 2>&1
openssl x509 -req -in "$CERT_DIR/$DOMAIN.csr" -CA "$CERT_DIR/ca.crt" \
  -CAkey "$CERT_DIR/ca.key" -CAcreateserial -days 1 -copy_extensions copy \
  -out "$CERT_DIR/$DOMAIN.leaf.crt" >/dev/null 2>&1
cat "$CERT_DIR/$DOMAIN.leaf.crt" "$CERT_DIR/ca.crt" >"$CERT_DIR/$DOMAIN.crt"

kill "$EDGE_PID" 2>/dev/null
wait "$EDGE_PID" 2>/dev/null
CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
EDGE_LISTEN="127.0.0.1:$EDGE_PORT" \
EDGE_HTTPS_LISTEN="127.0.0.1:$HTTPS_PORT" \
EDGE_ADMIN_LISTEN= \
AGENT_URL="http://127.0.0.1:$EDGE_PORT" \
AGENT_TOKEN="$NODE_TOKEN" \
NODE_ID="waf-body-edge-$$" \
CERT_DIR="$CERT_DIR" \
CACHE_BACKEND=memory \
CACHE_TTL=60 \
RUST_LOG=lagran_edge=warn,edge=warn \
./target/debug/lagran-edge >>"$LOG_DIR/edge.log" 2>&1 &
EDGE_PID=$!
PIDS+=($!)
for _ in $(seq 1 80); do
  curl -skf --resolve "$DOMAIN:$HTTPS_PORT:127.0.0.1" \
    "https://$DOMAIN:$HTTPS_PORT/__lagran/health" >/dev/null && break
  sleep 0.5
done
H2_CODE=""
for _ in $(seq 1 40); do
  H2_CODE=$(curl -sk --http2 --resolve "$DOMAIN:$HTTPS_PORT:127.0.0.1" \
    -o "$LOG_DIR/body" -w '%{http_code}:%{http_version}' \
    -X POST -H 'content-type: application/json' --data-binary '{"hello":"h2"}' \
    "https://$DOMAIN:$HTTPS_PORT/api/echo")
  [[ "$H2_CODE" == 200:* ]] && break
  sleep 0.5
done
check "benign H2 body forwarded" "${H2_CODE%%:*}" "200"
check "request used HTTP/2" "${H2_CODE##*:}" "2"
check "origin received the H2 body unchanged" \
  "$(jq -r '.echo' "$LOG_DIR/body" 2>/dev/null)" '{"hello":"h2"}'
H2_ATTACK=$(curl -sk --http2 --resolve "$DOMAIN:$HTTPS_PORT:127.0.0.1" \
  -o "$LOG_DIR/body" -w '%{http_code}' -X POST -H 'content-type: application/json' \
  --data-binary '{"q":"'\'' or 1=1"}' "https://$DOMAIN:$HTTPS_PORT/api/echo")
check "H2 SQLi body blocked" "$H2_ATTACK" "403"

echo "== CC/rate-limit runs before body inspection =="
curl -s -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$DOMAIN_ID/settings" \
  -H "$AUTH" -H 'content-type: application/json' \
  -d '{"rate_limit_rps":1,"rate_limit_burst":1}' >/dev/null
curl -s -X POST -H "x-lagran-agent-token: $NODE_TOKEN" \
  "http://127.0.0.1:$EDGE_PORT/__lagran/config/reload" >/dev/null
RATE_ACTIVE=0
for _ in $(seq 1 60); do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $DOMAIN" \
    "http://127.0.0.1:$EDGE_PORT/")
  if [[ "$CODE" == "429" ]]; then RATE_ACTIVE=1; break; fi
  sleep 0.5
done
check "rate limit reached the edge" "$RATE_ACTIVE" "1"
BEFORE=$(curl -s -H "x-lagran-agent-token: $NODE_TOKEN" \
  "http://127.0.0.1:$EDGE_PORT/__lagran/metrics" \
  | awk '/^lagran_edge_waf_body_inspected_total /{print $2; exit}')
# Give the token bucket one refill so the first request is the allowed one.
sleep 2
FIRST=$(body_request '{"rate":"first"}')
SECOND=$(body_request '{"rate":"second"}')
AFTER=$(curl -s -H "x-lagran-agent-token: $NODE_TOKEN" \
  "http://127.0.0.1:$EDGE_PORT/__lagran/metrics" \
  | awk '/^lagran_edge_waf_body_inspected_total /{print $2; exit}')
check "first request passes the rate limit" "$FIRST" "200"
check "second request is rate limited" "$SECOND" "429"
DELTA=$(( ${AFTER:-0} - ${BEFORE:-0} ))
if [[ "$DELTA" -eq 1 ]]; then
  pass "rate-limited request did not read a body (inspected +$DELTA)"
else
  fail "rate-limited request body read (inspected +$DELTA, want +1)"
fi

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL WAF BODY CHECKS PASSED"
else
  echo "$FAILED WAF BODY CHECK(S) FAILED (logs: $LOG_DIR)"
  exit 1
fi
