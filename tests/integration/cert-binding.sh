#!/usr/bin/env bash
# Certificate binding regression:
#   * a certificate is stored under the domain that was authorised, never under
#     the client-supplied `domain_name`;
#   * a mismatched private key or garbage PEM is rejected;
#   * uploading a replacement supersedes the previous active certificate.
#
#   bash tests/integration/cert-binding.sh
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18680}"
LOG_DIR="${LOG_DIR:-/tmp/lagran-cert-binding}"
mkdir -p "$LOG_DIR"
DOMAIN_A="cert-a-$$.test"
DOMAIN_B="cert-b-$$.test"
DOMAIN_C="cert-c-$$.test"

PIDS=()
FAILED=0
TOKEN=""
IDS=()
pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }
check() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }

cleanup() {
  for id in "${IDS[@]:-}"; do
    [[ -n "$id" ]] && curl -s -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/domains/$id" \
      -H "authorization: Bearer $TOKEN" >/dev/null 2>&1
  done
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

command -v openssl >/dev/null || { echo "openssl required"; exit 1; }
gen_pair() {
  local label=$1 san=$2
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=$san" \
    -addext "subjectAltName=DNS:$san" \
    -keyout "$LOG_DIR/$label.key" -out "$LOG_DIR/$label.crt" >/dev/null 2>&1
}
# The binding cases upload one certificate under several domains; a wildcard
# keeps them covered by its SAN while still exercising the authorisation rules.
gen_pair p1 "*.test"
gen_pair p2 "*.test"
gen_pair p3 "other.test"

CONTROL_BIND="127.0.0.1:$CONTROL_PORT" CAPTCHA_ENABLED=false ./target/debug/lagran-control \
  >"$LOG_DIR/control.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 80); do curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null && break; sleep 0.5; done
curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null || { echo "control failed"; exit 1; }

TOKEN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r '.token // empty')
[[ -n "$TOKEN" ]] || { echo "admin login failed"; exit 1; }
AUTH="authorization: Bearer $TOKEN"

create_domain() {
  local name=$1 token=$2
  curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" \
    -H "authorization: Bearer $token" -H 'content-type: application/json' \
    -d "{\"name\":\"$name\",\"origin_host\":\"127.0.0.1\",\"origin_port\":19090,\"origin_proto\":\"http\"}" \
    | jq -r '.id // empty'
}
A=$(create_domain "$DOMAIN_A" "$TOKEN")
B=$(create_domain "$DOMAIN_B" "$TOKEN")
[[ -n "$A" && -n "$B" ]] || { echo "admin domain create failed"; exit 1; }
IDS+=("$A" "$B")

USER_EMAIL="cert-user-$$@example.test"
curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/users" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"email\":\"$USER_EMAIL\",\"password\":\"cert-pass-123\",\"role\":\"user\"}" >/dev/null
UTOKEN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d "{\"email\":\"$USER_EMAIL\",\"password\":\"cert-pass-123\"}" | jq -r '.token // empty')
[[ -n "$UTOKEN" ]] || { echo "user login failed"; exit 1; }
C=$(create_domain "$DOMAIN_C" "$UTOKEN")
[[ -n "$C" ]] || { echo "user domain create failed"; exit 1; }
IDS+=("$C")

upload() { # <token> <domain_id> <domain_name> <cert> <key> -> status . domain_name
  local token=$1 did=$2 dname=$3 cert=$4 key=$5
  jq -n --arg did "$did" --arg dname "$dname" \
    --arg cert "$(cat "$cert")" --arg key "$(cat "$key")" \
    '{domain_id:$did, domain_name:$dname, cert_pem:$cert, key_pem:$key}' \
  | curl -s -o "$LOG_DIR/upload.json" -w '%{http_code}' -X POST \
      "http://127.0.0.1:$CONTROL_PORT/api/v1/certs" \
      -H "authorization: Bearer $token" -H 'content-type: application/json' --data @-
}

echo "== cross-tenant name must not decide the stored domain =="
CODE=$(upload "$UTOKEN" "$C" "$DOMAIN_A" "$LOG_DIR/p1.crt" "$LOG_DIR/p1.key")
check "user upload authorised on C returns 201" "$CODE" "201"
STORED=$(jq -r '.domain_name // empty' "$LOG_DIR/upload.json")
check "certificate stored under C, not A" "$STORED" "$DOMAIN_C"

CODE=$(upload "$UTOKEN" "$A" "$DOMAIN_A" "$LOG_DIR/p1.crt" "$LOG_DIR/p1.key")
check "user cannot write a certificate for A" "$CODE" "403"

echo "== admin mismatch is canonicalised to the authorised domain =="
CODE=$(upload "$TOKEN" "$A" "$DOMAIN_B" "$LOG_DIR/p1.crt" "$LOG_DIR/p1.key")
check "upload returns 201" "$CODE" "201"
STORED=$(jq -r '.domain_name // empty' "$LOG_DIR/upload.json")
check "certificate stored under A, not B" "$STORED" "$DOMAIN_A"

CODE=$(upload "$TOKEN" "$A" "$DOMAIN_A" "$LOG_DIR/p3.crt" "$LOG_DIR/p3.key")
check "certificate for another domain is rejected" "$CODE" "400"

echo "== malformed or mismatched PEM is rejected =="
CODE=$(upload "$TOKEN" "$A" "$DOMAIN_A" "$LOG_DIR/p1.crt" "$LOG_DIR/p2.key")
check "mismatched key rejected" "$CODE" "400"
printf 'not a certificate' >"$LOG_DIR/garbage.crt"
printf 'not a key' >"$LOG_DIR/garbage.key"
CODE=$(upload "$TOKEN" "$A" "$DOMAIN_A" "$LOG_DIR/garbage.crt" "$LOG_DIR/garbage.key")
check "garbage PEM rejected" "$CODE" "400"

echo "== replacement supersedes the previous active certificate =="
CODE=$(upload "$TOKEN" "$A" "$DOMAIN_A" "$LOG_DIR/p2.crt" "$LOG_DIR/p2.key")
check "replacement upload returns 201" "$CODE" "201"
ACTIVE=$(curl -s -H "$AUTH" "http://127.0.0.1:$CONTROL_PORT/api/v1/certs" \
  | jq --arg d "$DOMAIN_A" '[.[] | select(.domain_name == $d and .status == "active")] | length')
check "exactly one active certificate for A" "$ACTIVE" "1"
SUPERSEDED=$(curl -s -H "$AUTH" "http://127.0.0.1:$CONTROL_PORT/api/v1/certs" \
  | jq --arg d "$DOMAIN_A" '[.[] | select(.domain_name == $d and .status == "superseded")] | length')
check "old certificate marked superseded" "$SUPERSEDED" "1"

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL CERTIFICATE BINDING CHECKS PASSED"
else
  echo "$FAILED CERTIFICATE BINDING CHECK(S) FAILED (logs: $LOG_DIR)"
  exit 1
fi
