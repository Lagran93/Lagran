#!/usr/bin/env bash
# Config versions, rollback, approval, staged release and apply reports.
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18680}"
EDGE_PORT="${EDGE_PORT:-18681}"
ORIGIN_PORT="${ORIGIN_PORT:-19600}"
DOMAIN="release-$$.test"
NODE_NAME="release-edge-$$"
LOG_DIR="${LOG_DIR:-/tmp/lagran-config-release}"
mkdir -p "$LOG_DIR"

PIDS=()
FAILED=0
TOKEN=""
DOMAIN_ID=""
NODE_TOKEN=""

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

api() { curl -s -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' "$@"; }
jqget() { printf '%s' "$1" | jq -r "$2"; }

MOCK_BIN="$ROOT/target/mock-origin"
if [[ ! -x "$MOCK_BIN" || tools/mock-origin/origin.rs -nt "$MOCK_BIN" ]]; then
  rustc -O tools/mock-origin/origin.rs -o "$MOCK_BIN" || exit 1
fi
"$MOCK_BIN" "$ORIGIN_PORT" >"$LOG_DIR/origin.log" 2>&1 & PIDS+=($!)

CONTROL_BIND="127.0.0.1:$CONTROL_PORT" AGENT_TOKEN=test-global ALERT_EVAL_SECS=60 \
  ./target/debug/lagran-control >"$LOG_DIR/control.log" 2>&1 & PIDS+=($!)
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null && break; sleep 0.5; done
TOKEN=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r .token)
[[ -n "$TOKEN" ]] || { echo "login failed"; exit 1; }

CREATED=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" \
  -d "{\"name\":\"$DOMAIN\",\"origin_host\":\"127.0.0.1\",\"origin_port\":$ORIGIN_PORT}")
DOMAIN_ID=$(jqget "$CREATED" .id)
[[ -n "$DOMAIN_ID" ]] || { echo "domain failed: $CREATED"; exit 1; }

NODE=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" \
  -d "{\"name\":\"$NODE_NAME\",\"region\":\"test\",\"agent_url\":\"http://127.0.0.1:$EDGE_PORT\"}")
NODE_TOKEN=$(jqget "$NODE" .token)
[[ -n "$NODE_TOKEN" ]] || { echo "node failed: $NODE"; exit 1; }

CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
NODE_ID="$NODE_NAME" AGENT_TOKEN="$NODE_TOKEN" \
EDGE_LISTEN="127.0.0.1:$EDGE_PORT" EDGE_ADMIN_LISTEN= \
CACHE_TTL=60 CACHE_BACKEND=memory CONFIG_SYNC_INTERVAL_SECS=5 \
./target/debug/lagran-edge >"$LOG_DIR/edge.log" 2>&1 & PIDS+=($!)
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$EDGE_PORT/__lagran/health" >/dev/null && break; sleep 0.5; done
for _ in $(seq 1 20); do
  [[ "$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/nodes" | jq -r --arg n "$NODE_NAME" '.[] | select(.name==$n) | .status' | head -1)" == "online" ]] && break
  sleep 0.5
done

echo "== versions =="
V1=$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/config/versions?domain=$DOMAIN" | jq -r '.[0].id')
check "domain create records v1" "$([[ -n "$V1" && "$V1" != "null" ]] && echo yes)" "yes"

api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/rules" \
  -d "{\"domain_id\":\"$DOMAIN_ID\",\"path_pattern\":\"/assets/*\",\"action\":\"cache\",\"ttl_seconds\":600,\"priority\":10}" >/dev/null
V2=$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/config/versions?domain=$DOMAIN" | jq -r '.[0].id')
check "rule change records v2" "$([[ -n "$V2" && "$V2" != "$V1" ]] && echo yes)" "yes"
DIFF=$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/config/versions/$V2" | jq -r '.diff | length')
check "version diff present" "$([[ "$DIFF" -gt 0 ]] && echo yes)" "yes"

echo "== one-click rollback =="
api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/config/versions/$V1/rollback" -d '{}' >/dev/null
PUB=$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/domains" | jq -r --arg d "$DOMAIN" '.[] | select(.name==$d) | .published_version_id')
check "rollback pins v1" "$PUB" "$V1"

echo "== dry-run + approval + staged publish =="
REL=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/config/releases" \
  -d "{\"versions\":[{\"domain\":\"$DOMAIN\",\"version_id\":\"$V2\"}],\"target_nodes\":[\"$NODE_NAME\"],\"note\":\"gray v2\"}")
REL_ID=$(jqget "$REL" .id)
check "release created pending" "$(jqget "$REL" .status)" "pending_approval"
DRY=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/config/releases/$REL_ID/dry-run" -d '{}')
check "dry-run ok" "$(jqget "$DRY" .ok)" "true"
check "dry-run has diff" "$([[ "$(jqget "$DRY" '.domains[0].diff | length')" -gt 0 ]] && echo yes)" "yes"
api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/config/releases/$REL_ID/approve" -d '{}' >/dev/null
check "approved" "$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/config/releases/$REL_ID" | jq -r .status)" "approved"
api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/config/releases/$REL_ID/publish" -d '{}' >/dev/null
check "publishing" "$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/config/releases/$REL_ID" | jq -r .status)" "publishing"
PUBLISHED=0
for _ in $(seq 1 30); do
  STATUS=$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/config/releases/$REL_ID" | jq -r .status)
  [[ "$STATUS" == "published" ]] && { PUBLISHED=1; break; }
  sleep 1
done
check "release published after edge report" "$PUBLISHED" "1"
CFG=$(curl -s "http://127.0.0.1:$CONTROL_PORT/api/v1/config" \
  -H "x-lagran-agent-token: $NODE_TOKEN" -H "x-lagran-node-id: $NODE_NAME")
check "published snapshot reaches edge config" \
  "$(printf '%s' "$CFG" | jq -r --arg d "$DOMAIN" '[.domains[] | select(.domain==$d) | .rules[] | select(.path_pattern=="/assets/*")] | length')" "1"

echo "== auto rollback on apply failure =="
REL2=$(api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/config/releases" \
  -d "{\"versions\":[{\"domain\":\"$DOMAIN\",\"version_id\":\"$V1\"}],\"target_nodes\":[\"$NODE_NAME\"],\"note\":\"fail test\"}")
REL2_ID=$(jqget "$REL2" .id)
api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/config/releases/$REL2_ID/approve" -d '{}' >/dev/null
api -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/config/releases/$REL2_ID/publish" -d '{}' >/dev/null
curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/config/apply-report" \
  -H "x-lagran-agent-token: $NODE_TOKEN" -H "x-lagran-node-id: $NODE_NAME" \
  -H 'content-type: application/json' \
  -d "{\"release_id\":\"$REL2_ID\",\"success\":false,\"error\":\"simulated apply failure\"}" >/dev/null
check "release rolled back" "$(api "http://127.0.0.1:$CONTROL_PORT/api/v1/config/releases/$REL2_ID" | jq -r .status)" "rolled_back"
CFG2=$(curl -s "http://127.0.0.1:$CONTROL_PORT/api/v1/config" \
  -H "x-lagran-agent-token: $NODE_TOKEN" -H "x-lagran-node-id: $NODE_NAME")
check "auto rollback preserves previous published snapshot" \
  "$(printf '%s' "$CFG2" | jq -r --arg d "$DOMAIN" '[.domains[] | select(.domain==$d) | .rules[] | select(.path_pattern=="/assets/*")] | length')" "1"

if (( FAILED > 0 )); then
  echo "CONFIG RELEASE CHECKS FAILED: $FAILED"
  exit 1
fi
echo "ALL CONFIG RELEASE CHECKS PASSED"
