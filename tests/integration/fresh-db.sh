#!/usr/bin/env bash
# Fresh-database check: run all migrations against a throwaway database, then
# verify the demo admin bootstrap and seeded defaults.
#
#   bash tests/integration/fresh-db.sh
#
# The database is created/dropped inside the Postgres docker container
# (override with PG_CONTAINER / PG_ADMIN / PGUSER / PGPASS / PG_HOST).
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

PORT="${PORT:-18090}"
DBNAME="lagran_fresh_$$"
PG_CONTAINER="${PG_CONTAINER:-postgresql}"
PG_ADMIN="${PG_ADMIN:-postgres}"
PGUSER="${PGUSER:-lagran}"
PGPASS="${PGPASS:-lagran}"

if ! command -v docker >/dev/null || ! docker ps --format '{{.Names}}' | grep -qx "$PG_CONTAINER"; then
  echo "skip: postgres container '$PG_CONTAINER' not found (set PG_CONTAINER)"
  exit 0
fi

PSQL="docker exec $PG_CONTAINER psql -U $PG_ADMIN -d postgres -v ON_ERROR_STOP=1"
$PSQL -c "CREATE DATABASE $DBNAME OWNER $PGUSER" >/dev/null || { echo "createdb failed"; exit 1; }

PID=""
cleanup() {
  [[ -n "$PID" ]] && kill "$PID" 2>/dev/null
  docker exec "$PG_CONTAINER" psql -U "$PG_ADMIN" -d postgres \
    -c "DROP DATABASE IF EXISTS $DBNAME" >/dev/null 2>&1
}
trap cleanup EXIT

DATABASE_URL="postgres://$PGUSER:$PGPASS@127.0.0.1:5432/$DBNAME" \
CONTROL_BIND="127.0.0.1:$PORT" \
CAPTCHA_ENABLED=false ./target/debug/lagran-control >/tmp/lagran-fresh.log 2>&1 &
PID=$!

for _ in $(seq 1 60); do
  curl -sf "http://127.0.0.1:$PORT/health" >/dev/null && break
  sleep 0.5
done
if ! curl -sf "http://127.0.0.1:$PORT/health" >/dev/null; then
  echo "FAIL control did not start on a fresh database"
  tail -20 /tmp/lagran-fresh.log
  exit 1
fi

LOGIN=$(curl -s -X POST "http://127.0.0.1:$PORT/api/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}')
TOKEN=$(printf '%s' "$LOGIN" | jq -r '.token // empty')
ROLE=$(curl -s -H "authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/api/v1/auth/me" | jq -r '.role')
NODES=$(curl -s -o /dev/null -w '%{http_code}' -H "authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/api/v1/nodes")
DOMAINS=$(curl -s -H "authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/api/v1/domains" | jq 'length')
RULE_ACTION=$(curl -s -H "authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/api/v1/rules" | jq -r '.[0].action')

echo "role=$ROLE nodes=$NODES domains=$DOMAINS seeded_rule_action=$RULE_ACTION"
if [[ "$ROLE" == "admin" && "$NODES" == "200" && "$DOMAINS" == "1" && "$RULE_ACTION" == "cache" ]]; then
  echo "FRESH DB OK"
else
  echo "FRESH DB FAILED"
  grep -a ERROR /tmp/lagran-fresh.log | tail -5
  exit 1
fi
