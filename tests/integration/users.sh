#!/usr/bin/env bash
# Multi-user registration, admin user management, active-state and profile tests.
#
#   bash tests/integration/users.sh
set -uo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

CONTROL_PORT="${CONTROL_PORT:-18420}"
LOG_DIR="${LOG_DIR:-/tmp/lagran-users}"
mkdir -p "$LOG_DIR"

PIDS=()
FAILED=0
TS="$$"
USER_EMAIL="member-$TS@example.test"
ADMIN_EMAIL="admin-$TS@example.test"
PASSWORD="UserPass123"
NEW_PASSWORD="UserPass456"

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }
check() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }

cleanup() { for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done; wait 2>/dev/null; }
trap cleanup EXIT

api() { curl -s -H "authorization: Bearer $1" -H 'content-type: application/json' "${@:2}"; }
login() {
  curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
    -H 'content-type: application/json' \
    -d "{\"email\":\"$1\",\"password\":\"$2\"}"
}

echo "== start control =="
ALLOW_REGISTER=true CONTROL_BIND="127.0.0.1:$CONTROL_PORT" AGENT_TOKEN=test-global \
  CAPTCHA_ENABLED=false ./target/debug/lagran-control >"$LOG_DIR/control.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 80); do
  curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null && break
  sleep 0.5
done
curl -sf "http://127.0.0.1:$CONTROL_PORT/health" >/dev/null || {
  echo "control did not start"; tail -20 "$LOG_DIR/control.log"; exit 1
}

echo "== public registration config =="
CFG=$(curl -s "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/config")
check "registration is advertised" "$(printf '%s' "$CFG" | jq -r '.allow_register')" "true"

echo "== self registration =="
REG=$(curl -s -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/register" \
  -H 'content-type: application/json' \
  -d "{\"email\":\"$USER_EMAIL\",\"password\":\"$PASSWORD\",\"name\":\"Member $TS\"}")
USER_TOKEN=$(printf '%s' "$REG" | jq -r '.token // empty')
check "register returns token" "$(printf '%s' "$REG" | jq -r '.user.role')" "user"
[[ -n "$USER_TOKEN" ]] || { echo "registration failed: $REG"; exit 1; }
check "registered user sees own profile" "$(api "$USER_TOKEN" "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/me" | jq -r '.email')" "$USER_EMAIL"
PROFILE=$(api "$USER_TOKEN" -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/me" \
  -H 'content-type: application/json' -d '{"name":"Renamed Member"}')
check "user updates own profile" "$(printf '%s' "$PROFILE" | jq -r '.name')" "Renamed Member"
PROJECTS=$(api "$USER_TOKEN" "http://127.0.0.1:$CONTROL_PORT/api/v1/projects")
check "registration creates personal project" "$(printf '%s' "$PROJECTS" | jq length)" "1"
NONADMIN_CODE=$(api "$USER_TOKEN" -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CONTROL_PORT/api/v1/users")
check "normal user cannot list users" "$NONADMIN_CODE" "403"

echo "== admin user management =="
ADMIN_TOKEN=$(login demo@lagran.dev demo123 | jq -r '.token // empty')
[[ -n "$ADMIN_TOKEN" ]] || { echo "admin login failed"; exit 1; }
check "admin lists users" "$(api "$ADMIN_TOKEN" "http://127.0.0.1:$CONTROL_PORT/api/v1/users" | jq --arg e "$USER_EMAIL" '[.[] | select(.email == $e)] | length')" "1"

CREATED=$(api "$ADMIN_TOKEN" -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/users" \
  -H 'content-type: application/json' \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$PASSWORD\",\"name\":\"Admin $TS\",\"role\":\"admin\"}")
ADMIN_ID=$(printf '%s' "$CREATED" | jq -r '.id // empty')
check "admin creates admin user" "$(printf '%s' "$CREATED" | jq -r '.role')" "admin"
[[ -n "$ADMIN_ID" ]] || { echo "create admin failed: $CREATED"; exit 1; }

SELF_DISABLE=$(api "$ADMIN_TOKEN" -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/users/$(api "$ADMIN_TOKEN" "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/me" | jq -r '.id')" \
  -H 'content-type: application/json' -d '{"is_active":false}' -o /dev/null -w '%{http_code}')
check "admin cannot disable self" "$SELF_DISABLE" "400"

echo "== disable / re-enable / password =="
USER_ID=$(api "$ADMIN_TOKEN" "http://127.0.0.1:$CONTROL_PORT/api/v1/users" | jq -r --arg e "$USER_EMAIL" '.[] | select(.email == $e) | .id')
UPDATED=$(api "$ADMIN_TOKEN" -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/users/$USER_ID" \
  -H 'content-type: application/json' -d '{"is_active":false}')
check "admin disables user" "$(printf '%s' "$UPDATED" | jq -r '.is_active')" "false"
DISABLED_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' -d "{\"email\":\"$USER_EMAIL\",\"password\":\"$PASSWORD\"}")
check "disabled user cannot login" "$DISABLED_CODE" "403"
DISABLED_ME=$(api "$USER_TOKEN" -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/me")
check "disabled token cannot use profile" "$DISABLED_ME" "403"

api "$ADMIN_TOKEN" -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/users/$USER_ID" \
  -H 'content-type: application/json' -d '{"is_active":true}' >/dev/null
USER_TOKEN=$(login "$USER_EMAIL" "$PASSWORD" | jq -r '.token // empty')
[[ -n "$USER_TOKEN" ]] || { echo "re-enabled login failed"; exit 1; }
CHANGE_RESP=$(api "$USER_TOKEN" -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/me/password" \
  -H 'content-type: application/json' \
  -d "{\"current_password\":\"$PASSWORD\",\"new_password\":\"$NEW_PASSWORD\"}")
check "user changes own password" "$(printf '%s' "$CHANGE_RESP" | jq -r '.success')" "true"
NEW_USER_TOKEN=$(printf '%s' "$CHANGE_RESP" | jq -r '.token // empty')
[[ -n "$NEW_USER_TOKEN" ]] || { echo "password change did not return a token"; exit 1; }
check "old JWT is revoked immediately" \
  "$(api "$USER_TOKEN" -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/me")" "401"
check "new JWT works after password change" \
  "$(api "$NEW_USER_TOKEN" -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/me")" "200"
OLD_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' -d "{\"email\":\"$USER_EMAIL\",\"password\":\"$PASSWORD\"}")
NEW_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
  -H 'content-type: application/json' -d "{\"email\":\"$USER_EMAIL\",\"password\":\"$NEW_PASSWORD\"}")
check "old password rejected" "$OLD_CODE" "401"
check "new password accepted" "$NEW_CODE" "200"

ADMIN2_TOKEN=$(login "$ADMIN_EMAIL" "$PASSWORD" | jq -r '.token // empty')
check "new admin can login" "$(api "$ADMIN2_TOKEN" -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CONTROL_PORT/api/v1/users")" "200"
ADMIN2_ID=$(api "$ADMIN2_TOKEN" "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/me" | jq -r '.id')
check "new admin cannot demote self" \
  "$(api "$ADMIN2_TOKEN" -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/users/$ADMIN2_ID" \
      -H 'content-type: application/json' -d '{"role":"user"}' -o /dev/null -w '%{http_code}')" "400"

echo "== project member roles =="
PROJECT_ID=$(api "$ADMIN_TOKEN" -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/projects" \
  -H 'content-type: application/json' -d "{\"name\":\"users-proj-$TS\"}" | jq -r '.id')
MEMBER=$(api "$ADMIN_TOKEN" -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/projects/$PROJECT_ID/members" \
  -H 'content-type: application/json' -d "{\"email\":\"$USER_EMAIL\",\"role\":\"member\"}")
check "admin adds project member" "$(printf '%s' "$MEMBER" | jq -r '.role')" "member"
UPDATED_ROLE=$(api "$ADMIN_TOKEN" -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/projects/$PROJECT_ID/members/$USER_ID" \
  -H 'content-type: application/json' -d '{"role":"admin"}')
check "admin promotes project member" "$(printf '%s' "$UPDATED_ROLE" | jq -r '.role')" "admin"
api "$ADMIN_TOKEN" -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/projects/$PROJECT_ID" >/dev/null

echo "== admin password reset revokes token =="
RESET=$(api "$ADMIN_TOKEN" -X PUT "http://127.0.0.1:$CONTROL_PORT/api/v1/users/$USER_ID/password" \
  -H 'content-type: application/json' -d "{\"password\":\"$PASSWORD\"}")
check "admin resets user password" "$(printf '%s' "$RESET" | jq -r '.success')" "true"
check "admin reset revokes old JWT" \
  "$(api "$NEW_USER_TOKEN" -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/me")" "401"
check "reset password can login" \
  "$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$CONTROL_PORT/api/v1/auth/login" \
      -H 'content-type: application/json' -d "{\"email\":\"$USER_EMAIL\",\"password\":\"$PASSWORD\"}")" "200"

echo "== delete =="
DELETED=$(api "$ADMIN_TOKEN" -X DELETE "http://127.0.0.1:$CONTROL_PORT/api/v1/users/$USER_ID" | jq -r '.success')
check "admin deletes user" "$DELETED" "true"
check "deleted user is gone" "$(api "$ADMIN_TOKEN" "http://127.0.0.1:$CONTROL_PORT/api/v1/users" | jq --arg e "$USER_EMAIL" '[.[] | select(.email == $e)] | length')" "0"

if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL USER CHECKS PASSED"
else
  echo "$FAILED USER CHECK(S) FAILED (logs: $LOG_DIR)"
  exit 1
fi
