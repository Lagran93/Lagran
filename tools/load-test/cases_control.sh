#!/usr/bin/env bash
# Control-plane API load cases. Sourced by run_all.sh.
#
# These hit the Axum/sqlx control plane directly to exercise JWT verification,
# the per-request Actor reload from PostgreSQL, JSON serialization and the
# Prometheus aggregation endpoint. Each is measured with hey.

run_control_cases() {
  local base="http://127.0.0.1:$CONTROL_PORT"

  log "control: /health (no auth, no DB)"
  run_hey "health-c64" "$base/health" 15 64

  log "control: /ready (DB ping)"
  run_hey "ready-c64" "$base/ready" 15 64

  log "control: GET /api/v1/domains (JWT + DB, tenant filter)"
  run_hey "domains-c64" "$base/api/v1/domains" 15 64 -H "Authorization: Bearer $TOKEN"

  log "control: GET /api/v1/nodes (admin, ~large result set)"
  run_hey "nodes-c32" "$base/api/v1/nodes" 12 32 -H "Authorization: Bearer $TOKEN"

  log "control: GET /api/v1/stats/by-domain (aggregation)"
  run_hey "stats-c32" "$base/api/v1/stats/by-domain" 12 32 -H "Authorization: Bearer $TOKEN"

  log "control: GET /metrics (Prometheus, requires AGENT_TOKEN)"
  run_hey "metrics-c16" "$base/metrics" 12 16 -H "X-Lagran-Agent-Token: $GLOBAL_AGENT_TOKEN"
}
