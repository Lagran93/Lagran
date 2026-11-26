#!/usr/bin/env bash
# Database / cache infrastructure load. Sourced by run_all.sh / run_part2.sh.
#
# pgbench isolates PostgreSQL itself; redis-benchmark characterises the Redis
# instance. The dev host installs only the PostgreSQL *client* metapackage and
# its /usr/bin/pgbench wrapper errors with "install at least one
# postgresql-client-<version> package", so we use the pgbench binary extracted
# from the postgresql-17 package in /tmp/pgsrv (it speaks the v3 wire protocol
# and works against the 18.6 server).

PGBENCH_BIN="${PGBENCH_BIN:-/tmp/pgsrv/usr/lib/postgresql/17/bin/pgbench}"
export LD_LIBRARY_PATH="/tmp/pgsrv/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"

pg_env() {
  export PGPASSWORD="${PGPASSWORD:-123456}"
  export PGHOST="${PGHOST:-127.0.0.1}"
  export PGPORT="${PGPORT:-5432}"
  export PGUSER="${PGUSER:-lagran}"
}

_pg_tps() { awk -F'= ' '/tps =/{print $2}' <<<"$1" | awk '{print $1}'; }
_pg_lat() { awk -F'= ' '/latency average/{print $2}' <<<"$1" | awk '{print $1}'; }

run_pgbench() {
  : > "$WORK/pgbench-results.tsv"
  printf 'label\ttps\tlatency_avg_ms\tscale\tclients\n' > "$WORK/pgbench-results.tsv"
  pg_env
  [ -x "$PGBENCH_BIN" ] || { log "pgbench binary $PGBENCH_BIN missing, skipping"; return; }

  # The dev role can create schemas but not databases, so isolate the bench
  # tables in their own schema inside the existing `lagran` database instead of
  # polluting the public application tables.
  local db=lagran
  psql -d "$db" -tAc 'CREATE SCHEMA IF NOT EXISTS pgbench' >/dev/null 2>&1 || { log "cannot create pgbench schema, skipping"; return; }
  export PGOPTIONS="-c search_path=pgbench"

  log "pgbench: initialise scale 10 (~1M rows) into schema pgbench"
  "$PGBENCH_BIN" -i -q -s 10 "$db" > "$WORK/raw/pgbench-init.txt" 2>&1 || true

  _pg_run() {
    local label="$1" clients="$2"; shift 2
    local out; out=$("$PGBENCH_BIN" "$@" -M prepared "$db" 2>&1)
    printf '%s\n' "$out" > "$WORK/raw/pgbench-${label}.txt"
    local tps lat
    tps=$(_pg_tps "$out"); lat=$(_pg_lat "$out")
    printf '%s\t%s\t%s\t%s\t%s\n' "$label" "${tps:-?}" "${lat:-?}" "10" "$clients" >> "$WORK/pgbench-results.tsv"
    printf '  %-18s tps=%-12s lat_avg=%s ms\n' "$label" "${tps:-?}" "${lat:-?}"
  }

  log "pgbench: read-only SELECT, 16 clients"
  _pg_run "select-c16" 16 -S -c 16 -j 4 -T 20

  log "pgbench: read-only SELECT, 64 clients"
  _pg_run "select-c64" 64 -S -c 64 -j 8 -T 15

  log "pgbench: read/write tpcb-like, 32 clients"
  _pg_run "tpcb-c32" 32 -c 32 -j 8 -T 20

  unset PGOPTIONS
}

run_redis_bench() {
  : > "$WORK/redis-results.tsv"
  printf 'label\tcmd\trps\tp50_ms\n' > "$WORK/redis-results.tsv"
  command -v redis-benchmark >/dev/null 2>&1 || { log "redis-benchmark missing, skipping"; return; }

  local out label conns
  for conns in 50 200; do
    label="redis-c$conns"
    log "redis-benchmark: $conns clients, PING/SET/GET 300k"
    out=$(redis-benchmark -h 127.0.0.1 -p 6379 -c "$conns" -n 300000 -t ping,set,get -q 2>&1)
    printf '%s\n' "$out" > "$WORK/raw/${label}.txt"
    # -q emits in-place progress separated by CR; the per-command summary line is
    # "<CMD>: <rps> requests per second, p50=<ms> msec". Normalise CR to LF first.
    while IFS= read -r line; do
      local cmd rps p50
      cmd=$(awk -F': ' '{print $1}' <<<"$line" | sed 's/[[:space:]]*$//')
      rps=$(awk '{for(i=1;i<=NF;i++) if($i=="requests"){print $(i-1)}}' <<<"$line")
      p50=$(sed -n 's/.*p50=\([0-9.]*\) msec.*/\1/p' <<<"$line")
      [ -n "$cmd" ] && [ -n "$rps" ] && \
        printf '%s\t%s\t%s\t%s\n' "$label" "$cmd" "$rps" "${p50:-?}" >> "$WORK/redis-results.tsv"
    done < <(tr '\r' '\n' < "$WORK/raw/${label}.txt" | grep -E ' requests per second, p50=')
  done
}

