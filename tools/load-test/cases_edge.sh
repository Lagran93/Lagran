#!/usr/bin/env bash
# Edge data-plane load cases. Sourced by run_all.sh.
#
# Matrix is intentionally CDN-shaped: a hot small object at several concurrency
# levels, a large object (bandwidth bound), a Range slice, a pure origin
# pass-through (cache miss every request), non-keepalive churn, a keep-alive
# soak, then WAF allowed/blocked once WAF is enabled on the domain.

run_edge_cases() {
  : > "$WORK/edge-results.tsv"
  printf 'label\trps\tp50\tp90\tp99\txfer\terrors\tcpu_pct\trss_mb\trss_peak_mb\tconns\tthreads\n' \
    > "$WORK/edge-results.tsv"

  log "edge: small-object cache HIT ramp (/cached)"
  local c
  for c in 16 64 128 256 512; do
    local t=4; [ "$c" -ge 256 ] && t=8
    run_wrk "hit-small-c$c" "/cached" "$c" "$t" "$DUR"
  done

  log "edge: 2 MiB object cache HIT (bandwidth)"
  for c in 16 64 128; do
    local t=4; [ "$c" -ge 64 ] && t=8
    run_wrk "hit-2m-c$c" "/large" "$c" "$t" "$DUR"
  done

  log "edge: 1 KiB Range on the 2 MiB object"
  run_wrk "range-1k-c64" "/large" 64 4 "$DUR" -H "Range: bytes=0-1023"

  log "edge: origin pass-through (no-store, every request to origin)"
  for c in 64 128; do
    run_wrk "origin-pass-c$c" "/nostore" "$c" 4 "$DUR"
  done

  log "edge: Connection: close churn"
  run_wrk "keepalive-close-c64" "/cached" 64 4 "$DUR" -H "Connection: close"

  log "edge: dynamic POST forwarding (/echo)"
  run_hey "dynamic-post-c32" "http://127.0.0.1:$EDGE_PORT/echo" "$DUR" 32 \
    -host "$DOMAIN" -m POST -H "content-type: text/plain" -d 'ping'

  log "edge: steady-state soak /cached c=128 for 60s"
  run_wrk "soak-60s-c128" "/cached" 128 8 60
}

# CPU profile of the edge under load using perf. `perf_event_paranoid=2` allows
# user-space sampling of our own process. Non-fatal if perf is unavailable.
run_edge_perf() {
  local pid; pid="$(edge_pid)"
  [ -z "$pid" ] && { log "perf: no edge pid, skipping"; return; }
  command -v perf >/dev/null 2>&1 || { log "perf: not installed, skipping"; return; }

  log "perf stat: 10s small-object HIT"
  ( wrk -t8 -c128 -d10s --latency -H "Host: $DOMAIN" \
      "http://127.0.0.1:$EDGE_PORT/cached" >/dev/null 2>&1 ) &
  local wpid=$!
  perf stat -p "$pid" -e task-clock,cycles,instructions,branches,branch-misses,cache-references,cache-misses \
    -- sleep 10 > "$WORK/raw/perf-stat.txt" 2>&1 || true
  wait "$wpid" 2>/dev/null || true

  log "perf record: ~10s sampling for top symbols"
  ( wrk -t8 -c128 -d10s -H "Host: $DOMAIN" \
      "http://127.0.0.1:$EDGE_PORT/cached" >/dev/null 2>&1 ) &
  wpid=$!
  perf record -q -g -F 999 -p "$pid" -o "$WORK/raw/edge.perf.data" -- sleep 10 >/dev/null 2>&1 || true
  wait "$wpid" 2>/dev/null || true
  if [ -f "$WORK/raw/edge.perf.data" ]; then
    perf report -i "$WORK/raw/edge.perf.data" --stdio --no-children --sort dso,symbol 2>/dev/null \
      | sed -n '1,40p' > "$WORK/raw/perf-report.txt" || true
  fi
}

# WAF allowed vs blocked. Assumes WAF is enabled on $DOMAIN by the driver.
run_edge_waf() {
  log "edge: WAF allowed (/cached) vs blocked (/blockme custom deny rule)"
  run_wrk "waf-allow-c64" "/cached" 64 4 "$DUR"
  run_wrk "waf-block-c64" "/blockme" 64 4 "$DUR"
}
