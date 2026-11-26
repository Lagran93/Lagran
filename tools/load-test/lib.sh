#!/usr/bin/env bash
# Shared helpers for the Lagran CDN load-test harness.
#
# Sourced by run_all.sh. Keeps process bookkeeping, CPU/RSS sampling and the
# wrk wrapping logic in one place so each case file stays small.
#
# Conventions:
#   $WORK        absolute output directory (raw wrk/hey logs + tsv rows)
#   $EDGE_PORT   edge data-plane listen port
#   $DOMAIN      host header the edge routes to the mock origin
#   PIDS[]       background PIDs to kill on teardown
#
# All results are appended to TSV files inside $WORK so they can be turned into
# the markdown report without re-running anything.

set -uo pipefail

# seconds a single wrk run lasts unless a case overrides it
: "${DUR:=15}"

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }

# Discover the edge PID we started (there may be other lagran-edge processes on
# the box from earlier runs; we always remember the PID we launched).
edge_pid() { printf '%s' "${EDGE_PID:-}"; }

cpu_ticks() { awk '{print $14+$15}' "/proc/$1/stat" 2>/dev/null || echo 0; }
rss_kb() { awk '/VmRSS/{print $2}' "/proc/$1/status" 2>/dev/null || echo 0; }
hwm_kb() { awk '/VmHWM/{print $2}' "/proc/$1/status" 2>/dev/null || echo 0; }

# run_wrk LABEL PATH CONNS THREADS DUR [extra wrk args...]
#
# Runs wrk against the edge, sampling the edge process CPU ticks and RSS before
# and after, then appends one TSV row:
#   label rps p50 p90 p99 transfer errors cpu_pct rss_mb rss_peak_mb conns threads
# The full wrk output is stored at $WORK/raw/wrk-<label>.txt for the appendix.
run_wrk() {
  local label="$1" path="$2" conns="$3" threads="$4" dur="$5"; shift 5
  local pid; pid="$(edge_pid)"
  local hz; hz=$(getconf CLK_TCK)
  local t0 t1 r0 r1 hwm out rps p50 p90 p99 xfer errs cpu rss rss_pk rawname
  rawname="$(printf '%s' "$label" | tr '/ ' '__')"

  # Warm the object so a HIT case measures steady-state, not the first fill.
  curl -s -o /dev/null -m 10 -H "Host: $DOMAIN" "http://127.0.0.1:$EDGE_PORT$path" || true

  t0=$(cpu_ticks "$pid"); r0=$(rss_kb "$pid")
  out=$(wrk -t"$threads" -c"$conns" -d"${dur}s" --latency -H "Host: $DOMAIN" "$@" \
        "http://127.0.0.1:$EDGE_PORT$path" 2>&1)
  t1=$(cpu_ticks "$pid"); r1=$(rss_kb "$pid"); hwm=$(hwm_kb "$pid")

  printf '%s\n' "$out" > "$WORK/raw/wrk-${rawname}.txt"

  rps=$(awk '/Requests\/sec:/{print $2}' <<<"$out")
  p50=$(awk '$1=="50%"{print $2}' <<<"$out")
  p90=$(awk '$1=="90%"{print $2}' <<<"$out")
  p99=$(awk '$1=="99%"{print $2}' <<<"$out")
  xfer=$(awk '/Transfer\/sec:/{print $2}' <<<"$out")
  errs=$(sed -n 's/.*Socket errors: connect \([0-9]*\), read \([0-9]*\), write \([0-9]*\), timeout \([0-9]*\).*/\1+\2+\3+\4/p' <<<"$out")
  [ -z "$errs" ] && errs=0
  errs=$(awk -F+ '{s=0; for(i=1;i<=NF;i++) s+=$i; print s}' <<<"$errs")
  cpu=$(awk -v a="$t0" -v b="$t1" -v hz="$hz" -v d="$dur" 'BEGIN{printf "%.1f", (b-a)*100.0/hz/d}')
  rss=$(( ${r1:-0} / 1024 ))
  rss_pk=$(( ${hwm:-0} / 1024 ))

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$label" "${rps:-0}" "${p50:-?}" "${p90:-?}" "${p99:-?}" "${xfer:-?}" \
    "${errs:-0}" "$cpu" "$rss" "$rss_pk" "$conns" "$threads" \
    >> "$WORK/edge-results.tsv"

  printf '  %-22s rps=%-10s p50=%-8s p99=%-8s xfer=%-8s err=%-4s cpu=%s%% rss=%sMB(peak %sMB) c=%s\n' \
    "$label" "${rps:-?}" "${p50:-?}" "${p99:-?}" "${xfer:-?}" "${errs:-0}" "$cpu" "$rss" "$rss_pk" "$conns"
}

# _hey_pct OUT PCT — extract the "<PCT>% in X secs" latency (hey doubles the %
# sign on some builds, so strip them and compare the numeric first field).
_hey_pct() {
  awk -v p="$1" '{ gsub(/%/,""); if ($1==p) { for (i=2;i<=NF;i++) if ($i ~ /^[0-9]+(\.[0-9]+)?$/) { print $i; exit } } }' <<<"$2"
}

# run_hey LABEL URL DUR CONNS [extra hey args...]
#
# Runs `hey`. Appends: label rps avg_s p50 p90 p99 status_dist to hey-results.tsv.
# `-host <domain>` (a real hey flag) is passed via "$@" where the Host header
# must be overridden. Records the full status-code distribution so 4xx/5xx are
# visible rather than silently folded into a single "ok" count.
run_hey() {
  local label="$1" url="$2" dur="$3" conns="$4"; shift 4
  local out rawname
  rawname="$(printf '%s' "$label" | tr '/ ' '__')"
  out=$(hey -z "${dur}s" -c "$conns" "$@" "$url" 2>&1)
  printf '%s\n' "$out" > "$WORK/raw/hey-${rawname}.txt"
  local rps avg p50 p90 p99 status
  rps=$(awk '/Requests\/sec:/{print $2}' <<<"$out")
  avg=$(awk '/Average:/{print $2}' <<<"$out")
  p50=$(_hey_pct 50 "$out")
  p90=$(_hey_pct 90 "$out")
  p99=$(_hey_pct 99 "$out")
  status=$(awk '/Status code distribution:/{f=1;next} f&&/\[/{gsub(/[\[\]]/,""); if($0~/responses/){print $1":"$2}}' <<<"$out" | paste -sd, -)
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$label" "${rps:-0}" "${avg:-?}" "${p50:-?}" "${p90:-?}" "${p99:-?}" "${status:-?}" \
    >> "$WORK/hey-results.tsv"
  printf '  %-22s rps=%-12s avg=%-9s p50=%-9s p90=%-9s p99=%-9s %s\n' \
    "$label" "${rps:-?}" "${avg:-?}" "${p50:-?}" "${p90:-?}" "${p99:-?}" "${status:-?}"
}

# wait_http URL [attempts] — poll until the URL returns any HTTP response.
wait_http() {
  local url="$1" n="${2:-80}" i
  for ((i=0;i<n;i++)); do
    curl -sf -o /dev/null -m 2 "$url" && return 0
    sleep 0.5
  done
  return 1
}
