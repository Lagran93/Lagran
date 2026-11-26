#!/usr/bin/env bash
# Authoritative DNS (apps/dns) load. Sourced by run_all.sh.
#
# Compiles the std-only generator, starts lagran-dns pointed at the running
# control plane and measures steady-state resolution QPS. Rate limiting is
# disabled for the throughput figures (it is a fixed per-source cap that would
# otherwise dominate); a real deployment keeps it on.

start_dns() {
  local bin="$ROOT/target/debug/lagran-dns"
  [ -x "$bin" ] || { log "lagran-dns binary missing, skipping DNS"; DNS_OK=0; return; }
  DNS_OK=1
  DNS_LISTEN="127.0.0.1:$DNS_PORT" \
  DNS_ZONE="lagran.test" \
  DNS_NS_NAME="ns1.lagran.test" \
  DNS_NS_IP="203.0.113.53" \
  DNS_SOA_MNAME="ns1.lagran.test" \
  DNS_SOA_RNAME="hostmaster.lagran.test" \
  CONTROL_URL="http://127.0.0.1:$CONTROL_PORT" \
  AGENT_TOKEN="$GLOBAL_AGENT_TOKEN" \
  DNS_FALLBACK_IP="203.0.113.53" \
  DNS_RATE_LIMIT_PER_SOURCE="0" \
  DNS_RATE_LIMIT_PER_PREFIX="0" \
  DNS_CACHE_SECS="30" \
  DNS_WORKERS="4" \
  RUST_LOG="lagran_dns=warn" \
    "$bin" > "$WORK/raw/dns.log" 2>&1 &
  PIDS+=($!)
  sleep 1.5
}

run_dns_cases() {
  : > "$WORK/dns-results.tsv"
  printf 'threads\tduration_s\tqps\tavg_us\tp50_us\tp90_us\tp99_us\tok\ttimeouts\n' > "$WORK/dns-results.tsv"
  [ "${DNS_OK:-0}" = "1" ] || { log "DNS skipped"; return; }

  local loader="$WORK/dns_load"
  if [ ! -x "$loader" ] || [ "$ROOT/tools/load-test/dns_load.rs" -nt "$loader" ]; then
    log "building dns_load"
    rustc -O "$ROOT/tools/load-test/dns_load.rs" -o "$loader" || { log "dns_load build failed"; return; }
  fi

  local line t
  for t in 1 4 8; do
    log "dns: www.lagran.test threads=$t 10s"
    line=$("$loader" 127.0.0.1 "$DNS_PORT" www.lagran.test 10 "$t" 2>&1)
    printf '%s\n' "$line" > "$WORK/raw/dns-t$t.txt"
    local qps avg p50 p90 p99 ok to thr
    qps=$(awk '{for(i=1;i<=NF;i++) if($i~/^qps=/){sub("qps=","",$i);print $i}}' <<<"$line")
    avg=$(awk '{for(i=1;i<=NF;i++) if($i~/^avg_us=/){sub("avg_us=","",$i);print $i}}' <<<"$line")
    p50=$(awk '{for(i=1;i<=NF;i++) if($i~/^p50_us=/){sub("p50_us=","",$i);print $i}}' <<<"$line")
    p90=$(awk '{for(i=1;i<=NF;i++) if($i~/^p90_us=/){sub("p90_us=","",$i);print $i}}' <<<"$line")
    p99=$(awk '{for(i=1;i<=NF;i++) if($i~/^p99_us=/){sub("p99_us=","",$i);print $i}}' <<<"$line")
    ok=$(awk '{for(i=1;i<=NF;i++) if($i~/^ok=/){sub("ok=","",$i);print $i}}' <<<"$line")
    to=$(awk '{for(i=1;i<=NF;i++) if($i~/^timeouts=/){sub("timeouts=","",$i);print $i}}' <<<"$line")
    thr=$(awk '{for(i=1;i<=NF;i++) if($i~/^threads=/){sub("threads=","",$i);print $i}}' <<<"$line")
    printf '%s\t10\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "${thr:-$t}" "${qps:-0}" "${avg:-0}" "${p50:-0}" "${p90:-0}" "${p99:-0}" "${ok:-0}" "${to:-0}" \
      >> "$WORK/dns-results.tsv"
    printf '  dns threads=%-2s qps=%-10s p99=%sus ok=%s to=%s\n' "${thr:-$t}" "${qps:-?}" "${p99:-?}" "${ok:-?}" "${to:-?}"
  done
}
