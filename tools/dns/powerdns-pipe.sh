#!/usr/bin/env bash
# PowerDNS pipe backend → Lagran scheduler (Geo/ISP Phase 1).
#
# PowerDNS launches this script and speaks the pipe protocol on stdin/stdout.
# Configure:
#   launch=pipe
#   pipe-command=/path/to/tools/dns/powerdns-pipe.sh
#   pipe-abi-version=1
#   pipe-timeout=2000
#
# Environment:
#   CONTROL_URL  control plane base URL (default http://127.0.0.1:8080)
#   AGENT_TOKEN  X-Lagran-Agent-Token used for /api/v1/schedule
set -u

CONTROL_URL="${CONTROL_URL:-http://127.0.0.1:8080}"
CONTROL_URL="${CONTROL_URL%/}"
AGENT_TOKEN="${AGENT_TOKEN:-}"

emit_end() { printf 'END\n'; }

while IFS= read -r line; do
  line="${line%$'\r'}"
  case "$line" in
    HELO*)
      printf 'OK\tLagran GeoDNS pipe backend\n'
      ;;
    PING*)
      emit_end
      ;;
    Q$'\t'*)
      IFS=$'\t' read -r _tag qname qclass qtype qid remote <<<"$line"
      qname="${qname%.}"
      ip=""
      ttl=30
      case "$qtype" in
        A|AAAA)
          json=$(curl -sG "$CONTROL_URL/api/v1/schedule" \
            --data-urlencode "domain=$qname" \
            --data-urlencode "ip=$remote" \
            -H "x-lagran-agent-token: $AGENT_TOKEN" 2>/dev/null)
          ip=$(printf '%s' "$json" | jq -r '.primary.public_ip // empty' 2>/dev/null)
          ttl=$(printf '%s' "$json" | jq -r '.ttl // 30' 2>/dev/null)
          [[ -z "$ttl" || "$ttl" == "null" ]] && ttl=30
          ;;
      esac
      if [[ -n "$ip" ]]; then
        printf 'DATA\t%s\t%s\t%s\t%s\t%s\t%s\n' "$qname" "$qclass" "$qtype" "$ttl" "$qid" "$ip"
      fi
      emit_end
      ;;
    *)
      emit_end
      ;;
  esac
done
