//! Authoritative DNS configuration.

use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub listen: String,
    /// Zone apex, lower-case, without trailing dot.
    pub zone: String,
    pub ttl: u32,
    /// One or more NS names (comma separated), e.g. ns1,ns2.
    pub ns_names: Vec<String>,
    /// One A/AAAA per NS name (comma separated, same order).
    pub ns_ips: Vec<IpAddr>,
    pub soa_mname: String,
    pub soa_rname: String,
    pub control_url: String,
    pub agent_token: String,
    pub cache_secs: u64,
    pub stale_secs: u64,
    pub workers: usize,
    pub tcp_enabled: bool,
    pub fallback_ip: Option<String>,
}

fn split_list(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(|s| s.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

impl DnsConfig {
    pub fn from_env() -> Self {
        let zone = std::env::var("DNS_ZONE")
            .unwrap_or_else(|_| "edge.lagran.net".into())
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();

        let mut ns_names =
            split_list(&std::env::var("DNS_NS_NAME").unwrap_or_else(|_| format!("ns1.{zone}")));
        if ns_names.is_empty() {
            ns_names.push(format!("ns1.{zone}"));
        }

        let mut ns_ips: Vec<IpAddr> = std::env::var("DNS_NS_IP")
            .unwrap_or_else(|_| "127.0.0.1".into())
            .split(',')
            .filter_map(|s| s.trim().parse::<IpAddr>().ok())
            .collect();
        if ns_ips.is_empty() {
            ns_ips.push("127.0.0.1".parse().expect("valid fallback IP"));
        }
        // If fewer IPs than names, repeat the last one instead of dropping NS.
        while ns_ips.len() < ns_names.len() {
            let last = *ns_ips.last().expect("at least one NS IP");
            ns_ips.push(last);
        }

        let soa_mname = std::env::var("DNS_SOA_MNAME").unwrap_or_else(|_| ns_names[0].clone());
        let soa_rname =
            std::env::var("DNS_SOA_RNAME").unwrap_or_else(|_| format!("hostmaster.{zone}"));
        Self {
            listen: std::env::var("DNS_LISTEN").unwrap_or_else(|_| "0.0.0.0:53".into()),
            zone,
            ttl: std::env::var("DNS_TTL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30)
                .clamp(5, 300),
            ns_names,
            ns_ips,
            soa_mname,
            soa_rname,
            control_url: std::env::var("CONTROL_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8080".into()),
            agent_token: std::env::var("AGENT_TOKEN").unwrap_or_default(),
            cache_secs: std::env::var("DNS_CACHE_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            stale_secs: std::env::var("DNS_STALE_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
            workers: std::env::var("DNS_WORKERS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8)
                .clamp(1, 64),
            tcp_enabled: std::env::var("DNS_TCP")
                .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
                .unwrap_or(true),
            fallback_ip: std::env::var("DNS_FALLBACK_IP")
                .ok()
                .filter(|s| !s.trim().is_empty()),
        }
    }

    pub fn http_timeout(&self) -> Duration {
        Duration::from_millis(
            std::env::var("DNS_CONTROL_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(800),
        )
    }
}
