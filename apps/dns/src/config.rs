//! Authoritative DNS configuration.

use std::time::Duration;

#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub listen: String,
    /// Zone apex, lower-case, without trailing dot.
    pub zone: String,
    pub ttl: u32,
    pub ns_name: String,
    pub ns_ip: String,
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

impl DnsConfig {
    pub fn from_env() -> Self {
        let zone = std::env::var("DNS_ZONE")
            .unwrap_or_else(|_| "edge.lagran.net".into())
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let ns_name = std::env::var("DNS_NS_NAME").unwrap_or_else(|_| format!("ns1.{zone}"));
        let ns_ip = std::env::var("DNS_NS_IP").unwrap_or_else(|_| "127.0.0.1".into());
        let soa_mname = std::env::var("DNS_SOA_MNAME").unwrap_or_else(|_| ns_name.clone());
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
            ns_name,
            ns_ip,
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
