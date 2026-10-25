//! Edge node configuration

pub mod registry;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct EdgeConfig {
    pub listen_addr: String,
    pub https_listen_addr: Option<String>,
    pub origin_url: String,
    pub default_ttl_secs: u64,
    pub cache_capacity: u64,
    /// memory | disk | hybrid
    pub cache_backend: String,
    pub disk_cache_dir: String,
    pub disk_cache_max_bytes: u64,
    pub node_id: String,
    pub region: String,
    pub control_url: String,
    pub agent_url: String,
    pub heartbeat_interval_secs: u64,
    pub domain: String,
    pub tls_cert_file: Option<String>,
    pub tls_key_file: Option<String>,
    pub access_log_path: Option<String>,
    pub agent_token: String,
    pub access_log_json: bool,
    pub access_log_buffer: usize,
    pub access_log_report: bool,
    pub access_log_report_interval_secs: u64,
    /// Directory to persist TLS certs across restarts
    pub cert_dir: String,
    /// Trust `X-Forwarded-For` for the client IP (only behind a trusted proxy).
    pub trust_proxy_headers: bool,
    /// Ship WAF events to the control plane.
    pub waf_report: bool,
    pub waf_report_interval_secs: u64,
}

impl Default for EdgeConfig {
    fn default() -> Self {
        let listen = std::env::var("EDGE_LISTEN").unwrap_or_else(|_| "0.0.0.0:8081".into());
        let agent_url = std::env::var("AGENT_URL").unwrap_or_else(|_| {
            if let Some(port) = listen.rsplit(':').next() {
                format!("http://127.0.0.1:{port}")
            } else {
                format!("http://{listen}")
            }
        });
        let https_listen_addr = std::env::var("EDGE_HTTPS_LISTEN")
            .ok()
            .filter(|s| !s.is_empty());

        Self {
            listen_addr: listen,
            https_listen_addr,
            origin_url: std::env::var("ORIGIN_URL")
                .unwrap_or_else(|_| "https://example.com".into()),
            default_ttl_secs: std::env::var("CACHE_TTL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            cache_capacity: std::env::var("CACHE_CAPACITY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10_000),
            cache_backend: std::env::var("CACHE_BACKEND")
                .unwrap_or_else(|_| "memory".into())
                .to_lowercase(),
            disk_cache_dir: std::env::var("DISK_CACHE_DIR")
                .unwrap_or_else(|_| "./data/cache".into()),
            disk_cache_max_bytes: std::env::var("DISK_CACHE_MAX_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1_073_741_824), // 1 GiB
            node_id: std::env::var("NODE_ID").unwrap_or_else(|_| "edge-001".into()),
            region: std::env::var("NODE_REGION").unwrap_or_else(|_| "local".into()),
            control_url: std::env::var("CONTROL_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8080".into()),
            agent_url,
            heartbeat_interval_secs: std::env::var("HEARTBEAT_INTERVAL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(15),
            domain: std::env::var("EDGE_DOMAIN").unwrap_or_default(),
            tls_cert_file: std::env::var("EDGE_TLS_CERT")
                .ok()
                .filter(|s| !s.is_empty()),
            tls_key_file: std::env::var("EDGE_TLS_KEY").ok().filter(|s| !s.is_empty()),
            access_log_path: std::env::var("ACCESS_LOG_PATH")
                .ok()
                .filter(|s| !s.is_empty()),
            agent_token: std::env::var("AGENT_TOKEN")
                .or_else(|_| std::env::var("EDGE_AGENT_TOKEN"))
                .unwrap_or_default(),
            access_log_json: std::env::var("ACCESS_LOG_JSON")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            access_log_buffer: std::env::var("ACCESS_LOG_BUFFER")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2000),
            access_log_report: std::env::var("ACCESS_LOG_REPORT")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(true),
            access_log_report_interval_secs: std::env::var("ACCESS_LOG_REPORT_INTERVAL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            cert_dir: std::env::var("CERT_DIR").unwrap_or_else(|_| "./data/certs".into()),
            trust_proxy_headers: bool_env("TRUST_PROXY_HEADERS", false),
            waf_report: bool_env("WAF_REPORT", true),
            waf_report_interval_secs: std::env::var("WAF_REPORT_INTERVAL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
        }
    }
}

fn bool_env(name: &str, default: bool) -> bool {
    std::env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(default)
}

impl EdgeConfig {
    pub fn load() -> Self {
        let _ = dotenvy::dotenv();
        Self::default()
    }
}
