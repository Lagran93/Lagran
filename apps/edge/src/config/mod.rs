//! Edge node configuration

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct EdgeConfig {
    pub listen_addr: String,
    /// Optional HTTPS listen address, e.g. 0.0.0.0:8443
    pub https_listen_addr: Option<String>,
    pub origin_url: String,
    pub default_ttl_secs: u64,
    pub cache_capacity: u64,
    pub node_id: String,
    pub region: String,
    pub control_url: String,
    pub agent_url: String,
    pub heartbeat_interval_secs: u64,
    pub domain: String,
    /// Local PEM paths (optional, override control cert)
    pub tls_cert_file: Option<String>,
    pub tls_key_file: Option<String>,
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

        let https_listen_addr = std::env::var("EDGE_HTTPS_LISTEN").ok().filter(|s| !s.is_empty());

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
            tls_cert_file: std::env::var("EDGE_TLS_CERT").ok().filter(|s| !s.is_empty()),
            tls_key_file: std::env::var("EDGE_TLS_KEY").ok().filter(|s| !s.is_empty()),
        }
    }
}

impl EdgeConfig {
    pub fn load() -> Self {
        let _ = dotenvy::dotenv();
        Self::default()
    }
}
