//! Edge node configuration

pub mod registry;

use serde::Deserialize;

fn normalize_control_url(raw: &str) -> String {
    let value = raw.trim().trim_end_matches('/');
    if value.is_empty() {
        "http://127.0.0.1:8080".into()
    } else {
        value.to_string()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct EdgeConfig {
    pub listen_addr: String,
    /// Optional isolated listener for control-plane management endpoints.
    /// When unset, management stays on `listen_addr` for compatibility.
    pub admin_listen_addr: Option<String>,
    pub https_listen_addr: Option<String>,
    pub origin_url: String,
    pub default_ttl_secs: u64,
    pub cache_capacity: u64,
    /// Approximate memory-cache byte cap; 0 means unbounded.
    pub cache_max_bytes: u64,
    /// Redis L2 cache endpoint (falls back to REDIS_URL when empty).
    pub cache_redis_url: String,
    pub cache_redis_prefix: String,
    /// Maximum serialized body written to Redis L2.
    pub cache_l2_max_body: usize,
    /// memory | disk | hybrid
    pub cache_backend: String,
    pub disk_cache_dir: String,
    pub disk_cache_max_bytes: u64,
    pub node_id: String,
    pub region: String,
    /// Public IP reported to the control plane for GeoDNS scheduling.
    pub public_ip: String,
    pub control_url: String,
    pub agent_url: String,
    pub heartbeat_interval_secs: u64,
    /// How often to pull the shared CC ban list from the control plane.
    pub cc_sync_interval_secs: u64,
    /// Optional Redis URL for distributed CC sliding-window counters.
    /// Empty keeps CC fully in-process.
    pub redis_url: String,
    pub domain: String,
    pub access_log_path: Option<String>,
    pub agent_token: String,
    /// HMAC secret for signed WAF rulepacks (empty = AGENT_TOKEN fallback).
    pub waf_rulepack_secret: String,
    pub access_log_json: bool,
    pub access_log_buffer: usize,
    pub access_log_report: bool,
    pub access_log_report_interval_secs: u64,
    /// Directory to persist TLS certs across restarts
    pub cert_dir: String,
    /// Directory to cache verified signed WAF rulepacks.
    pub waf_rulepack_cache_dir: String,
    /// Trust `X-Forwarded-For` for the client IP (only behind a trusted proxy).
    pub trust_proxy_headers: bool,
    /// Ship WAF events to the control plane.
    pub waf_report: bool,
    pub waf_report_interval_secs: u64,
    /// HMAC secret for challenge nonces / clearance cookies (empty = derive).
    pub challenge_secret: String,
    /// Port to use in HTTP→HTTPS redirects (None = 443, or derived from the
    /// HTTPS listener port when it is not 443).
    pub https_redirect_port: Option<u16>,
    /// Max response body size stored in cache (bytes). Larger responses are
    /// still proxied but not written to cache.
    pub max_cacheable_body: usize,
    /// Request header names excluded from the shared-cache key. This is for
    /// headers that do not vary the response body, such as Accept-Language on
    /// a single-language site, so prefetch and browsers share one object.
    pub cache_key_ignore_headers: Vec<String>,
    /// Idle timeout while waiting for origin response bytes. This is separate
    /// from the per-domain connect/header timeout so media streams are not
    /// aborted just because the whole object takes longer than 10s.
    pub origin_read_timeout_ms: u64,
    /// Idle read timeout for Range/media streaming. Longer than the normal
    /// origin read timeout so slow video origins do not become 504s.
    pub origin_stream_read_timeout_ms: u64,
    /// Maximum bytes written into the large cache from one Range response.
    /// Bounded ranges larger than this are proxied without filling; an
    /// open-ended video range fills a bounded prefix, and a suffix range fills
    /// the tail, both up to this limit.
    pub range_fill_max_bytes: u64,
    /// Downstream HTTP/1.1 keepalive idle timeout.
    pub downstream_keepalive_secs: u64,
    /// Downstream HTTP/2 idle timeout after the last active stream.
    pub downstream_h2_idle_secs: u64,
    /// Maximum requests served on one downstream connection.
    pub downstream_keepalive_requests: u32,
    /// Idle timeout for established WebSocket tunnels.
    pub websocket_idle_secs: u64,
    /// Optional streaming disk cache for large objects (Phase 2).
    pub large_cache_enabled: bool,
    pub large_cache_dir: String,
    pub large_cache_min_object_bytes: u64,
    /// Maximum complete object admitted to the large cache. Partial Range
    /// windows are still admitted for larger objects, limited by
    /// `range_fill_max_bytes`, because only the written segments occupy disk.
    pub large_cache_max_object_bytes: u64,
    pub large_cache_max_bytes: u64,
    /// How often the edge pulls domain config from control (seconds).
    pub config_sync_interval_secs: u64,
}

impl Default for EdgeConfig {
    fn default() -> Self {
        let listen = std::env::var("EDGE_LISTEN").unwrap_or_else(|_| "0.0.0.0:8081".into());
        let admin_listen_addr = std::env::var("EDGE_ADMIN_LISTEN")
            .ok()
            .filter(|s| !s.trim().is_empty());
        let agent_url = std::env::var("AGENT_URL").unwrap_or_else(|_| {
            let agent_listen = admin_listen_addr.as_deref().unwrap_or(&listen);
            if let Some(port) = agent_listen.rsplit(':').next() {
                format!("http://127.0.0.1:{port}")
            } else {
                format!("http://{agent_listen}")
            }
        });
        let https_listen_addr = std::env::var("EDGE_HTTPS_LISTEN")
            .ok()
            .filter(|s| !s.is_empty());
        let https_redirect_port = std::env::var("EDGE_HTTPS_REDIRECT_PORT")
            .ok()
            .and_then(|v| v.parse::<u16>().ok())
            .or_else(|| {
                https_listen_addr
                    .as_deref()
                    .and_then(|addr| addr.rsplit(':').next())
                    .and_then(|p| p.parse::<u16>().ok())
                    .filter(|p| *p != 443)
            });

        Self {
            listen_addr: listen,
            admin_listen_addr,
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
            cache_max_bytes: std::env::var("CACHE_MAX_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(512 * 1024 * 1024)
                .clamp(16 * 1024 * 1024, 8 * 1024 * 1024 * 1024),
            cache_redis_url: env_nonempty("CACHE_REDIS_URL").unwrap_or_default(),
            cache_redis_prefix: std::env::var("CACHE_REDIS_PREFIX")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "lagran:cache".to_string()),
            cache_l2_max_body: std::env::var("CACHE_L2_MAX_BODY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8 * 1024 * 1024)
                .clamp(1024 * 1024, 64 * 1024 * 1024),
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
            public_ip: std::env::var("PUBLIC_IP").unwrap_or_default(),
            control_url: normalize_control_url(&std::env::var("CONTROL_URL").unwrap_or_default()),
            agent_url,
            heartbeat_interval_secs: std::env::var("HEARTBEAT_INTERVAL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(15),
            cc_sync_interval_secs: std::env::var("CC_SYNC_INTERVAL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            redis_url: env_nonempty("REDIS_URL").unwrap_or_default(),
            domain: std::env::var("EDGE_DOMAIN").unwrap_or_default(),
            access_log_path: std::env::var("ACCESS_LOG_PATH")
                .ok()
                .filter(|s| !s.is_empty()),
            agent_token: env_nonempty("AGENT_TOKEN")
                .or_else(|| env_nonempty("EDGE_AGENT_TOKEN"))
                .unwrap_or_default(),
            waf_rulepack_secret: env_nonempty("WAF_RULEPACK_SECRET").unwrap_or_default(),
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
            waf_rulepack_cache_dir: std::env::var("WAF_RULEPACK_CACHE_DIR")
                .unwrap_or_else(|_| "./data/waf-rulepacks".into()),
            trust_proxy_headers: bool_env("TRUST_PROXY_HEADERS", false),
            waf_report: bool_env("WAF_REPORT", true),
            waf_report_interval_secs: std::env::var("WAF_REPORT_INTERVAL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            challenge_secret: std::env::var("CHALLENGE_SECRET").unwrap_or_default(),
            https_redirect_port,
            max_cacheable_body: std::env::var("MAX_CACHEABLE_BODY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8 * 1024 * 1024)
                .clamp(64 * 1024, 64 * 1024 * 1024),
            cache_key_ignore_headers: std::env::var("CACHE_KEY_IGNORE_HEADERS")
                .unwrap_or_default()
                .split(',')
                .map(|name| name.trim().to_ascii_lowercase())
                .filter(|name| !name.is_empty())
                .collect(),
            origin_read_timeout_ms: std::env::var("ORIGIN_READ_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30_000)
                .clamp(1_000, 600_000),
            origin_stream_read_timeout_ms: std::env::var("ORIGIN_STREAM_READ_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(120_000)
                .clamp(5_000, 1_800_000),
            range_fill_max_bytes: std::env::var("RANGE_FILL_MAX_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(32 * 1024 * 1024)
                .clamp(0, 1024 * 1024 * 1024),
            downstream_keepalive_secs: std::env::var("DOWNSTREAM_KEEPALIVE_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60)
                .clamp(5, 3600),
            downstream_h2_idle_secs: std::env::var("DOWNSTREAM_H2_IDLE_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(120)
                .clamp(5, 3600),
            downstream_keepalive_requests: std::env::var("DOWNSTREAM_KEEPALIVE_REQUESTS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1_000)
                .clamp(1, 100_000),
            websocket_idle_secs: std::env::var("WEBSOCKET_IDLE_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300)
                .clamp(10, 86_400),
            large_cache_enabled: bool_env("LARGE_CACHE_ENABLED", false),
            large_cache_dir: std::env::var("LARGE_CACHE_DIR")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "./data/large-cache".into()),
            large_cache_min_object_bytes: std::env::var("LARGE_CACHE_MIN_OBJECT_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8 * 1024 * 1024)
                .clamp(1024 * 1024, 1024 * 1024 * 1024),
            large_cache_max_object_bytes: std::env::var("LARGE_CACHE_MAX_OBJECT_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1024 * 1024 * 1024)
                .clamp(1024 * 1024, 4 * 1024 * 1024 * 1024),
            large_cache_max_bytes: std::env::var("LARGE_CACHE_MAX_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(20 * 1024 * 1024 * 1024),
            config_sync_interval_secs: std::env::var("CONFIG_SYNC_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(15)
                .clamp(5, 300),
        }
    }
}

fn bool_env(name: &str, default: bool) -> bool {
    std::env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(default)
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

impl EdgeConfig {
    pub fn load() -> Self {
        let _ = dotenvy::dotenv();
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_url_is_normalized() {
        assert_eq!(
            normalize_control_url("  https://control.example.com/  "),
            "https://control.example.com"
        );
        assert_eq!(normalize_control_url("   "), "http://127.0.0.1:8080");
    }
}
