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
    /// Worker threads for the Pingora data plane.
    ///
    /// Pingora's own default is a single thread, which serialises downstream
    /// TLS, WAF scanning and upstream TLS handshakes. Every origin fetch then
    /// queues behind the handshake of the previous one.
    pub worker_threads: usize,
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
    /// When false, requests skip the access-log path entirely.
    ///
    /// Exists to separate "we are not writing logs" from "the log writer is
    /// slow": both used to look identical from the outside, and only the second is
    /// a problem worth fixing. Defaults to true.
    pub access_log_enabled: bool,
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
    /// MaxMind GeoLite2-Country database used by the WAF country rules.
    pub geoip_country_db: String,
    /// MaxMind GeoLite2-ASN database used by the WAF ASN rules.
    pub geoip_asn_db: String,
    /// Trust `X-Forwarded-For` for the client IP (only behind a trusted proxy).
    ///
    /// Retained for compatibility; it is only consulted when
    /// [`EdgeConfig::trusted_proxies`] is empty. Prefer setting
    /// `TRUSTED_PROXIES`, which bounds the trust to specific networks.
    pub trust_proxy_headers: bool,
    /// Parsed `TRUSTED_PROXIES` CIDR list. Only requests whose socket peer is in
    /// this set may influence the client IP or the request scheme.
    #[serde(skip)]
    pub trusted_proxies: crate::security::trusted_proxy::TrustedProxies,
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
    /// TCP connect timeout to an origin.
    ///
    /// Deliberately separate from `origin_read_timeout_ms` and from the
    /// per-domain request timeout: a dead origin must fail over in seconds,
    /// not stall every fetch for the whole request budget.
    pub origin_connect_timeout_ms: u64,
    /// Gzip responses to clients when the origin returned identity.
    ///
    /// Origin fetches always request identity so the shared cache stores one
    /// reusable representation; compression is applied per client on the way
    /// out.
    pub compression_enabled: bool,
    /// Bodies smaller than this are not compressed.
    pub compression_min_bytes: usize,
    /// gzip level, 1 (fastest) to 9 (smallest).
    pub compression_level: u32,
    /// Memory cap for pre-compressed response variants. 0 disables reuse.
    pub compressed_cache_bytes: u64,
    /// Maximum number of pre-compressed variants retained.
    pub compressed_cache_entries: u64,
    /// Objects larger than this are compressed per request but never retained.
    pub compressed_cache_max_object_bytes: usize,
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
            worker_threads: std::env::var("EDGE_WORKER_THREADS")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or_else(|| {
                    std::thread::available_parallelism()
                        .map(|n| n.get())
                        .unwrap_or(4)
                })
                .clamp(1, 256),
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
            access_log_enabled: std::env::var("ACCESS_LOG_ENABLED")
                .map(|v| {
                    !matches!(
                        v.trim().to_ascii_lowercase().as_str(),
                        "off" | "0" | "false" | "no" | "disabled"
                    )
                })
                .unwrap_or(true),
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
            geoip_country_db: std::env::var("GEOIP_COUNTRY_DB")
                .unwrap_or_else(|_| "./data/maxmind/GeoLite2-Country.mmdb".into()),
            geoip_asn_db: std::env::var("GEOIP_ASN_DB")
                .unwrap_or_else(|_| "./data/maxmind/GeoLite2-ASN.mmdb".into()),
            trust_proxy_headers: bool_env("TRUST_PROXY_HEADERS", false),
            // Parsed lazily below so a typo fails startup with a clear message.
            trusted_proxies: crate::security::trusted_proxy::TrustedProxies::default(),
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
            origin_connect_timeout_ms: std::env::var("ORIGIN_CONNECT_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3_000)
                .clamp(500, 60_000),
            compression_enabled: std::env::var("EDGE_COMPRESSION")
                .map(|v| {
                    !matches!(
                        v.trim().to_ascii_lowercase().as_str(),
                        "off" | "0" | "false" | "no" | "disabled"
                    )
                })
                .unwrap_or(true),
            compression_min_bytes: std::env::var("EDGE_COMPRESSION_MIN_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1024)
                .clamp(0, 1024 * 1024),
            compression_level: std::env::var("EDGE_COMPRESSION_LEVEL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(4)
                .clamp(1, 9),
            compressed_cache_bytes: std::env::var("EDGE_COMPRESSED_CACHE_MAX_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(64 * 1024 * 1024)
                .clamp(0, 4 * 1024 * 1024 * 1024),
            compressed_cache_entries: std::env::var("EDGE_COMPRESSED_CACHE_ENTRIES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10_000)
                .clamp(0, 1_000_000),
            compressed_cache_max_object_bytes: std::env::var("EDGE_COMPRESSED_CACHE_MAX_OBJECT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(4 * 1024 * 1024)
                .clamp(0, 64 * 1024 * 1024),
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
    /// Load configuration, failing fast on an unusable `TRUSTED_PROXIES`.
    ///
    /// A typo must not silently degrade to "trust nobody" (which breaks client
    /// IP reporting) or, worse, to "trust everybody".
    pub fn load() -> Self {
        Self::load_checked().unwrap_or_else(|e| panic!("invalid edge configuration: {e}"))
    }

    pub fn load_checked() -> Result<Self, String> {
        let _ = dotenvy::dotenv();
        let mut config = Self::default();
        let spec = std::env::var("TRUSTED_PROXIES").unwrap_or_default();
        config.trusted_proxies = crate::security::trusted_proxy::TrustedProxies::parse(&spec)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A typo in TRUSTED_PROXIES must fail startup rather than silently
    /// trusting nothing (breaking client IP reporting) or everything.
    #[test]
    fn invalid_trusted_proxies_is_rejected() {
        assert!(crate::security::trusted_proxy::TrustedProxies::parse("10.0.0.0/8").is_ok());
        assert!(crate::security::trusted_proxy::TrustedProxies::parse("10.0.0.0/33").is_err());
        assert!(crate::security::trusted_proxy::TrustedProxies::parse("nonsense").is_err());
        assert!(crate::security::trusted_proxy::TrustedProxies::parse("10.0.0.0/8, bad").is_err());
    }

    #[test]
    fn control_url_is_normalized() {
        assert_eq!(
            normalize_control_url("  https://control.example.com/  "),
            "https://control.example.com"
        );
        assert_eq!(normalize_control_url("   "), "http://127.0.0.1:8080");
    }
}
