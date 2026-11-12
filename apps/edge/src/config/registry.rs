//! Multi-domain registry: Host → origin + rules + CDN settings.
//!
//! Entries are shared behind `Arc` so the request path does not clone origin
//! URLs and rule vectors on every lookup.

use crate::cache::policy::CacheRule;
use crate::server::cc::CcConfig;
use crate::server::response_headers::ResponseHeaderOverrides;
use crate::waf::WafConfig;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct OriginTarget {
    pub url: String,
    pub weight: u32,
    pub priority: i32,
    pub enabled: bool,
    /// Override Host sent upstream. Used by Origin Shield (public domain Host)
    /// and by IP origins that need a hostname-based virtual host.
    pub host_header: Option<String>,
    /// TLS SNI / certificate hostname. `None` uses the URL host.
    pub sni: Option<String>,
}

impl OriginTarget {
    /// Smooth weighted round-robin. `seed` rotates the starting slot; retries
    /// then walk the returned list in order.
    pub fn weighted_order(candidates: Vec<Self>, seed: u64) -> Vec<Self> {
        if candidates.is_empty() {
            return candidates;
        }
        let total: u64 = candidates.iter().map(|o| u64::from(o.weight.max(1))).sum();
        let mut slot = seed % total.max(1);
        let mut start = 0usize;
        for (i, origin) in candidates.iter().enumerate() {
            let weight = u64::from(origin.weight.max(1));
            if slot < weight {
                start = i;
                break;
            }
            slot -= weight;
        }
        (0..candidates.len())
            .map(|i| candidates[(start + i) % candidates.len()].clone())
            .collect()
    }
}

#[derive(Debug, Clone, Default)]
pub struct DomainEntry {
    pub domain: String,
    pub origin_url: String,
    /// Weighted origin pool. `origin_url` / `backup_origin_url` are kept for
    /// compatibility with older config snapshots and health reporting.
    pub origins: Vec<OriginTarget>,
    pub rules: Vec<CacheRule>,
    /// True when any rule depends on the response Content-Type. The response
    /// path can then reuse the request policy without rescanning rules.
    pub has_content_type_rules: bool,
    pub version: String,
    pub rate_limit_rps: u32,
    pub rate_limit_burst: u32,
    pub ignore_query_string: bool,
    /// Comma-separated cache-key headers to ignore (origin, accept-language).
    pub cache_key_ignore_headers: String,
    pub cors_origins: String,
    /// Parsed CORS and custom response headers, shared by all responses.
    pub response_headers: Arc<ResponseHeaderOverrides>,
    pub hotlink_allow_referers: String,
    pub origin_timeout_ms: u32,
    pub custom_headers: String,
    /// Optional backup origin URL (empty = none)
    pub backup_origin_url: String,
    /// Redirect plain HTTP requests to HTTPS when enabled
    pub ssl_enabled: bool,
    /// WAF policy (disabled by default until configured in the console)
    pub waf: WafConfig,
    /// CC/L7 flood policy (disabled by default).
    pub cc: CcConfig,
    /// Require HMAC-signed URLs for this domain.
    pub signed_url_enabled: bool,
    /// off | all | paths. Empty means legacy signed_url_enabled behavior.
    pub signed_url_mode: String,
    /// Newline-separated path patterns; only used when mode is paths.
    pub signed_url_paths: String,
    /// Active signing key and previous key for zero-downtime rotation.
    pub signed_url_secret: String,
    pub signed_url_previous_secret: String,
    /// Maximum allowed link lifetime; 0 means the default (1 hour).
    pub signed_url_ttl_secs: u32,
    /// Static header injected into origin requests (empty = disabled).
    pub origin_auth_header: String,
    pub origin_auth_value: String,
    /// Accept the same HMAC-signed URL as a hotlink bypass.
    pub hotlink_signature_enabled: bool,
}

#[derive(Clone, Default)]
pub struct DomainRegistry {
    inner: Arc<RwLock<HashMap<String, Arc<DomainEntry>>>>,
    version: Arc<RwLock<String>>,
}

impl DomainRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn replace_all(&self, entries: Vec<DomainEntry>, version: String) {
        let mut map = HashMap::with_capacity(entries.len());
        for mut e in entries {
            // Keep rules ordered by priority once, not per request.
            e.rules.sort_by_key(|r| std::cmp::Reverse(r.priority));
            e.has_content_type_rules = e
                .rules
                .iter()
                .any(|rule| !rule.match_content_type.trim().is_empty());
            e.response_headers = Arc::new(ResponseHeaderOverrides::parse(
                &e.cors_origins,
                &e.custom_headers,
            ));
            let key = normalize_host(&e.domain);
            map.insert(key, Arc::new(e));
        }
        *self.inner.write().await = map;
        *self.version.write().await = version;
    }

    pub async fn upsert(&self, mut entry: DomainEntry) {
        entry.has_content_type_rules = entry
            .rules
            .iter()
            .any(|rule| !rule.match_content_type.trim().is_empty());
        entry.response_headers = Arc::new(ResponseHeaderOverrides::parse(
            &entry.cors_origins,
            &entry.custom_headers,
        ));
        let key = normalize_host(&entry.domain);
        self.inner.write().await.insert(key, Arc::new(entry));
    }

    pub async fn get(&self, host: &str) -> Option<Arc<DomainEntry>> {
        let host = normalize_host(host);
        if host.is_empty() {
            return None;
        }
        self.inner.read().await.get(&host).cloned()
    }

    /// Registry lookup that reports whether the registry is empty separately
    /// from "this host is not configured".
    ///
    /// A legacy single-origin deployment deliberately serves only the
    /// configured `EDGE_DOMAIN`; that mode is entered when the registry has no
    /// entries. Checking `is_empty()` in a separate lock acquisition allowed a
    /// snapshot swap between the two reads and made an unknown host briefly look
    /// like legacy mode.
    pub async fn lookup(&self, host: &str) -> (bool, Option<Arc<DomainEntry>>) {
        let host = normalize_host(host);
        let entries = self.inner.read().await;
        (
            entries.is_empty(),
            if host.is_empty() {
                None
            } else {
                entries.get(&host).cloned()
            },
        )
    }

    /// Domain name -> per-domain config version, for cache invalidation when a
    /// domain changes on the control plane.
    pub async fn version_map(&self) -> HashMap<String, String> {
        self.inner
            .read()
            .await
            .iter()
            .map(|(domain, entry)| (domain.clone(), entry.version.clone()))
            .collect()
    }

    pub async fn contains(&self, host: &str) -> bool {
        self.get(host).await.is_some()
    }

    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    pub async fn version(&self) -> String {
        self.version.read().await.clone()
    }

    pub async fn list_domains(&self) -> Vec<String> {
        self.inner.read().await.keys().cloned().collect()
    }

    /// Snapshot of all entries (used by health probes).
    pub async fn snapshot(&self) -> Vec<Arc<DomainEntry>> {
        self.inner.read().await.values().cloned().collect()
    }
}

/// Canonical form of a request or configuration host.
///
/// This is the single authority for host normalization on the edge. Registry
/// lookups, cache keys and the challenge/clearance binding all route through it,
/// so a given object can never be cached or resolved under two different keys
/// depending on how the client spelled the `Host` header.
///
/// Rules applied, in order:
/// * trim surrounding whitespace and lowercase;
/// * strip a bracketed IPv6 literal's brackets, and nothing else, so
///   `[2001:db8::1]:8080` becomes `2001:db8::1` while a bare `2001:db8::1`
///   keeps all of its segments;
/// * strip a trailing root dot (`example.com.` -> `example.com`);
/// * strip a numeric port (`example.com:443` -> `example.com`).
///
/// A non-numeric suffix is *not* stripped: `example.com:evil` is not a valid
/// authority and must stay distinct from `example.com` rather than silently
/// aliasing onto it.
pub fn normalize_host(host: &str) -> String {
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty() {
        return String::new();
    }

    // Bracketed IPv6 literal, optionally with a port after the closing bracket.
    if let Some(rest) = host.strip_prefix('[') {
        return match rest.find(']') {
            Some(end) => rest[..end].to_string(),
            // Unterminated bracket: treat the whole value as opaque.
            None => host,
        };
    }

    // A bare IPv6 literal contains several colons and no port; splitting on the
    // last colon would truncate it to its first segment, which is exactly the
    // bug that let `Host: 2001:db8::1` collide with `Host: 2001`.
    let host = if host.matches(':').count() > 1 {
        host
    } else if let Some((name, port)) = host.rsplit_once(':') {
        if !name.is_empty() && !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            name.to_string()
        } else {
            host
        }
    } else {
        host
    };

    // Strip the root dot last so `example.com.:443` and `example.com.` both
    // reduce to `example.com`. Doing this first left the port attached, and
    // `strip_suffix('.').unwrap_or(&host)` silently kept the dot entirely.
    host.trim_end_matches('.').to_string()
}

pub fn is_ip_host(host: &str) -> bool {
    let h = normalize_host(host);
    h.parse::<std::net::Ipv4Addr>().is_ok() || h.parse::<std::net::Ipv6Addr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, prio: i32) -> DomainEntry {
        DomainEntry {
            domain: name.into(),
            origin_url: "http://origin.test".into(),
            origins: vec![OriginTarget {
                url: "http://origin.test".into(),
                weight: 100,
                priority: 0,
                enabled: true,
                host_header: None,
                sni: None,
            }],
            rules: vec![
                CacheRule::simple("/*".into(), 60, 0),
                CacheRule::simple("/api/*".into(), 0, prio),
            ],
            has_content_type_rules: false,
            version: "v1".into(),
            rate_limit_rps: 0,
            rate_limit_burst: 0,
            ignore_query_string: false,
            cache_key_ignore_headers: String::new(),
            cors_origins: String::new(),
            response_headers: Arc::default(),
            hotlink_allow_referers: String::new(),
            origin_timeout_ms: 10_000,
            custom_headers: String::new(),
            backup_origin_url: String::new(),
            ssl_enabled: false,
            waf: WafConfig::default(),
            cc: CcConfig::default(),
            signed_url_enabled: false,
            signed_url_mode: String::new(),
            signed_url_paths: String::new(),
            signed_url_secret: String::new(),
            signed_url_previous_secret: String::new(),
            signed_url_ttl_secs: 3600,
            origin_auth_header: String::new(),
            origin_auth_value: String::new(),
            hotlink_signature_enabled: false,
        }
    }

    #[tokio::test]
    async fn lookup_normalizes_host_and_sorts_rules() {
        let reg = DomainRegistry::new();
        reg.replace_all(
            vec![entry("CDN.Example.COM", 5), entry("other.test", 1)],
            "v1".into(),
        )
        .await;
        let e = reg.get("cdn.example.com:8080").await.expect("hit");
        assert_eq!(e.domain, "CDN.Example.COM");
        assert_eq!(e.rules[0].priority, 5, "rules sorted by priority desc");
        assert!(reg.get("unknown.test").await.is_none());
        assert_eq!(reg.len().await, 2);
    }

    #[tokio::test]
    async fn lookup_reports_miss_and_empty_registry_atomically() {
        let reg = DomainRegistry::new();
        let (empty, found) = reg.lookup("cdn.test").await;
        assert!(empty);
        assert!(found.is_none());

        reg.replace_all(vec![entry("cdn.test", 1)], "v1".into())
            .await;
        let (empty, found) = reg.lookup("CDN.TEST:443").await;
        assert!(!empty);
        assert_eq!(found.unwrap().domain, "cdn.test");
        let (empty, found) = reg.lookup("unknown.test").await;
        assert!(!empty);
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn domain_snapshot_compiles_response_header_overrides() {
        let reg = DomainRegistry::new();
        let mut domain = entry("cdn.test", 1);
        domain.cors_origins = "https://cdn.test,https://other.test".into();
        domain.custom_headers = "X-Edge: lagran".into();
        reg.replace_all(vec![domain], "v1".into()).await;

        let domain = reg.get("cdn.test").await.unwrap();
        let mut headers = axum::http::HeaderMap::new();
        domain.response_headers.apply(&mut headers);
        assert_eq!(headers["access-control-allow-origin"], "https://cdn.test");
        assert_eq!(headers["x-edge"], "lagran");
    }

    #[tokio::test]
    async fn domain_snapshot_marks_content_type_rules() {
        let reg = DomainRegistry::new();
        let mut domain = entry("cdn.test", 1);
        domain.rules[0].match_content_type = "text/html".into();
        reg.replace_all(vec![domain], "v1".into()).await;
        assert!(
            reg.get("cdn.test").await.unwrap().has_content_type_rules,
            "replace_all must precompute content-type rule metadata"
        );

        let mut domain = entry("cdn.test", 1);
        domain.has_content_type_rules = true;
        reg.upsert(domain).await;
        assert!(
            !reg.get("cdn.test").await.unwrap().has_content_type_rules,
            "upsert must recompute stale metadata"
        );
    }

    #[test]
    fn host_normalization() {
        assert_eq!(normalize_host("Ex.COM:443"), "ex.com");
        assert_eq!(normalize_host("[::1]:8080"), "::1");
        assert_eq!(normalize_host(" [::1] "), "::1");
        // A bare IPv6 literal keeps every segment; splitting on the last colon
        // used to truncate it to `2001`, aliasing unrelated hosts together.
        assert_eq!(normalize_host("2001:db8::1"), "2001:db8::1");
        assert_eq!(normalize_host("[2001:db8::1]:443"), "2001:db8::1");
        // A trailing root dot is not a distinct host.
        assert_eq!(normalize_host("example.com."), "example.com");
        assert_eq!(normalize_host("example.com.:443"), "example.com");
        // A non-numeric suffix is not a port and must not alias the bare host.
        assert_eq!(normalize_host("example.com:evil"), "example.com:evil");
        assert_ne!(
            normalize_host("example.com:evil"),
            normalize_host("example.com")
        );
        assert_eq!(normalize_host(""), "");
        assert_eq!(normalize_host("   "), "");
        assert!(is_ip_host("127.0.0.1"));
    }

    #[test]
    fn weighted_order_respects_weights() {
        let pool = vec![
            OriginTarget {
                url: "http://a".into(),
                weight: 1,
                priority: 0,
                enabled: true,
                host_header: None,
                sni: None,
            },
            OriginTarget {
                url: "http://b".into(),
                weight: 3,
                priority: 0,
                enabled: true,
                host_header: None,
                sni: None,
            },
        ];
        let mut a = 0;
        let mut b = 0;
        for seed in 0..40 {
            match OriginTarget::weighted_order(pool.clone(), seed)[0]
                .url
                .as_str()
            {
                "http://a" => a += 1,
                "http://b" => b += 1,
                _ => unreachable!(),
            }
        }
        assert_eq!(a, 10);
        assert_eq!(b, 30);
    }
}
