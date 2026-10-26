//! Multi-domain registry: Host → origin + rules + CDN settings.
//!
//! Entries are shared behind `Arc` so the request path does not clone origin
//! URLs and rule vectors on every lookup.

use crate::cache::policy::CacheRule;
use crate::server::cc::CcConfig;
use crate::waf::WafConfig;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct DomainEntry {
    pub domain: String,
    pub origin_url: String,
    pub rules: Vec<CacheRule>,
    pub version: String,
    pub rate_limit_rps: u32,
    pub rate_limit_burst: u32,
    pub ignore_query_string: bool,
    pub cors_origins: String,
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
            let key = normalize_host(&e.domain);
            map.insert(key, Arc::new(e));
        }
        *self.inner.write().await = map;
        *self.version.write().await = version;
    }

    pub async fn upsert(&self, entry: DomainEntry) {
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

pub fn normalize_host(host: &str) -> String {
    let host = host.trim().to_lowercase();
    if host.is_empty() {
        return String::new();
    }
    if let Some(rest) = host.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return rest[..end].to_string();
        }
    }
    if let Some((name, port)) = host.rsplit_once(':') {
        if !name.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            return name.to_string();
        }
    }
    host
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
            rules: vec![
                CacheRule::simple("/*".into(), 60, 0),
                CacheRule::simple("/api/*".into(), 0, prio),
            ],
            version: "v1".into(),
            rate_limit_rps: 0,
            rate_limit_burst: 0,
            ignore_query_string: false,
            cors_origins: String::new(),
            hotlink_allow_referers: String::new(),
            origin_timeout_ms: 10_000,
            custom_headers: String::new(),
            backup_origin_url: String::new(),
            ssl_enabled: false,
            waf: WafConfig::default(),
            cc: CcConfig::default(),
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

    #[test]
    fn host_normalization() {
        assert_eq!(normalize_host("Ex.COM:443"), "ex.com");
        assert_eq!(normalize_host("[::1]:8080"), "::1");
        assert_eq!(normalize_host(" [::1] "), "::1");
        assert!(is_ip_host("127.0.0.1"));
    }
}
