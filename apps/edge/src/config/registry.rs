//! Multi-domain registry: Host → origin + rules + CDN settings

use crate::cache::policy::CacheRule;
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
}

#[derive(Clone, Default)]
pub struct DomainRegistry {
    inner: Arc<RwLock<HashMap<String, DomainEntry>>>,
    version: Arc<RwLock<String>>,
}

impl DomainRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn replace_all(&self, entries: Vec<DomainEntry>, version: String) {
        let mut map = HashMap::new();
        for e in entries {
            let key = normalize_host(&e.domain);
            map.insert(key, e);
        }
        *self.inner.write().await = map;
        *self.version.write().await = version;
    }

    pub async fn upsert(&self, entry: DomainEntry) {
        let key = normalize_host(&entry.domain);
        self.inner.write().await.insert(key, entry);
    }

    pub async fn get(&self, host: &str) -> Option<DomainEntry> {
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

    pub async fn version(&self) -> String {
        self.version.read().await.clone()
    }

    pub async fn list_domains(&self) -> Vec<String> {
        self.inner.read().await.keys().cloned().collect()
    }
}

pub fn normalize_host(host: &str) -> String {
    let host = host.trim().to_lowercase();
    if host.is_empty() {
        return String::new();
    }
    if host.starts_with('[') {
        if let Some(end) = host.find(']') {
            return host[1..end].to_string();
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
