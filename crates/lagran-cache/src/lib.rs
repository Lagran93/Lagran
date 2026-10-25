//! Shared cache abstractions and memory backend (DashMap)

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[async_trait]
pub trait CacheBackend: Send + Sync {
    async fn get_result(&self, key: &str) -> CacheGetResult;
    async fn get(&self, key: &str) -> Option<CacheEntry> {
        match self.get_result(key).await {
            CacheGetResult::Hit(e) | CacheGetResult::Stale(e) => Some(e),
            CacheGetResult::Miss | CacheGetResult::Expired => None,
        }
    }
    async fn set(&self, key: &str, entry: CacheEntry, ttl_secs: u64);
    /// Set with soft (fresh) TTL and optional stale-while-revalidate window
    async fn set_with_swr(&self, key: &str, entry: CacheEntry, fresh_secs: u64, swr_secs: u64);
    async fn delete(&self, key: &str);
    async fn clear(&self);
    async fn purge_matching(&self, patterns: &[String]) -> u64;
    async fn len(&self) -> usize;
}

#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
    /// When this entry was stored (for Age header)
    pub stored_at_epoch_secs: u64,
}

impl CacheEntry {
    pub fn new(status: u16, headers: Vec<(String, String)>, body: Bytes) -> Self {
        Self {
            status,
            headers,
            body,
            stored_at_epoch_secs: now_epoch_secs(),
        }
    }

    pub fn age_secs(&self) -> u64 {
        now_epoch_secs().saturating_sub(self.stored_at_epoch_secs)
    }
}

#[derive(Debug, Clone)]
pub enum CacheGetResult {
    /// Within fresh TTL
    Hit(CacheEntry),
    /// Past fresh TTL but within stale-while-revalidate window
    Stale(CacheEntry),
    /// Entry existed but hard-expired (removed)
    Expired,
    /// No entry
    Miss,
}

struct TimedEntry {
    entry: CacheEntry,
    /// Fresh until this instant
    fresh_until: Instant,
    /// Soft-usable (stale) until this instant; after that hard miss
    stale_until: Instant,
}

#[derive(Clone, Default)]
pub struct MemoryCache {
    inner: Arc<DashMap<String, TimedEntry>>,
}

impl MemoryCache {
    pub fn new(_max_capacity: u64) -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(10_000)
    }
}

fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[async_trait]
impl CacheBackend for MemoryCache {
    async fn get_result(&self, key: &str) -> CacheGetResult {
        let item = match self.inner.get(key) {
            Some(i) => i,
            None => return CacheGetResult::Miss,
        };
        let now = Instant::now();
        if now <= item.fresh_until {
            return CacheGetResult::Hit(item.entry.clone());
        }
        if now <= item.stale_until {
            return CacheGetResult::Stale(item.entry.clone());
        }
        drop(item);
        self.inner.remove(key);
        CacheGetResult::Expired
    }

    async fn set(&self, key: &str, entry: CacheEntry, ttl_secs: u64) {
        self.set_with_swr(key, entry, ttl_secs, 0).await;
    }

    async fn set_with_swr(&self, key: &str, entry: CacheEntry, fresh_secs: u64, swr_secs: u64) {
        let now = Instant::now();
        let fresh = Duration::from_secs(fresh_secs.max(1));
        let swr = Duration::from_secs(swr_secs);
        self.inner.insert(
            key.to_string(),
            TimedEntry {
                entry,
                fresh_until: now + fresh,
                stale_until: now + fresh + swr,
            },
        );
    }

    async fn delete(&self, key: &str) {
        self.inner.remove(key);
    }

    async fn clear(&self) {
        self.inner.clear();
    }

    async fn purge_matching(&self, patterns: &[String]) -> u64 {
        if patterns.is_empty() {
            let n = self.inner.len() as u64;
            self.inner.clear();
            return n;
        }
        let mut removed = 0u64;
        let keys: Vec<String> = self.inner.iter().map(|e| e.key().clone()).collect();
        for k in keys {
            if patterns.iter().any(|p| k.contains(p)) {
                self.inner.remove(&k);
                removed += 1;
            }
        }
        removed
    }

    async fn len(&self) -> usize {
        self.inner.len()
    }
}

pub type SharedCache = Arc<dyn CacheBackend>;
