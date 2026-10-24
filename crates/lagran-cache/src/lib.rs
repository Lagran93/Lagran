//! Shared cache abstractions and memory backend (DashMap)

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[async_trait]
pub trait CacheBackend: Send + Sync {
    async fn get(&self, key: &str) -> Option<CacheEntry>;
    async fn set(&self, key: &str, entry: CacheEntry, ttl_secs: u64);
    async fn delete(&self, key: &str);
    async fn clear(&self);
    /// Delete keys that contain any of the substrings (path/url match)
    async fn purge_matching(&self, patterns: &[String]) -> u64;
    async fn len(&self) -> usize;
}

#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

struct TimedEntry {
    entry: CacheEntry,
    expires_at: Instant,
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

#[async_trait]
impl CacheBackend for MemoryCache {
    async fn get(&self, key: &str) -> Option<CacheEntry> {
        let item = self.inner.get(key)?;
        if Instant::now() > item.expires_at {
            drop(item);
            self.inner.remove(key);
            return None;
        }
        Some(item.entry.clone())
    }

    async fn set(&self, key: &str, entry: CacheEntry, ttl_secs: u64) {
        let expires_at = Instant::now() + Duration::from_secs(ttl_secs.max(1));
        self.inner.insert(key.to_string(), TimedEntry { entry, expires_at });
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
        for key in keys {
            let hit = patterns.iter().any(|p| {
                if p.is_empty() {
                    return false;
                }
                // match full key or path portion
                key.contains(p.as_str())
            });
            if hit {
                self.inner.remove(&key);
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
