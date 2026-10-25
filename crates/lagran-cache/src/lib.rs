//! Shared cache abstractions and memory backend (DashMap + LRU eviction)

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
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
    async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
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

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
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

/// Approximate-LRU bookkeeping: a monotonic tick per access plus an ordered
/// queue of (key, tick). Stale queue records are skipped lazily and the queue
/// is compacted once it grows past twice the live key count.
#[derive(Default)]
struct LruState {
    tick: u64,
    pos: HashMap<String, u64>,
    order: VecDeque<(String, u64)>,
}

impl LruState {
    fn touch(&mut self, key: &str) {
        self.tick = self.tick.wrapping_add(1);
        let t = self.tick;
        self.pos.insert(key.to_string(), t);
        self.order.push_back((key.to_string(), t));
        let limit = self.pos.len().saturating_mul(2).saturating_add(64);
        if self.order.len() > limit {
            self.compact();
        }
    }

    fn compact(&mut self) {
        let mut order = std::mem::take(&mut self.order);
        order.retain(|(k, t)| self.pos.get(k).map(|cur| cur == t).unwrap_or(false));
        self.order = order;
    }

    fn remove(&mut self, key: &str) {
        self.pos.remove(key);
    }

    fn pop_victim(&mut self) -> Option<String> {
        while let Some((k, t)) = self.order.pop_front() {
            if self.pos.get(&k).is_some_and(|cur| *cur == t) {
                self.pos.remove(&k);
                return Some(k);
            }
        }
        None
    }
}

#[derive(Clone)]
pub struct MemoryCache {
    inner: Arc<DashMap<String, TimedEntry>>,
    lru: Arc<Mutex<LruState>>,
    /// Maximum number of entries; 0 means unbounded.
    capacity: usize,
}

impl Default for MemoryCache {
    fn default() -> Self {
        Self::new(10_000)
    }
}

impl MemoryCache {
    pub fn new(max_capacity: u64) -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
            lru: Arc::new(Mutex::new(LruState::default())),
            capacity: usize::try_from(max_capacity).unwrap_or(usize::MAX),
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    fn touch(&self, key: &str) {
        if let Ok(mut lru) = self.lru.lock() {
            lru.touch(key);
        }
    }

    /// Evict least-recently-used entries until the cache fits its capacity.
    fn evict_overflow(&self) {
        if self.capacity == 0 {
            return;
        }
        while self.inner.len() > self.capacity {
            let victim = match self.lru.lock() {
                Ok(mut lru) => lru.pop_victim(),
                Err(_) => None,
            };
            match victim {
                Some(key) => {
                    self.inner.remove(&key);
                }
                None => {
                    // LRU bookkeeping out of sync (entries inserted elsewhere):
                    // fall back to dropping an arbitrary entry so memory stays bounded.
                    let any = self.inner.iter().next().map(|e| e.key().clone());
                    match any {
                        Some(key) => {
                            self.inner.remove(&key);
                        }
                        None => break,
                    }
                }
            }
        }
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
            let entry = item.entry.clone();
            drop(item);
            self.touch(key);
            return CacheGetResult::Hit(entry);
        }
        if now <= item.stale_until {
            let entry = item.entry.clone();
            drop(item);
            self.touch(key);
            return CacheGetResult::Stale(entry);
        }
        drop(item);
        self.inner.remove(key);
        if let Ok(mut lru) = self.lru.lock() {
            lru.remove(key);
        }
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
        self.touch(key);
        self.evict_overflow();
    }

    async fn delete(&self, key: &str) {
        self.inner.remove(key);
        if let Ok(mut lru) = self.lru.lock() {
            lru.remove(key);
        }
    }

    async fn clear(&self) {
        self.inner.clear();
        if let Ok(mut lru) = self.lru.lock() {
            lru.pos.clear();
            lru.order.clear();
        }
    }

    async fn purge_matching(&self, patterns: &[String]) -> u64 {
        if patterns.is_empty() {
            let n = self.inner.len() as u64;
            self.clear().await;
            return n;
        }
        let keys: Vec<String> = self
            .inner
            .iter()
            .filter(|e| patterns.iter().any(|p| !p.is_empty() && e.key().contains(p)))
            .map(|e| e.key().clone())
            .collect();
        let mut removed = 0u64;
        for k in keys {
            if self.inner.remove(&k).is_some() {
                removed += 1;
            }
            if let Ok(mut lru) = self.lru.lock() {
                lru.remove(&k);
            }
        }
        removed
    }

    async fn len(&self) -> usize {
        self.inner.len()
    }
}

pub type SharedCache = Arc<dyn CacheBackend>;

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(body: &'static str) -> CacheEntry {
        CacheEntry::new(
            200,
            vec![("content-type".into(), "text/plain".into())],
            Bytes::from_static(body.as_bytes()),
        )
    }

    #[tokio::test]
    async fn hit_and_miss() {
        let c = MemoryCache::new(10);
        c.set("k", entry("a"), 60).await;
        match c.get_result("k").await {
            CacheGetResult::Hit(e) => assert_eq!(e.header("content-type"), Some("text/plain")),
            other => panic!("expected hit, got {other:?}"),
        }
        assert!(matches!(c.get_result("nope").await, CacheGetResult::Miss));
    }

    #[tokio::test]
    async fn swr_window_reports_stale() {
        let c = MemoryCache::new(10);
        c.set_with_swr("k", entry("a"), 1, 60).await;
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(matches!(c.get_result("k").await, CacheGetResult::Stale(_)));
    }

    #[tokio::test]
    async fn lru_evicts_oldest() {
        let c = MemoryCache::new(2);
        c.set("a", entry("a"), 60).await;
        c.set("b", entry("b"), 60).await;
        // touch a so b becomes the LRU victim
        let _ = c.get_result("a").await;
        c.set("c", entry("c"), 60).await;
        assert_eq!(c.len().await, 2);
        assert!(matches!(c.get_result("a").await, CacheGetResult::Hit(_)));
        assert!(matches!(c.get_result("b").await, CacheGetResult::Miss));
        assert!(matches!(c.get_result("c").await, CacheGetResult::Hit(_)));
    }

    #[tokio::test]
    async fn purge_matching_removes_keys() {
        let c = MemoryCache::new(10);
        c.set("GET:a.example/x", entry("a"), 60).await;
        c.set("GET:b.example/x", entry("b"), 60).await;
        assert_eq!(c.purge_matching(&["a.example".into()]).await, 1);
        assert_eq!(c.len().await, 1);
    }

    #[tokio::test]
    async fn unbounded_when_capacity_zero() {
        let c = MemoryCache::new(0);
        for i in 0..100 {
            c.set(&format!("k{i}"), entry("x"), 60).await;
        }
        assert_eq!(c.len().await, 100);
    }
}
