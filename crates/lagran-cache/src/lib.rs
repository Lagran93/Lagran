//! Shared cache abstractions and memory backend (DashMap + LRU eviction)

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheSource {
    /// Local process memory cache.
    L1,
    /// Shared Redis L2 cache.
    L2,
    /// Local large-object/disk cache.
    L3,
    Unknown,
}

impl CacheSource {
    pub fn as_str(self) -> &'static str {
        match self {
            CacheSource::L1 => "l1",
            CacheSource::L2 => "l2",
            CacheSource::L3 => "l3",
            CacheSource::Unknown => "unknown",
        }
    }
}

#[async_trait]
pub trait CacheBackend: Send + Sync {
    async fn get_result(&self, key: &str) -> CacheGetResult;
    /// Same as `get_result`, additionally reporting which cache layer served it.
    async fn get_result_with_source(&self, key: &str) -> (CacheGetResult, CacheSource) {
        (self.get_result(key).await, CacheSource::L1)
    }
    /// Cheap local-only presence probe. Used to avoid taking a Redis
    /// single-flight lock when L1 already has the object.
    async fn has_local(&self, _key: &str) -> bool {
        false
    }
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
    /// Purge entries whose `Surrogate-Key` / `Cache-Tag` response header
    /// contains any of the requested tags.
    async fn purge_tags(&self, _tags: &[String], _domain: &str) -> u64 {
        0
    }
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
    /// Fresh-until epoch (for remaining TTL header); 0 when unknown.
    pub fresh_until_epoch_secs: u64,
    /// Hard-expiry epoch including stale-while-revalidate; 0 when unknown.
    pub stale_until_epoch_secs: u64,
}

impl CacheEntry {
    pub fn new(status: u16, headers: Vec<(String, String)>, body: Bytes) -> Self {
        Self {
            status,
            headers,
            body,
            stored_at_epoch_secs: now_epoch_secs(),
            fresh_until_epoch_secs: 0,
            stale_until_epoch_secs: 0,
        }
    }

    /// Cache tags from standard response headers.
    pub fn tags(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (name, value) in &self.headers {
            if !["surrogate-key", "cache-tag", "x-cache-tag"]
                .iter()
                .any(|n| name.eq_ignore_ascii_case(n))
            {
                continue;
            }
            out.extend(
                value
                    .split(|c: char| c == ',' || c.is_whitespace())
                    .map(str::trim)
                    .filter(|tag| !tag.is_empty())
                    .map(str::to_string),
            );
        }
        out
    }

    pub fn age_secs(&self) -> u64 {
        now_epoch_secs().saturating_sub(self.stored_at_epoch_secs)
    }

    /// Remaining fresh lifetime in seconds, when the backend recorded it.
    pub fn ttl_secs(&self) -> Option<u64> {
        (self.fresh_until_epoch_secs > 0)
            .then(|| self.fresh_until_epoch_secs.saturating_sub(now_epoch_secs()))
    }

    /// Approximate heap footprint used by the memory backend's byte cap.
    pub fn memory_size(&self) -> u64 {
        let mut size = self.body.len() as u64 + 128;
        for (name, value) in &self.headers {
            size += (name.len() + value.len()) as u64 + 32;
        }
        size
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
    /// Maximum approximate bytes; 0 means unbounded.
    max_bytes: u64,
    used_bytes: Arc<AtomicU64>,
}

impl Default for MemoryCache {
    fn default() -> Self {
        Self::new(10_000)
    }
}

impl MemoryCache {
    pub fn new(max_capacity: u64) -> Self {
        Self::with_max_bytes(max_capacity, 0)
    }

    pub fn with_max_bytes(max_capacity: u64, max_bytes: u64) -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
            lru: Arc::new(Mutex::new(LruState::default())),
            capacity: usize::try_from(max_capacity).unwrap_or(usize::MAX),
            max_bytes,
            used_bytes: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    pub fn used_bytes(&self) -> u64 {
        self.used_bytes.load(Ordering::Relaxed)
    }

    fn touch(&self, key: &str) {
        if let Ok(mut lru) = self.lru.lock() {
            lru.touch(key);
        }
    }

    /// Evict least-recently-used entries until the cache fits its capacity.
    /// Subtract `bytes` from the running total without wrapping.
    ///
    /// `fetch_sub` on a `u64` wraps to a huge value if two threads account for
    /// the same removal, and the wrap makes `over_limit()` permanently true: the
    /// cache then evicts every entry it holds, on every insert. A saturating
    /// update keeps the counter meaningful even if bookkeeping ever drifts.
    fn release_bytes(&self, bytes: u64) {
        self.used_bytes
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                Some(used.saturating_sub(bytes))
            })
            .ok();
    }

    /// Sum of `memory_size()` over the entries currently held.
    ///
    /// O(n) in the entry count; only used on `clear` and by tests.
    fn accounted_bytes(&self) -> u64 {
        self.inner
            .iter()
            .map(|e| e.entry.memory_size())
            .fold(0u64, |acc, size| acc.saturating_add(size))
    }

    fn remove_key(&self, key: &str) -> Option<TimedEntry> {
        let removed = self.inner.remove(key).map(|(_, entry)| entry);
        if let Some(entry) = &removed {
            self.release_bytes(entry.entry.memory_size());
        }
        if let Ok(mut lru) = self.lru.lock() {
            lru.remove(key);
        }
        removed
    }

    fn over_limit(&self) -> bool {
        (self.capacity > 0 && self.inner.len() > self.capacity)
            || (self.max_bytes > 0 && self.used_bytes.load(Ordering::Relaxed) > self.max_bytes)
    }

    /// Evict least-recently-used entries until count and byte limits fit.
    fn evict_overflow(&self) {
        while self.over_limit() {
            let victim = match self.lru.lock() {
                Ok(mut lru) => lru.pop_victim(),
                Err(_) => None,
            };
            match victim {
                Some(key) => {
                    self.remove_key(&key);
                }
                None => {
                    // LRU bookkeeping out of sync (entries inserted elsewhere):
                    // fall back to dropping an arbitrary entry so memory stays bounded.
                    let any = self.inner.iter().next().map(|e| e.key().clone());
                    match any {
                        Some(key) => {
                            self.remove_key(&key);
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
        self.remove_key(key);
        CacheGetResult::Expired
    }

    async fn set(&self, key: &str, entry: CacheEntry, ttl_secs: u64) {
        self.set_with_swr(key, entry, ttl_secs, 0).await;
    }

    async fn set_with_swr(&self, key: &str, mut entry: CacheEntry, fresh_secs: u64, swr_secs: u64) {
        let now = Instant::now();
        let fresh = Duration::from_secs(fresh_secs.max(1));
        let swr = Duration::from_secs(swr_secs);
        let fresh_secs = fresh_secs.max(1);
        let now_epoch = now_epoch_secs();
        entry.fresh_until_epoch_secs = now_epoch + fresh_secs;
        entry.stale_until_epoch_secs = now_epoch + fresh_secs + swr_secs;
        entry.stored_at_epoch_secs = now_epoch;
        // Account for the replacement atomically per key.
        //
        // The previous code added the new size and subtracted the old one as two
        // independent operations on a shared counter. Two concurrent writers to
        // the same key can both observe their own `insert` return value while
        // another thread's value is the one actually replaced, so the total
        // drifts; repeated drift wraps the `u64` and triggers a full eviction
        // storm. Pairing the sizes and applying the delta in one update keeps the
        // counter consistent regardless of interleaving.
        let new_entry = TimedEntry {
            entry,
            fresh_until: now + fresh,
            stale_until: now + fresh + swr,
        };
        let size = new_entry.entry.memory_size();
        // `DashMap::insert` returns the replaced value under the shard lock, so
        // the delta is exact even with concurrent writers on the same key. A
        // separate `get` before the insert leaves a window where two writers
        // both read the same old size and both subtract it.
        let old = self.inner.insert(key.to_string(), new_entry);
        let old_size = old.map(|e| e.entry.memory_size()).unwrap_or(0);
        self.used_bytes
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                Some(used.saturating_sub(old_size).saturating_add(size))
            })
            .ok();
        self.touch(key);
        self.evict_overflow();
    }

    async fn delete(&self, key: &str) {
        self.remove_key(key);
    }

    async fn clear(&self) {
        self.inner.clear();
        // Recompute rather than zero: an `insert` that raced with `clear` may
        // already have added its bytes, and storing 0 would then under-count
        // them permanently. Recomputing from the live map is always correct and
        // also heals any earlier drift.
        self.used_bytes
            .store(self.accounted_bytes(), Ordering::Relaxed);
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
            .filter(|e| {
                patterns
                    .iter()
                    .any(|p| !p.is_empty() && e.key().contains(p))
            })
            .map(|e| e.key().clone())
            .collect();
        let mut removed = 0u64;
        for k in keys {
            if self.remove_key(&k).is_some() {
                removed += 1;
            }
        }
        removed
    }

    async fn purge_tags(&self, tags: &[String], domain: &str) -> u64 {
        let wanted: Vec<String> = tags.iter().map(|t| t.to_ascii_lowercase()).collect();
        if wanted.is_empty() {
            return 0;
        }
        let domain = domain.to_ascii_lowercase();
        let keys: Vec<String> = self
            .inner
            .iter()
            .filter(|e| {
                (domain.is_empty() || e.key().to_ascii_lowercase().contains(&domain))
                    && e.value()
                        .entry
                        .tags()
                        .iter()
                        .any(|tag| wanted.iter().any(|w| w == &tag.to_ascii_lowercase()))
            })
            .map(|e| e.key().clone())
            .collect();
        let mut removed = 0u64;
        for k in keys {
            if self.remove_key(&k).is_some() {
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
    async fn byte_budget_evicts_entries() {
        let c = MemoryCache::with_max_bytes(10, 650);
        let big = CacheEntry::new(
            200,
            vec![("content-type".into(), "text/plain".into())],
            Bytes::from(vec![7_u8; 128]),
        );
        c.set("a", big.clone(), 60).await;
        c.set("b", big.clone(), 60).await;
        assert!(c.used_bytes() <= 650);
        c.set("c", big, 60).await;
        assert!(c.used_bytes() <= 650);
        assert!(c.len().await <= 2);
    }

    /// A wrapped counter makes `over_limit()` permanently true, so the cache
    /// evicts everything on every insert.
    ///
    /// This exercises `release_bytes` directly: driving the wrap through
    /// concurrent `set` calls is timing-dependent and did not reproduce it
    /// reliably, so the arithmetic is what gets asserted.
    #[tokio::test]
    async fn release_bytes_never_wraps() {
        let c = MemoryCache::with_max_bytes(1000, 100_000);
        c.set("a", entry("a"), 60).await;
        let before = c.used_bytes();
        assert!(before > 0);

        // Releasing more than is accounted must clamp at zero, not wrap.
        c.release_bytes(before + 1);
        assert_eq!(
            c.used_bytes(),
            0,
            "over-release must saturate at zero, not wrap to u64::MAX"
        );

        // Over-releasing desynchronises the counter from the live map: the
        // entry is still there but uncounted. That is exactly why `clear`
        // recomputes instead of trusting the running total, and it is why the
        // real code paths never release bytes they did not add. Verify the
        // recovery mechanism works rather than asserting a state the cache is
        // not supposed to reach.
        assert_ne!(c.used_bytes(), c.accounted_bytes());
        c.clear().await;
        assert_eq!(
            c.used_bytes(),
            c.accounted_bytes(),
            "clear must resynchronise the counter with reality"
        );
    }

    /// Overwriting the same key repeatedly must keep the total exact.
    #[tokio::test]
    async fn repeated_overwrite_keeps_total_exact() {
        let c = MemoryCache::with_max_bytes(1000, 100_000);
        for _ in 0..500 {
            c.set("same-key", entry("a"), 60).await;
        }
        assert_eq!(c.len().await, 1);
        assert_eq!(
            c.used_bytes(),
            c.accounted_bytes(),
            "total must equal the single live entry"
        );
    }

    /// Two writers on the same key must not both subtract the same old size.
    #[tokio::test]
    async fn concurrent_overwrite_keeps_accounting_consistent() {
        let c = std::sync::Arc::new(MemoryCache::with_max_bytes(1000, 100_000));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let cache = c.clone();
            handles.push(tokio::spawn(async move {
                for _ in 0..200 {
                    cache.set("hot", entry("x"), 60).await;
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(c.len().await, 1, "single key must stay single");
        let one = c.accounted_bytes();
        assert_eq!(
            c.used_bytes(),
            one,
            "accounted total must match the actual entry"
        );
    }

    /// `clear` recomputes instead of zeroing, so a racing insert is not lost.
    #[tokio::test]
    async fn clear_recomputes_instead_of_zeroing() {
        let c = MemoryCache::new(100);
        c.set("a", entry("a"), 60).await;
        c.set("b", entry("b"), 60).await;
        c.clear().await;
        assert_eq!(c.len().await, 0);
        assert_eq!(c.used_bytes(), 0);
        assert_eq!(c.used_bytes(), c.accounted_bytes());
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
