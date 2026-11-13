//! Shared cache abstractions and memory backend (DashMap + LRU eviction)

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Upper bound on any freshness or stale-while-revalidate lifetime.
///
/// TTLs come from cache rules and origin `Cache-Control` headers, both outside
/// the process's trust boundary. A value such as
/// `max-age=18446744073709551615` used to flow unchanged into
/// `SystemTime + Duration` inside the Pingora response filter and panic, killing
/// the worker thread. 400 days is the cap browsers apply to persisted HTTP cache
/// entries; longer lifetimes are meaningless for a CDN and only turn arithmetic
/// bugs into outages.
pub const MAX_TTL_SECS: u64 = 400 * 24 * 60 * 60;

/// Clamp a lifetime derived from configuration or an origin header.
pub fn clamp_ttl_secs(secs: u64) -> u64 {
    secs.min(MAX_TTL_SECS)
}

/// Add `secs` to an `Instant`, falling back to the maximum lifetime instead of
/// panicking on overflow.
fn instant_add(now: Instant, secs: u64) -> Instant {
    // Fall back to the clamp value and finally to `now`: adding anything to an
    // instant that is already close to `Instant::MAX` can fail too, and a
    // deadline in the past is a safe (if useless) outcome.
    now.checked_add(Duration::from_secs(secs))
        .or_else(|| now.checked_add(Duration::from_secs(MAX_TTL_SECS)))
        .unwrap_or(now)
}

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

/// A structured cache-purge target.
///
/// Purge used to be a raw `key.contains(pattern)` check, so refreshing one URL
/// (or the domain appended to every pattern) deleted whole domains, and a
/// domain string matched other tenants whose names merely contained it. Targets
/// are scoped to one host and match the key structure `METHOD:host:path`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PurgeTarget {
    pub host: String,
    /// `path` or `path?query`, exactly as it appears in the cache key.
    pub path: String,
    /// When true, match every path under `path` at a path boundary.
    pub prefix: bool,
}

impl PurgeTarget {
    /// Build a target from an owning domain and a path (or `path?query`).
    pub fn new(host: &str, path: &str, prefix: bool) -> Option<Self> {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || !path.starts_with('/') {
            return None;
        }
        Some(Self {
            host,
            path: path.to_string(),
            prefix,
        })
    }

    /// Target that matches every cached object of a domain (config change).
    pub fn for_domain(host: &str) -> Option<Self> {
        Self::new(host, "/", true)
    }
}

/// Whether a cache key (`METHOD:host:path[?query][|vary=hash]`) matches.
pub fn cache_key_matches(key: &str, target: &PurgeTarget) -> bool {
    let Some((host, path)) = split_cache_key(key) else {
        return false;
    };
    if !host.eq_ignore_ascii_case(&target.host) {
        return false;
    }
    if target.prefix {
        path_matches_prefix(path, &target.path)
    } else {
        path == target.path
    }
}

/// Host portion of a cache key, for tag purges.
pub fn cache_key_host(key: &str) -> Option<&str> {
    split_cache_key(key).map(|(host, _)| host)
}

fn split_cache_key(key: &str) -> Option<(&str, &str)> {
    let (_, rest) = key.split_once(':')?;
    let slash = rest.find('/')?;
    if slash == 0 || rest.as_bytes().get(slash - 1) != Some(&b':') {
        return None;
    }
    let host = &rest[..slash - 1];
    if host.is_empty() {
        return None;
    }
    Some((host, strip_vary(&rest[slash..])))
}

/// Drop trailing `|label=<16 hex chars>` vary components from the path.
fn strip_vary(path: &str) -> &str {
    let mut end = path.len();
    while let Some(pos) = path[..end].rfind('|') {
        let suffix = &path[pos + 1..end];
        let Some((label, hash)) = suffix.split_once('=') else {
            break;
        };
        if label.len() <= 16 && hash.len() == 16 && hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            end = pos;
        } else {
            break;
        }
    }
    &path[..end]
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    if path == prefix {
        return true;
    }
    let Some(rest) = path.strip_prefix(prefix) else {
        return false;
    };
    prefix.ends_with('/') || rest.starts_with('/') || rest.starts_with('?')
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
    async fn purge_matching(&self, targets: &[PurgeTarget]) -> u64;
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

/// Sharded LRU bookkeeping.
///
/// A single process-wide `Mutex<LruState>` made every L1 hit serialize on one
/// lock and allocate the key twice. Both costs scaled with core count, so the
/// cache became slower the more threads it served. The recency index is now
/// split into power-of-two shards selected by a hash of the key: a hit only
/// contends with keys that land in the same shard.
///
/// The global tick is a single atomic, so ordering across shards stays
/// comparable. Eviction still picks the globally oldest entry (the minimum of
/// each shard's oldest live record), which keeps exact-LRU victim selection
/// rather than degrading to per-shard LRU.
#[derive(Default)]
struct LruShard {
    pos: HashMap<Arc<str>, u64>,
    order: VecDeque<(Arc<str>, u64)>,
}

impl LruShard {
    /// Record an access. Reuses the key's existing `Arc` when the entry is
    /// already tracked, so a repeated hit allocates nothing.
    fn touch(&mut self, key: &str, tick: u64) {
        let arc: Arc<str> = self
            .pos
            .get_key_value(key)
            .map(|(existing, _)| existing.clone())
            .unwrap_or_else(|| Arc::from(key));
        self.pos.insert(arc.clone(), tick);
        self.order.push_back((arc, tick));
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

    /// Oldest live record, discarding superseded queue entries on the way.
    /// Does not remove the entry, so the caller can compare shards first.
    fn peek_victim(&mut self) -> Option<(u64, Arc<str>)> {
        loop {
            let (key, tick) = match self.order.front() {
                Some((key, tick)) => (key.clone(), *tick),
                None => return None,
            };
            if self.pos.get(&key).is_some_and(|cur| *cur == tick) {
                return Some((tick, key));
            }
            self.order.pop_front();
        }
    }

    fn pop_victim(&mut self) -> Option<Arc<str>> {
        while let Some((key, tick)) = self.order.pop_front() {
            if self.pos.get(&key).is_some_and(|cur| *cur == tick) {
                self.pos.remove(&key);
                return Some(key);
            }
        }
        None
    }

    fn clear(&mut self) {
        self.pos.clear();
        self.order.clear();
    }
}

fn shard_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .next_power_of_two()
        .clamp(8, 64)
}

fn shard_hash(key: &str) -> usize {
    // FNV-1a: cheap, no dependency, and only used to pick a shard.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in key.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash as usize
}

#[derive(Clone)]
pub struct MemoryCache {
    inner: Arc<DashMap<String, TimedEntry>>,
    /// Recency index, sharded to keep L1 hits off a process-wide lock.
    lru: Arc<[Mutex<LruShard>]>,
    /// Monotonic access counter shared by all shards so cross-shard age is
    /// comparable when eviction picks a victim.
    tick: Arc<AtomicU64>,
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
        let shards: Vec<Mutex<LruShard>> = (0..shard_count())
            .map(|_| Mutex::new(LruShard::default()))
            .collect();
        Self {
            inner: Arc::new(DashMap::new()),
            lru: Arc::from(shards),
            tick: Arc::new(AtomicU64::new(0)),
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

    fn shard(&self, key: &str) -> &Mutex<LruShard> {
        // `lru` is never empty and its length is a power of two.
        &self.lru[shard_hash(key) % self.lru.len()]
    }

    fn touch(&self, key: &str) {
        let tick = self.tick.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut shard) = self.shard(key).lock() {
            shard.touch(key, tick);
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
        if let Ok(mut shard) = self.shard(key).lock() {
            shard.remove(key);
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
            match self.next_victim() {
                Some(key) => {
                    self.remove_key(&key);
                }
                None => {
                    // Recency bookkeeping out of sync (entries inserted
                    // elsewhere): drop an arbitrary entry so the byte/count
                    // ceiling still holds.
                    match self.inner.iter().next().map(|e| e.key().clone()) {
                        Some(key) => {
                            self.remove_key(&key);
                        }
                        None => break,
                    }
                }
            }
        }
    }

    /// Globally oldest tracked key: the shard with the smallest head tick wins,
    /// so sharding does not weaken LRU quality.
    fn next_victim(&self) -> Option<String> {
        // Retry a few times: between peeking and claiming, a concurrent hit may
        // promote the entry we selected, leaving that shard with no victim.
        for _ in 0..4 {
            let mut best: Option<(u64, usize)> = None;
            for (index, shard) in self.lru.iter().enumerate() {
                let Ok(mut guard) = shard.lock() else {
                    continue;
                };
                let Some((tick, _)) = guard.peek_victim() else {
                    continue;
                };
                if best.is_none_or(|(best_tick, _)| tick < best_tick) {
                    best = Some((tick, index));
                }
            }
            let (_, index) = best?;
            if let Ok(mut guard) = self.lru[index].lock() {
                if let Some(claimed) = guard.pop_victim() {
                    return Some(claimed.to_string());
                }
            }
        }
        None
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

    /// Local presence probe that never touches the recency index.
    ///
    /// Callers use this to decide whether a cross-node single-flight lock is
    /// needed. Routing it through `get_result` promoted the entry and took the
    /// LRU lock on every cacheable request, which is exactly the cost this
    /// probe is supposed to avoid.
    async fn has_local(&self, key: &str) -> bool {
        let Some(item) = self.inner.get(key) else {
            return false;
        };
        let now = Instant::now();
        now <= item.stale_until
    }

    async fn set(&self, key: &str, entry: CacheEntry, ttl_secs: u64) {
        self.set_with_swr(key, entry, ttl_secs, 0).await;
    }

    async fn set_with_swr(&self, key: &str, mut entry: CacheEntry, fresh_secs: u64, swr_secs: u64) {
        let now = Instant::now();
        // Clamp here as well as in the policy layer: this is the last point
        // before the values become `Instant`/epoch deadlines, and a caller that
        // bypasses `decide_storage` must not be able to overflow them.
        let fresh_secs = clamp_ttl_secs(fresh_secs).max(1);
        let swr_secs = clamp_ttl_secs(swr_secs);
        let now_epoch = now_epoch_secs();
        entry.fresh_until_epoch_secs = now_epoch.saturating_add(fresh_secs);
        entry.stale_until_epoch_secs = now_epoch
            .saturating_add(fresh_secs)
            .saturating_add(swr_secs);
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
            fresh_until: instant_add(now, fresh_secs),
            stale_until: instant_add(instant_add(now, fresh_secs), swr_secs),
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
        for shard in self.lru.iter() {
            if let Ok(mut guard) = shard.lock() {
                guard.clear();
            }
        }
    }

    async fn purge_matching(&self, targets: &[PurgeTarget]) -> u64 {
        if targets.is_empty() {
            return 0;
        }
        let keys: Vec<String> = self
            .inner
            .iter()
            .filter(|e| targets.iter().any(|t| cache_key_matches(e.key(), t)))
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
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        let keys: Vec<String> = self
            .inner
            .iter()
            .filter(|e| {
                (domain.is_empty()
                    || cache_key_host(e.key()).is_some_and(|h| h.eq_ignore_ascii_case(&domain)))
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
    async fn oversized_ttl_is_clamped() {
        let c = MemoryCache::new(10);
        c.set_with_swr("k", entry("a"), u64::MAX, u64::MAX).await;
        let CacheGetResult::Hit(e) = c.get_result("k").await else {
            panic!("expected hit");
        };
        let now = now_epoch_secs();
        assert!(e.fresh_until_epoch_secs > now, "deadline must be in the future");
        assert!(
            e.fresh_until_epoch_secs <= now + MAX_TTL_SECS,
            "deadline escaped the clamp: {}",
            e.fresh_until_epoch_secs
        );
        assert!(e.stale_until_epoch_secs >= e.fresh_until_epoch_secs);
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
        c.set("GET:a.example:/x", entry("a"), 60).await;
        c.set("GET:b.example:/x", entry("b"), 60).await;
        let target = PurgeTarget::new("a.example", "/x", false).unwrap();
        assert_eq!(c.purge_matching(&[target]).await, 1);
        assert_eq!(c.len().await, 1);
    }

    #[test]
    fn purge_target_is_host_and_path_scoped() {
        let key = "GET:example.com:/small";
        let exact = PurgeTarget::new("example.com", "/small", false).unwrap();
        assert!(cache_key_matches(key, &exact));
        // Query strings identify a different representation.
        assert!(!cache_key_matches("GET:example.com:/small?q=1", &exact));
        // A different tenant whose name merely contains the host must not match.
        assert!(!cache_key_matches("GET:myexample.com:/small", &exact));
        // Prefixes stop at a path boundary.
        let prefix = PurgeTarget::new("example.com", "/small", true).unwrap();
        assert!(cache_key_matches(key, &prefix));
        assert!(cache_key_matches("GET:example.com:/small/a", &prefix));
        assert!(!cache_key_matches("GET:example.com:/smaller", &prefix));
        // Vary suffixes belong to the same representation.
        assert!(cache_key_matches(
            "GET:example.com:/small|lang=0123456789abcdef",
            &exact
        ));
        // Domain-wide targets used on config changes cover every path.
        let domain = PurgeTarget::for_domain("example.com").unwrap();
        assert!(cache_key_matches("GET:example.com:/anything?x=1", &domain));
        assert!(!cache_key_matches("GET:other.com:/anything", &domain));
        // A bare "/" URL must not become a cross-tenant purge.
        let root = PurgeTarget::new("example.com", "/", false).unwrap();
        assert!(!cache_key_matches("GET:other.com:/", &root));
    }

    #[tokio::test]
    async fn unbounded_when_capacity_zero() {
        let c = MemoryCache::new(0);
        for i in 0..100 {
            c.set(&format!("k{i}"), entry("x"), 60).await;
        }
        assert_eq!(c.len().await, 100);
    }

    /// Sharding the recency index must not change which entry is evicted: the
    /// victim is still the globally oldest access, even when keys land in
    /// different shards.
    #[tokio::test]
    async fn sharded_lru_still_evicts_globally_oldest() {
        let c = MemoryCache::new(3);
        // Spread keys across shards by construction; the hash decides placement.
        c.set("a", entry("a"), 60).await;
        c.set("b", entry("b"), 60).await;
        c.set("c", entry("c"), 60).await;
        // Touch b and c so `a` is the global LRU regardless of its shard.
        let _ = c.get_result("b").await;
        let _ = c.get_result("c").await;
        c.set("d", entry("d"), 60).await;
        assert_eq!(c.len().await, 3);
        assert!(
            matches!(c.get_result("a").await, CacheGetResult::Miss),
            "globally oldest entry must be the eviction victim"
        );
        for key in ["b", "c", "d"] {
            assert!(
                matches!(c.get_result(key).await, CacheGetResult::Hit(_)),
                "recently used entry {key} must survive"
            );
        }
    }

    /// `has_local` exists to avoid promoting an entry: it must not refresh
    /// recency, or the probe would silently defeat LRU ordering.
    #[tokio::test]
    async fn has_local_does_not_promote() {
        let c = MemoryCache::new(2);
        c.set("a", entry("a"), 60).await;
        c.set("b", entry("b"), 60).await;
        // `a` is the oldest; probing it must not make it younger than `b`.
        assert!(c.has_local("a").await);
        c.set("c", entry("c"), 60).await;
        assert!(
            matches!(c.get_result("a").await, CacheGetResult::Miss),
            "has_local must not refresh recency"
        );
        assert!(matches!(c.get_result("b").await, CacheGetResult::Hit(_)));
        assert!(matches!(c.get_result("c").await, CacheGetResult::Hit(_)));
    }

    #[tokio::test]
    async fn has_local_reports_presence_and_expiry() {
        let c = MemoryCache::new(10);
        assert!(!c.has_local("missing").await);
        c.set_with_swr("k", entry("a"), 1, 1).await;
        assert!(c.has_local("k").await, "fresh entry must be present");
        // Past fresh+stale the entry is no longer usable without a refetch.
        tokio::time::sleep(Duration::from_millis(2100)).await;
        assert!(!c.has_local("k").await);
    }
}
