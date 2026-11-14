//! Persistent file cache on disk.
//!
//! Layout: `<root>/<xx>/<hash>.meta` (JSON) + `<root>/<xx>/<hash>.bin` (body).
//! Writes are atomic (temp file + rename), the meta file carries the cache key
//! so prefix purges do not have to clear the whole cache, and overflow evicts
//! the oldest files instead of wiping the directory.

use async_trait::async_trait;
use bytes::Bytes;
use lagran_cache::{CacheBackend, CacheEntry, CacheGetResult, PurgeTarget};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::sync::Mutex;

use super::policy::stable_hash_str;

/// How many directory entries one eviction pass may examine.
///
/// Eviction runs on the write path, so its cost must not scale with cache size.
/// The previous implementation walked the whole tree, stat'ed every file and
/// sorted all of them while holding `evict_lock`, which stalled every
/// concurrent writer once the cache was full. A pass now walks shard
/// directories from a rotating cursor and stops after this many entries; a
/// cache that is still over budget is finished by the next write.
///
/// Sized against [`EVICT_VICTIM_BUDGET`]: a sample this large reliably yields
/// enough old entries to fill the victim budget, while staying inside a single
/// millisecond on local storage.
const EVICT_ENTRY_BUDGET: usize = 256;

/// How many entries one eviction pass may delete.
///
/// Each victim costs two `unlink` calls. Deleting a thousand entries in one
/// pass turned a single `set` into a ~100 ms stall on overlay/tmpfs, because
/// the write path waits for eviction to finish. Capping the victims keeps the
/// per-write cost predictable; a cache that is still over budget is trimmed by
/// the following writes.
const EVICT_VICTIM_BUDGET: usize = 64;

#[derive(Serialize, Deserialize)]
struct DiskMeta {
    /// Cache key this entry belongs to (used by purge). Absent on legacy files.
    #[serde(default)]
    key: String,
    status: u16,
    headers: Vec<(String, String)>,
    /// Fresh until (unix secs)
    fresh_until: u64,
    /// Stale usable until
    stale_until: u64,
    #[serde(default)]
    stored_at: u64,
}

pub struct DiskCache {
    root: PathBuf,
    max_bytes: u64,
    used_bytes: AtomicU64,
    entries: AtomicUsize,
    /// Serialises eviction scans only; normal writes do not take this lock.
    evict_lock: Mutex<()>,
    /// Shard index the next eviction pass starts from, so successive passes
    /// cover the whole tree without any single pass walking all of it.
    evict_cursor: AtomicUsize,
}

impl DiskCache {
    pub async fn new(dir: impl AsRef<Path>, max_bytes: u64) -> anyhow::Result<Self> {
        let root = dir.as_ref().to_path_buf();
        fs::create_dir_all(&root).await?;
        let (used, count) = scan_usage(&root).await.unwrap_or((0, 0));
        tracing::info!(path = %root.display(), used, count, max_bytes, "disk cache ready");
        Ok(Self {
            root,
            max_bytes,
            used_bytes: AtomicU64::new(used),
            entries: AtomicUsize::new(count),
            evict_lock: Mutex::new(()),
            evict_cursor: AtomicUsize::new(0),
        })
    }

    fn paths_for_key(&self, key: &str) -> (PathBuf, PathBuf) {
        let hash = stable_hash_str(key);
        let sub = format!("{:02x}", hash % 256);
        let dir = self.root.join(sub);
        let base = format!("{hash:016x}");
        (
            dir.join(format!("{base}.meta")),
            dir.join(format!("{base}.bin")),
        )
    }

    /// Read entry plus its remaining fresh/stale lifetime in seconds.
    async fn get_full(&self, key: &str) -> (CacheGetResult, u64, u64) {
        let (meta_path, bin_path) = self.paths_for_key(key);
        let meta_bytes = match fs::read(&meta_path).await {
            Ok(b) => b,
            Err(_) => return (CacheGetResult::Miss, 0, 0),
        };
        let meta: DiskMeta = match serde_json::from_slice(&meta_bytes) {
            Ok(m) => m,
            Err(_) => return (CacheGetResult::Miss, 0, 0),
        };
        // Keys can hash-collide only across sub-dirs; verify when recorded.
        if !meta.key.is_empty() && meta.key != key {
            return (CacheGetResult::Miss, 0, 0);
        }
        let now = now_unix();
        if now > meta.stale_until {
            self.remove_files(&meta_path, &bin_path, meta_bytes.len() as u64)
                .await;
            return (CacheGetResult::Expired, 0, 0);
        }
        let body = match fs::read(&bin_path).await {
            Ok(b) => b,
            Err(_) => return (CacheGetResult::Miss, 0, 0),
        };
        let entry = CacheEntry {
            status: meta.status,
            headers: meta.headers,
            body: Bytes::from(body),
            stored_at_epoch_secs: if meta.stored_at > 0 {
                meta.stored_at
            } else {
                meta.fresh_until.saturating_sub(60)
            },
            fresh_until_epoch_secs: meta.fresh_until,
            stale_until_epoch_secs: meta.stale_until,
        };
        let fresh_left = meta.fresh_until.saturating_sub(now);
        let stale_left = meta.stale_until.saturating_sub(now);
        if now <= meta.fresh_until {
            (CacheGetResult::Hit(entry), fresh_left, stale_left)
        } else {
            (CacheGetResult::Stale(entry), fresh_left, stale_left)
        }
    }

    async fn remove_files(&self, meta_path: &Path, bin_path: &Path, meta_len: u64) {
        let mut freed = meta_len;
        if let Ok(m) = fs::metadata(bin_path).await {
            freed += m.len();
        }
        if fs::remove_file(meta_path).await.is_ok() || fs::remove_file(bin_path).await.is_ok() {
            // Saturating updates: `fetch_sub` wraps to `u64::MAX` when two
            // concurrent removals account for the same bytes, which would make
            // `used_bytes` permanently over budget and `len()` report nonsense.
            self.used_bytes
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                    Some(used.saturating_sub(freed))
                })
                .ok();
            self.entries
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                    Some(n.saturating_sub(1))
                })
                .ok();
        }
        let _ = fs::remove_file(bin_path).await;
    }

    /// Evict least-recently-used entries until usage is back under 90% of the
    /// cap, examining at most [`EVICT_ENTRY_BUDGET`] directory entries per pass.
    ///
    /// The pass walks shard directories starting at a rotating cursor, so it
    /// samples the cache instead of rescanning it: memory and latency stay
    /// bounded no matter how many files are on disk. If the cache is still over
    /// budget afterwards, the next write continues where this one stopped.
    ///
    /// Entries are removed as a `(meta, bin)` pair. Deleting the two files
    /// independently (as the previous version did) could leave an orphaned
    /// body or sidecar behind and drift `entries` below the real file count.
    async fn evict_overflow(&self) {
        if self.max_bytes == 0 || self.used_bytes.load(Ordering::Relaxed) <= self.max_bytes {
            return;
        }
        let _guard = self.evict_lock.lock().await;
        // Re-check under the lock: another task may have evicted already.
        let used = self.used_bytes.load(Ordering::Relaxed);
        if used <= self.max_bytes {
            return;
        }
        let target = self.max_bytes / 10 * 9;

        let shards = 256usize;
        let start = self.evict_cursor.load(Ordering::Relaxed) % shards;
        // Collect the sample on a blocking thread. Each candidate needs a
        // `read_dir` entry plus one `stat` for its body; awaiting those one at
        // a time on the runtime turned a 2048-entry sample into ~100 ms of
        // sequential syscalls. `spawn_blocking` runs them back-to-back without
        // involving the async scheduler, and keeps the shard walk off the
        // request threads.
        let root = self.root.clone();
        let sample = tokio::task::spawn_blocking(move || {
            let mut candidates: Vec<(u64, u64, PathBuf, PathBuf)> = Vec::new();
            let mut examined = 0usize;
            let mut cursor = start;
            'scan: for offset in 0..shards {
                let shard = (start + offset) % shards;
                cursor = shard;
                let dir = root.join(format!("{shard:02x}"));
                let Ok(rd) = std::fs::read_dir(&dir) else {
                    continue;
                };
                for ent in rd.flatten() {
                    if examined >= EVICT_ENTRY_BUDGET {
                        break 'scan;
                    }
                    examined += 1;
                    let path = ent.path();
                    // Only sidecars are considered; the body path is derived
                    // from it so a victim is always a complete pair.
                    if path.extension().is_none_or(|e| e != "meta") {
                        continue;
                    }
                    let Ok(meta) = ent.metadata() else {
                        continue;
                    };
                    let mtime = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let bin = path.with_extension("bin");
                    let bin_len = std::fs::metadata(&bin).map(|m| m.len()).unwrap_or(0);
                    candidates.push((mtime, bin_len + meta.len(), path, bin));
                }
            }
            (candidates, examined, cursor)
        })
        .await
        .unwrap_or_default();
        let (mut candidates, examined, cursor) = sample;
        self.evict_cursor
            .store((cursor + 1) % shards, Ordering::Relaxed);
        // The sampled entries are evicted oldest-first; that approximates LRU
        // across the sample without needing a full sort of the cache.
        candidates.sort_unstable_by_key(|(mtime, _, _, _)| *mtime);

        let mut freed = 0u64;
        let mut victims = 0usize;
        for (_, size, meta_path, bin_path) in candidates {
            if used.saturating_sub(freed) <= target || victims >= EVICT_VICTIM_BUDGET {
                break;
            }
            let meta_removed = fs::remove_file(&meta_path).await.is_ok();
            let bin_removed = fs::remove_file(&bin_path).await.is_ok();
            if meta_removed || bin_removed {
                freed += size;
                victims += 1;
            }
        }
        self.used_bytes
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |u| {
                Some(u.saturating_sub(freed))
            })
            .ok();
        self.entries
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_sub(victims))
            })
            .ok();
        if victims > 0 {
            tracing::warn!(
                freed,
                victims,
                examined,
                remaining = self.used_bytes.load(Ordering::Relaxed),
                "disk cache evicted oldest sampled entries"
            );
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn scan_usage(root: &Path) -> anyhow::Result<(u64, usize)> {
    let mut total = 0u64;
    let mut count = 0usize;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut rd = match fs::read_dir(&dir).await {
            Ok(r) => r,
            Err(_) => continue,
        };
        while let Ok(Some(ent)) = rd.next_entry().await {
            let ft = ent.file_type().await?;
            if ft.is_dir() {
                stack.push(ent.path());
            } else if ft.is_file() {
                if let Ok(meta) = ent.metadata().await {
                    total += meta.len();
                    if meta.len() > 0 && ent.path().extension().is_some_and(|e| e == "bin") {
                        count += 1;
                    }
                }
            }
        }
    }
    Ok((total, count))
}

async fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    // `tmp<pid>` collided for every concurrent writer in this process: two
    // requests storing the same key (or a purge racing a write) shared one temp
    // file and could rename a half-written body into place. A per-write sequence
    // makes each staging file unique.
    static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = path.with_extension(format!(
        "{}.tmp{}-{}",
        path.extension().and_then(|e| e.to_str()).unwrap_or("bin"),
        std::process::id(),
        seq
    ));
    fs::write(&tmp, data).await?;
    match fs::rename(&tmp, path).await {
        Ok(()) => Ok(()),
        Err(e) => {
            // Some filesystems (9p/DrvFs) refuse rename-over-existing.
            let _ = fs::remove_file(path).await;
            let retry = fs::rename(&tmp, path).await;
            if retry.is_err() {
                let _ = fs::remove_file(&tmp).await;
            }
            retry.map_err(|_| e)
        }
    }
}

#[async_trait]
impl CacheBackend for DiskCache {
    async fn get_result(&self, key: &str) -> CacheGetResult {
        self.get_full(key).await.0
    }

    async fn set(&self, key: &str, entry: CacheEntry, ttl_secs: u64) {
        self.set_with_swr(key, entry, ttl_secs, 0).await;
    }

    async fn set_with_swr(&self, key: &str, entry: CacheEntry, fresh_secs: u64, swr_secs: u64) {
        let (meta_path, bin_path) = self.paths_for_key(key);
        if let Some(parent) = meta_path.parent() {
            if let Err(e) = fs::create_dir_all(parent).await {
                tracing::warn!(error = %e, "disk cache mkdir failed");
                return;
            }
        }
        // Account for the replaced copy, if any.
        let mut replaced = 0u64;
        if let Ok(m) = fs::metadata(&bin_path).await {
            replaced += m.len();
        }
        if let Ok(m) = fs::metadata(&meta_path).await {
            replaced += m.len();
        }

        let now = now_unix();
        let fresh = fresh_secs.max(1);
        let meta = DiskMeta {
            key: key.to_string(),
            status: entry.status,
            headers: entry.headers.clone(),
            fresh_until: now.saturating_add(fresh),
            stale_until: now.saturating_add(fresh).saturating_add(swr_secs),
            stored_at: if entry.stored_at_epoch_secs == 0 {
                now
            } else {
                entry.stored_at_epoch_secs
            },
        };
        let meta_bytes = match serde_json::to_vec(&meta) {
            Ok(b) => b,
            Err(_) => return,
        };
        let body_len = entry.body.len() as u64;
        if let Err(e) = write_atomic(&bin_path, &entry.body).await {
            tracing::warn!(error = %e, "disk cache write body failed");
            return;
        }
        if let Err(e) = write_atomic(&meta_path, &meta_bytes).await {
            tracing::warn!(error = %e, "disk cache write meta failed");
            let _ = fs::remove_file(&bin_path).await;
            return;
        }
        // Replace, do not accumulate: the old files are gone after the write,
        // so adding the new size on top of the already-counted old one made
        // `used_bytes` drift upwards until eviction ran on every write.
        let added = body_len.saturating_add(meta_bytes.len() as u64);
        self.used_bytes
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                Some(used.saturating_sub(replaced).saturating_add(added))
            })
            .ok();
        if replaced == 0 {
            self.entries.fetch_add(1, Ordering::Relaxed);
        }
        self.evict_overflow().await;
    }

    async fn delete(&self, key: &str) {
        let (meta_path, bin_path) = self.paths_for_key(key);
        let meta_len = fs::metadata(&meta_path).await.map(|m| m.len()).unwrap_or(0);
        self.remove_files(&meta_path, &bin_path, meta_len).await;
    }

    async fn clear(&self) {
        let _ = fs::remove_dir_all(&self.root).await;
        let _ = fs::create_dir_all(&self.root).await;
        self.used_bytes.store(0, Ordering::Relaxed);
        self.entries.store(0, Ordering::Relaxed);
    }

    /// Remove entries matching any structured purge target.
    async fn purge_matching(&self, targets: &[PurgeTarget]) -> u64 {
        if targets.is_empty() {
            return 0;
        }

        let mut victims = Vec::new();
        let mut stack = vec![self.root.clone()];
        while let Some(dir) = stack.pop() {
            let mut rd = match fs::read_dir(&dir).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            while let Ok(Some(ent)) = rd.next_entry().await {
                let Ok(ft) = ent.file_type().await else {
                    continue;
                };
                if ft.is_dir() {
                    stack.push(ent.path());
                    continue;
                }
                let path = ent.path();
                if path.extension().is_none_or(|e| e != "meta") {
                    continue;
                }
                let Ok(bytes) = fs::read(&path).await else {
                    continue;
                };
                let Ok(meta) = serde_json::from_slice::<DiskMeta>(&bytes) else {
                    continue;
                };
                if meta.key.is_empty() {
                    continue;
                }
                if targets
                    .iter()
                    .any(|target| lagran_cache::cache_key_matches(&meta.key, target))
                {
                    let bin = path.with_extension("bin");
                    victims.push((path, bin, bytes.len() as u64));
                }
            }
        }

        let mut removed = 0u64;
        for (meta_path, bin_path, meta_len) in victims {
            self.remove_files(&meta_path, &bin_path, meta_len).await;
            removed += 1;
        }
        tracing::info!(removed, "disk cache purge matched keys");
        removed
    }

    async fn purge_tags(&self, tags: &[String], domain: &str) -> u64 {
        let wanted: Vec<String> = tags.iter().map(|t| t.to_ascii_lowercase()).collect();
        if wanted.is_empty() {
            return 0;
        }
        let domain = domain.to_ascii_lowercase();
        let mut victims = Vec::new();
        let mut stack = vec![self.root.clone()];
        while let Some(dir) = stack.pop() {
            let mut rd = match fs::read_dir(&dir).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            while let Ok(Some(ent)) = rd.next_entry().await {
                let Ok(ft) = ent.file_type().await else {
                    continue;
                };
                if ft.is_dir() {
                    stack.push(ent.path());
                    continue;
                }
                let path = ent.path();
                if path.extension().is_none_or(|e| e != "meta") {
                    continue;
                }
                let Ok(bytes) = fs::read(&path).await else {
                    continue;
                };
                let Ok(meta) = serde_json::from_slice::<DiskMeta>(&bytes) else {
                    continue;
                };
                if !domain.is_empty()
                    && !lagran_cache::cache_key_host(&meta.key)
                        .is_some_and(|host| host.eq_ignore_ascii_case(&domain))
                {
                    continue;
                }
                let matched = meta.headers.iter().any(|(name, value)| {
                    if !["surrogate-key", "cache-tag", "x-cache-tag"]
                        .iter()
                        .any(|n| name.eq_ignore_ascii_case(n))
                    {
                        return false;
                    }
                    value
                        .split(|c: char| c == ',' || c.is_whitespace())
                        .map(str::trim)
                        .filter(|t| !t.is_empty())
                        .any(|t| wanted.iter().any(|w| w == &t.to_ascii_lowercase()))
                });
                if matched {
                    let bin = path.with_extension("bin");
                    victims.push((path, bin, bytes.len() as u64));
                }
            }
        }
        let mut removed = 0u64;
        for (meta_path, bin_path, meta_len) in victims {
            self.remove_files(&meta_path, &bin_path, meta_len).await;
            removed += 1;
        }
        tracing::info!(removed, "disk cache purge matched tags");
        removed
    }

    async fn len(&self) -> usize {
        self.entries.load(Ordering::Relaxed)
    }
}

/// L1 memory + L2 disk. Disk hits are promoted into memory with the remaining
/// freshness of the persisted entry (rather than a fixed TTL).
pub struct HybridCache {
    mem: Arc<lagran_cache::MemoryCache>,
    disk: Arc<DiskCache>,
}

impl HybridCache {
    pub fn new(mem: Arc<lagran_cache::MemoryCache>, disk: Arc<DiskCache>) -> Self {
        Self { mem, disk }
    }
}

#[async_trait]
impl CacheBackend for HybridCache {
    async fn get_result(&self, key: &str) -> CacheGetResult {
        match self.mem.get_result(key).await {
            CacheGetResult::Hit(e) => CacheGetResult::Hit(e),
            CacheGetResult::Stale(e) => CacheGetResult::Stale(e),
            other => {
                let (disk_res, fresh_left, stale_left) = self.disk.get_full(key).await;
                match disk_res {
                    CacheGetResult::Hit(e) => {
                        self.mem
                            .set_with_swr(
                                key,
                                e.clone(),
                                fresh_left.max(1),
                                stale_left.saturating_sub(fresh_left),
                            )
                            .await;
                        CacheGetResult::Hit(e)
                    }
                    CacheGetResult::Stale(e) => CacheGetResult::Stale(e),
                    CacheGetResult::Expired => CacheGetResult::Expired,
                    CacheGetResult::Miss => {
                        if matches!(other, CacheGetResult::Expired) {
                            CacheGetResult::Expired
                        } else {
                            CacheGetResult::Miss
                        }
                    }
                }
            }
        }
    }

    async fn set(&self, key: &str, entry: CacheEntry, ttl_secs: u64) {
        self.set_with_swr(key, entry, ttl_secs, 0).await;
    }

    async fn set_with_swr(&self, key: &str, entry: CacheEntry, fresh_secs: u64, swr_secs: u64) {
        self.mem
            .set_with_swr(key, entry.clone(), fresh_secs, swr_secs)
            .await;
        self.disk
            .set_with_swr(key, entry, fresh_secs, swr_secs)
            .await;
    }

    async fn delete(&self, key: &str) {
        self.mem.delete(key).await;
        self.disk.delete(key).await;
    }

    async fn clear(&self) {
        self.mem.clear().await;
        self.disk.clear().await;
    }

    async fn purge_matching(&self, targets: &[PurgeTarget]) -> u64 {
        let a = self.mem.purge_matching(targets).await;
        let b = self.disk.purge_matching(targets).await;
        a + b
    }

    async fn purge_tags(&self, tags: &[String], domain: &str) -> u64 {
        let a = self.mem.purge_tags(tags, domain).await;
        let b = self.disk.purge_tags(tags, domain).await;
        a + b
    }

    async fn len(&self) -> usize {
        self.mem.len().await + self.disk.len().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn concurrent_writes_use_distinct_staging_files() {
        let dir = std::env::temp_dir().join(format!(
            "lagran-disk-race-{}-{}",
            std::process::id(),
            now_unix()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("x.bin");
        let (a, b) = tokio::join!(
            write_atomic(&path, b"aaaa"),
            write_atomic(&path, b"bbbb")
        );
        a.unwrap();
        b.unwrap();
        let body = tokio::fs::read(&path).await.unwrap();
        assert!(body == b"aaaa" || body == b"bbbb", "torn body: {body:?}");
        let mut entries = tokio::fs::read_dir(&dir).await.unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            assert_eq!(entry.path(), path, "staging file left behind");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn overwrite_keeps_used_bytes_exact() {
        let dir = std::env::temp_dir().join(format!(
            "lagran-disk-overwrite-{}-{}",
            std::process::id(),
            now_unix()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let cache = DiskCache::new(&dir, 64 * 1024 * 1024).await.unwrap();
        let key = "GET:overwrite.test:/x";
        let first = CacheEntry::new(200, vec![], Bytes::from(vec![1u8; 1000]));
        cache.set_with_swr(key, first, 60, 0).await;
        let after_first = cache.used_bytes.load(Ordering::Relaxed);
        let second = CacheEntry::new(200, vec![], Bytes::from(vec![2u8; 2000]));
        cache.set_with_swr(key, second, 60, 0).await;

        let (meta, bin) = cache.paths_for_key(key);
        let actual = std::fs::metadata(&meta).unwrap().len()
            + std::fs::metadata(&bin).unwrap().len();
        let used = cache.used_bytes.load(Ordering::Relaxed);
        assert_eq!(used, actual, "used_bytes must equal the files on disk");
        assert!(
            used < after_first + 2001,
            "overwrite must not add the new size on top of the old one"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn persist_roundtrip_and_purge_by_prefix() {
        let dir = std::env::temp_dir().join(format!("lagran-disk-{}", std::process::id()));
        let cache = DiskCache::new(&dir, 1024 * 1024).await.unwrap();
        let entry = CacheEntry::new(
            200,
            vec![("content-type".into(), "text/plain".into())],
            Bytes::from_static(b"body"),
        );
        cache
            .set_with_swr("GET:a.test:/x", entry.clone(), 60, 30)
            .await;
        cache.set_with_swr("GET:b.test:/y", entry, 60, 30).await;
        assert_eq!(cache.len().await, 2);

        match cache.get_result("GET:a.test:/x").await {
            CacheGetResult::Hit(e) => assert_eq!(&e.body[..], b"body"),
            other => panic!("expected hit, got {other:?}"),
        }

        let target = lagran_cache::PurgeTarget::new("a.test", "/x", false).unwrap();
        assert_eq!(cache.purge_matching(&[target]).await, 1);
        assert_eq!(cache.len().await, 1);
        assert!(matches!(
            cache.get_result("GET:b.test:/y").await,
            CacheGetResult::Hit(_)
        ));
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn overflow_evicts_oldest_not_everything() {
        let dir = std::env::temp_dir().join(format!("lagran-disk-evict-{}", std::process::id()));
        let cache = DiskCache::new(&dir, 4096).await.unwrap();
        let big = Bytes::from(vec![0u8; 1500]);
        for i in 0..6 {
            let e = CacheEntry::new(200, vec![], big.clone());
            cache.set(&format!("GET:a.test/{i}"), e, 60).await;
        }
        assert!(cache.len().await >= 2, "cache should retain recent entries");
        assert!(cache.used_bytes.load(Ordering::Relaxed) <= 4096 + 4096 / 4);
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    /// Incremental eviction must still converge: after enough writes the cache
    /// has to be back under the cap, not stuck just above it because each pass
    /// only sampled a slice of the tree.
    #[tokio::test]
    async fn incremental_eviction_converges_under_cap() {
        let dir = std::env::temp_dir().join(format!("lagran-disk-converge-{}", std::process::id()));
        let cap = 64 * 1024;
        let cache = DiskCache::new(&dir, cap).await.unwrap();
        let body = Bytes::from(vec![7u8; 4096]);
        // Many more objects than fit, so eviction has to run repeatedly.
        for i in 0..400 {
            let e = CacheEntry::new(200, vec![], body.clone());
            cache.set(&format!("GET:c.test/{i}"), e, 60).await;
        }
        assert!(
            cache.used_bytes.load(Ordering::Relaxed) <= cap,
            "usage must settle at or below the cap, got {}",
            cache.used_bytes.load(Ordering::Relaxed)
        );
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    /// Eviction removes a `.meta`/`.bin` pair, so no orphaned half-entries are
    /// left behind and the entry count matches the files on disk.
    #[tokio::test]
    async fn eviction_leaves_no_orphan_files() {
        let dir = std::env::temp_dir().join(format!("lagran-disk-orphan-{}", std::process::id()));
        let cache = DiskCache::new(&dir, 32 * 1024).await.unwrap();
        let body = Bytes::from(vec![1u8; 2048]);
        for i in 0..120 {
            let e = CacheEntry::new(200, vec![], body.clone());
            cache.set(&format!("GET:o.test/{i}"), e, 60).await;
        }

        let mut meta_files = 0usize;
        let mut bin_files = 0usize;
        let mut stack = vec![dir.clone()];
        while let Some(current) = stack.pop() {
            let mut rd = tokio::fs::read_dir(&current).await.unwrap();
            while let Some(ent) = rd.next_entry().await.unwrap() {
                let ft = ent.file_type().await.unwrap();
                if ft.is_dir() {
                    stack.push(ent.path());
                } else if ent.path().extension().is_some_and(|e| e == "meta") {
                    meta_files += 1;
                } else if ent.path().extension().is_some_and(|e| e == "bin") {
                    bin_files += 1;
                }
            }
        }
        assert_eq!(
            meta_files, bin_files,
            "every sidecar must have a body and vice versa"
        );
        assert_eq!(
            meta_files,
            cache.len().await,
            "entry count must match the number of sidecars"
        );
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
