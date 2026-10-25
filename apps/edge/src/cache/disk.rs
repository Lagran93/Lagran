//! Persistent file cache on disk.
//!
//! Layout: `<root>/<xx>/<hash>.meta` (JSON) + `<root>/<xx>/<hash>.bin` (body).
//! Writes are atomic (temp file + rename), the meta file carries the cache key
//! so prefix purges do not have to clear the whole cache, and overflow evicts
//! the oldest files instead of wiping the directory.

use async_trait::async_trait;
use bytes::Bytes;
use lagran_cache::{CacheBackend, CacheEntry, CacheGetResult};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::sync::Mutex;

use super::policy::stable_hash_str;

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
            self.remove_files(&meta_path, &bin_path, meta_bytes.len() as u64).await;
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
            self.used_bytes.fetch_sub(freed.min(self.used_bytes.load(Ordering::Relaxed)), Ordering::Relaxed);
            self.entries.fetch_sub(1, Ordering::Relaxed);
        }
        let _ = fs::remove_file(bin_path).await;
    }

    /// Drop oldest files (by mtime) until usage is back under 90% of the cap.
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
        let mut files = Vec::new();
        let mut stack = vec![self.root.clone()];
        while let Some(dir) = stack.pop() {
            let mut rd = match fs::read_dir(&dir).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            while let Ok(Some(ent)) = rd.next_entry().await {
                let Ok(ft) = ent.file_type().await else { continue };
                if ft.is_dir() {
                    stack.push(ent.path());
                } else if ft.is_file() {
                    let Ok(meta) = ent.metadata().await else { continue };
                    let mtime = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    files.push((mtime, meta.len(), ent.path()));
                }
            }
        }
        files.sort_by_key(|(mtime, _, _)| *mtime);
        let mut freed = 0u64;
        let mut victims = 0usize;
        for (_, len, path) in files {
            if used.saturating_sub(freed) <= target {
                break;
            }
            if fs::remove_file(&path).await.is_ok() {
                freed += len;
                victims += 1;
            }
        }
        self.used_bytes.fetch_sub(freed, Ordering::Relaxed);
        self.entries.fetch_sub(victims, Ordering::Relaxed);
        tracing::warn!(freed, victims, "disk cache evicted oldest entries");
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
    let tmp = path.with_extension(format!(
        "{}.tmp{}",
        path.extension().and_then(|e| e.to_str()).unwrap_or("bin"),
        std::process::id()
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
            fresh_until: now + fresh,
            stale_until: now + fresh + swr_secs,
            stored_at: entry.stored_at_epoch_secs.max(now),
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
        self.used_bytes
            .fetch_add(body_len + meta_bytes.len() as u64, Ordering::Relaxed);
        if replaced == 0 {
            self.entries.fetch_add(1, Ordering::Relaxed);
        }
        self.evict_overflow().await;
    }

    async fn delete(&self, key: &str) {
        let (meta_path, bin_path) = self.paths_for_key(key);
        let meta_len = fs::metadata(&meta_path)
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        self.remove_files(&meta_path, &bin_path, meta_len).await;
    }

    async fn clear(&self) {
        let _ = fs::remove_dir_all(&self.root).await;
        let _ = fs::create_dir_all(&self.root).await;
        self.used_bytes.store(0, Ordering::Relaxed);
        self.entries.store(0, Ordering::Relaxed);
    }

    /// Remove entries whose cache key contains any of the patterns.
    /// An empty pattern list clears the cache.
    async fn purge_matching(&self, patterns: &[String]) -> u64 {
        if patterns.is_empty() {
            let n = self.len().await as u64;
            self.clear().await;
            return n;
        }
        let patterns: Vec<&str> = patterns
            .iter()
            .map(|p| p.as_str())
            .filter(|p| !p.is_empty())
            .collect();
        if patterns.is_empty() {
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
                let Ok(ft) = ent.file_type().await else { continue };
                if ft.is_dir() {
                    stack.push(ent.path());
                    continue;
                }
                let path = ent.path();
                if path.extension().is_none_or(|e| e != "meta") {
                    continue;
                }
                let Ok(bytes) = fs::read(&path).await else { continue };
                let Ok(meta) = serde_json::from_slice::<DiskMeta>(&bytes) else {
                    continue;
                };
                if meta.key.is_empty() {
                    continue;
                }
                if patterns.iter().any(|p| meta.key.contains(p)) {
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
                            .set_with_swr(key, e.clone(), fresh_left.max(1), stale_left.saturating_sub(fresh_left))
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

    async fn purge_matching(&self, patterns: &[String]) -> u64 {
        let a = self.mem.purge_matching(patterns).await;
        let b = self.disk.purge_matching(patterns).await;
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
    async fn persist_roundtrip_and_purge_by_prefix() {
        let dir = std::env::temp_dir().join(format!("lagran-disk-{}", std::process::id()));
        let cache = DiskCache::new(&dir, 1024 * 1024).await.unwrap();
        let entry = CacheEntry::new(
            200,
            vec![("content-type".into(), "text/plain".into())],
            Bytes::from_static(b"body"),
        );
        cache.set_with_swr("GET:a.test/x", entry.clone(), 60, 30).await;
        cache.set_with_swr("GET:b.test/y", entry, 60, 30).await;
        assert_eq!(cache.len().await, 2);

        match cache.get_result("GET:a.test/x").await {
            CacheGetResult::Hit(e) => assert_eq!(&e.body[..], b"body"),
            other => panic!("expected hit, got {other:?}"),
        }

        assert_eq!(cache.purge_matching(&["a.test".into()]).await, 1);
        assert_eq!(cache.len().await, 1);
        assert!(matches!(
            cache.get_result("GET:b.test/y").await,
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
}
