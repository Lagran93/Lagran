//! Persistent file cache on disk

use async_trait::async_trait;
use bytes::Bytes;
use lagran_cache::{CacheBackend, CacheEntry, CacheGetResult};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::sync::Mutex;

#[derive(Serialize, Deserialize)]
struct DiskMeta {
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
    lock: Mutex<()>,
}

impl DiskCache {
    pub async fn new(dir: impl AsRef<Path>, max_bytes: u64) -> anyhow::Result<Self> {
        let root = dir.as_ref().to_path_buf();
        fs::create_dir_all(&root).await?;
        let used = scan_usage(&root).await.unwrap_or(0);
        tracing::info!(path = %root.display(), used, max_bytes, "disk cache ready");
        Ok(Self {
            root,
            max_bytes,
            used_bytes: AtomicU64::new(used),
            lock: Mutex::new(()),
        })
    }

    fn paths_for_key(&self, key: &str) -> (PathBuf, PathBuf) {
        let hash = simple_hash(key);
        let sub = format!("{:02x}", hash % 256);
        let dir = self.root.join(sub);
        let base = format!("{:016x}", hash);
        (
            dir.join(format!("{base}.meta")),
            dir.join(format!("{base}.bin")),
        )
    }
}

fn simple_hash(s: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn scan_usage(root: &Path) -> anyhow::Result<u64> {
    let mut total = 0u64;
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
                }
            }
        }
    }
    Ok(total)
}

#[async_trait]
impl CacheBackend for DiskCache {
    async fn get_result(&self, key: &str) -> CacheGetResult {
        let (meta_path, bin_path) = self.paths_for_key(key);
        let meta_bytes = match fs::read(&meta_path).await {
            Ok(b) => b,
            Err(_) => return CacheGetResult::Miss,
        };
        let meta: DiskMeta = match serde_json::from_slice(&meta_bytes) {
            Ok(m) => m,
            Err(_) => return CacheGetResult::Miss,
        };
        let now = now_unix();
        if now > meta.stale_until {
            let _ = fs::remove_file(&meta_path).await;
            let _ = fs::remove_file(&bin_path).await;
            return CacheGetResult::Expired;
        }
        let body = match fs::read(&bin_path).await {
            Ok(b) => b,
            Err(_) => return CacheGetResult::Miss,
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
        if now <= meta.fresh_until {
            CacheGetResult::Hit(entry)
        } else {
            CacheGetResult::Stale(entry)
        }
    }

    async fn set(&self, key: &str, entry: CacheEntry, ttl_secs: u64) {
        self.set_with_swr(key, entry, ttl_secs, 0).await;
    }

    async fn set_with_swr(&self, key: &str, entry: CacheEntry, fresh_secs: u64, swr_secs: u64) {
        let _guard = self.lock.lock().await;
        let (meta_path, bin_path) = self.paths_for_key(key);
        if let Some(parent) = meta_path.parent() {
            let _ = fs::create_dir_all(parent).await;
        }
        let now = now_unix();
        let fresh = fresh_secs.max(1);
        let meta = DiskMeta {
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
        if let Err(e) = fs::write(&bin_path, &entry.body).await {
            tracing::warn!(error = %e, "disk cache write body failed");
            return;
        }
        if let Err(e) = fs::write(&meta_path, &meta_bytes).await {
            tracing::warn!(error = %e, "disk cache write meta failed");
            let _ = fs::remove_file(&bin_path).await;
            return;
        }
        self.used_bytes
            .fetch_add(body_len + meta_bytes.len() as u64, Ordering::Relaxed);
        // Simple eviction: if over max, clear all (MVP)
        if self.used_bytes.load(Ordering::Relaxed) > self.max_bytes {
            tracing::warn!("disk cache over capacity, clearing");
            let _ = fs::remove_dir_all(&self.root).await;
            let _ = fs::create_dir_all(&self.root).await;
            self.used_bytes.store(0, Ordering::Relaxed);
        }
    }

    async fn delete(&self, key: &str) {
        let (meta_path, bin_path) = self.paths_for_key(key);
        let _ = fs::remove_file(&meta_path).await;
        let _ = fs::remove_file(&bin_path).await;
    }

    async fn clear(&self) {
        let _ = fs::remove_dir_all(&self.root).await;
        let _ = fs::create_dir_all(&self.root).await;
        self.used_bytes.store(0, Ordering::Relaxed);
    }

    async fn purge_matching(&self, patterns: &[String]) -> u64 {
        // Full clear if any pattern (simple)
        if patterns.is_empty() {
            self.clear().await;
            return 1;
        }
        self.clear().await;
        1
    }

    async fn len(&self) -> usize {
        0 // expensive to count; optional
    }
}

/// L1 memory + L2 disk
pub struct HybridCache {
    mem: Arc<dyn CacheBackend>,
    disk: Arc<dyn CacheBackend>,
}

impl HybridCache {
    pub fn new(mem: Arc<dyn CacheBackend>, disk: Arc<dyn CacheBackend>) -> Self {
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
                // promote from disk
                match self.disk.get_result(key).await {
                    CacheGetResult::Hit(e) => {
                        self.mem.set(key, e.clone(), 60).await;
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
        self.mem.len().await
    }
}
