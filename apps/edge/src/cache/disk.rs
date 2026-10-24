//! Persistent file cache on disk

use async_trait::async_trait;
use bytes::Bytes;
use lagran_cache::{CacheBackend, CacheEntry};
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
    expires_unix: u64,
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
        (dir.join(format!("{base}.meta")), dir.join(format!("{base}.bin")))
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
    async fn get(&self, key: &str) -> Option<CacheEntry> {
        let (meta_path, bin_path) = self.paths_for_key(key);
        let meta_bytes = fs::read(&meta_path).await.ok()?;
        let meta: DiskMeta = serde_json::from_slice(&meta_bytes).ok()?;
        if now_unix() > meta.expires_unix {
            let _ = fs::remove_file(&meta_path).await;
            let _ = fs::remove_file(&bin_path).await;
            return None;
        }
        let body = fs::read(&bin_path).await.ok()?;
        Some(CacheEntry {
            status: meta.status,
            headers: meta.headers,
            body: Bytes::from(body),
        })
    }

    async fn set(&self, key: &str, entry: CacheEntry, ttl_secs: u64) {
        let _guard = self.lock.lock().await;
        let (meta_path, bin_path) = self.paths_for_key(key);
        if let Some(parent) = meta_path.parent() {
            let _ = fs::create_dir_all(parent).await;
        }

        let meta = DiskMeta {
            status: entry.status,
            headers: entry.headers.clone(),
            expires_unix: now_unix() + ttl_secs.max(1),
        };
        let meta_bytes = match serde_json::to_vec(&meta) {
            Ok(b) => b,
            Err(_) => return,
        };

        // rough size accounting
        let new_size = meta_bytes.len() as u64 + entry.body.len() as u64;
        let used = self.used_bytes.load(Ordering::Relaxed);
        if used + new_size > self.max_bytes {
            // simple: skip write when full (production: LRU eviction)
            tracing::warn!("disk cache full, skip set");
            return;
        }

        if fs::write(&meta_path, &meta_bytes).await.is_ok()
            && fs::write(&bin_path, entry.body.as_ref()).await.is_ok()
        {
            self.used_bytes.fetch_add(new_size, Ordering::Relaxed);
        }
    }

    async fn delete(&self, key: &str) {
        let (meta_path, bin_path) = self.paths_for_key(key);
        let _ = fs::remove_file(meta_path).await;
        let _ = fs::remove_file(bin_path).await;
    }

    async fn clear(&self) {
        let _guard = self.lock.lock().await;
        let _ = fs::remove_dir_all(&self.root).await;
        let _ = fs::create_dir_all(&self.root).await;
        self.used_bytes.store(0, Ordering::Relaxed);
    }

    async fn purge_matching(&self, patterns: &[String]) -> u64 {
        // disk purge by scanning is expensive; clear all if empty patterns or *
        if patterns.is_empty() || patterns.iter().any(|p| p == "*" || p == "/*") {
            self.clear().await;
            return 1;
        }
        // best-effort: no full index — clear for safety on path purge
        self.clear().await;
        1
    }

    async fn len(&self) -> usize {
        0 // not tracked precisely
    }
}

/// Two-tier: memory first, then disk
pub struct HybridCache {
    memory: Arc<dyn CacheBackend>,
    disk: Arc<dyn CacheBackend>,
}

impl HybridCache {
    pub fn new(memory: Arc<dyn CacheBackend>, disk: Arc<dyn CacheBackend>) -> Self {
        Self { memory, disk }
    }
}

#[async_trait]
impl CacheBackend for HybridCache {
    async fn get(&self, key: &str) -> Option<CacheEntry> {
        if let Some(e) = self.memory.get(key).await {
            return Some(e);
        }
        if let Some(e) = self.disk.get(key).await {
            // promote to memory with short TTL approximation — use 60s
            self.memory.set(key, e.clone(), 60).await;
            return Some(e);
        }
        None
    }

    async fn set(&self, key: &str, entry: CacheEntry, ttl_secs: u64) {
        self.memory.set(key, entry.clone(), ttl_secs).await;
        self.disk.set(key, entry, ttl_secs).await;
    }

    async fn delete(&self, key: &str) {
        self.memory.delete(key).await;
        self.disk.delete(key).await;
    }

    async fn clear(&self) {
        self.memory.clear().await;
        self.disk.clear().await;
    }

    async fn purge_matching(&self, patterns: &[String]) -> u64 {
        let a = self.memory.purge_matching(patterns).await;
        let b = self.disk.purge_matching(patterns).await;
        a + b
    }

    async fn len(&self) -> usize {
        self.memory.len().await
    }
}
