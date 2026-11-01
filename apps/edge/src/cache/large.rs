//! Disk-backed cache for large objects.
//!
//! Unlike `CacheEntry`, this store never buffers the full object in memory:
//! origin bytes are streamed into a temporary file and a reader streams the
//! committed file back in bounded chunks. It intentionally supports complete
//! objects first (Phase 2); partial/Range chunk caching can build on the same
//! sidecar metadata later.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;

use super::policy::stable_hash_str;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LargeMeta {
    pub key: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub content_length: u64,
    pub fresh_until: u64,
    pub stale_until: u64,
    pub stored_at: u64,
    pub complete: bool,
    /// Inclusive byte ranges that have been fully written. Empty for legacy
    /// complete objects (where `complete` means 0..content_length-1).
    #[serde(default)]
    pub segments: Vec<(u64, u64)>,
}

impl LargeMeta {
    pub fn covers(&self, start: u64, end: u64) -> bool {
        self.complete || self.segments.iter().any(|(s, e)| *s <= start && *e >= end)
    }
}

pub struct LargeEntry {
    pub meta: LargeMeta,
    file: File,
}

impl LargeEntry {
    pub fn content_length(&self) -> u64 {
        self.meta.content_length
    }

    pub fn covers(&self, start: u64, end: u64) -> bool {
        self.meta.covers(start, end)
    }

    pub async fn read_at(&mut self, pos: u64, max: usize) -> std::io::Result<Option<Bytes>> {
        if pos >= self.meta.content_length {
            return Ok(None);
        }
        self.file.seek(std::io::SeekFrom::Start(pos)).await?;
        let want = max.min((self.meta.content_length - pos) as usize).max(1);
        let mut buf = vec![0_u8; want];
        let n = self.file.read(&mut buf).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.truncate(n);
        Ok(Some(Bytes::from(buf)))
    }
}

pub struct LargeWriter {
    cache: Arc<LargeCache>,
    meta: LargeMeta,
    file: File,
    temp_path: PathBuf,
    data_path: PathBuf,
    meta_path: PathBuf,
    written: u64,
    failed: bool,
}

impl LargeWriter {
    pub fn content_length(&self) -> u64 {
        self.meta.content_length
    }

    pub fn failed(&self) -> bool {
        self.failed
    }

    pub async fn write_all(&mut self, data: &[u8]) {
        if self.failed || data.is_empty() {
            return;
        }
        if self.written + data.len() as u64 > self.meta.content_length {
            self.failed = true;
            return;
        }
        if self.file.write_all(data).await.is_err() {
            self.failed = true;
            return;
        }
        self.written += data.len() as u64;
    }

    pub async fn commit(mut self) -> bool {
        if self.failed || self.written != self.meta.content_length {
            self.abort().await;
            return false;
        }
        if self.file.flush().await.is_err() || self.file.sync_all().await.is_err() {
            self.abort().await;
            return false;
        }
        let old_len = fs::metadata(&self.data_path)
            .await
            .map(|m| m.len())
            .unwrap_or(0)
            + fs::metadata(&self.meta_path)
                .await
                .map(|m| m.len())
                .unwrap_or(0);
        if fs::rename(&self.temp_path, &self.data_path).await.is_err() {
            let _ = fs::remove_file(&self.temp_path).await;
            return false;
        }
        self.meta.complete = true;
        self.meta.stored_at = now_unix();
        let meta_bytes = match serde_json::to_vec(&self.meta) {
            Ok(v) => v,
            Err(_) => {
                let _ = fs::remove_file(&self.data_path).await;
                return false;
            }
        };
        if write_atomic(&self.meta_path, &meta_bytes).await.is_err() {
            let _ = fs::remove_file(&self.data_path).await;
            return false;
        }
        self.cache.used_bytes.fetch_add(
            self.meta.content_length + meta_bytes.len() as u64,
            Ordering::Relaxed,
        );
        if old_len > 0 {
            self.cache.release_bytes(old_len);
        } else {
            self.cache.entries.fetch_add(1, Ordering::Relaxed);
        }
        self.cache.evict_overflow().await;
        true
    }

    async fn abort(&mut self) {
        let _ = fs::remove_file(&self.temp_path).await;
    }
}

impl Drop for LargeWriter {
    fn drop(&mut self) {
        // Remove an uncommitted temp file if the cache write is cancelled by a
        // client disconnect or an upstream error.
        let _ = std::fs::remove_file(&self.temp_path);
    }
}

/// Writes one byte range (normally from an origin 206 response) into an
/// existing or new partial object. Only fully received ranges are recorded in
/// the sidecar metadata.
pub struct RangeWriter {
    cache: Arc<LargeCache>,
    meta: LargeMeta,
    file: File,
    data_path: PathBuf,
    meta_path: PathBuf,
    start: u64,
    end: u64,
    written: u64,
    new_entry: bool,
    committed: bool,
}

impl RangeWriter {
    pub async fn write_all(&mut self, data: &[u8]) {
        if self.written + data.len() as u64 > self.end - self.start + 1 {
            return;
        }
        if self.file.write_all(data).await.is_ok() {
            self.written += data.len() as u64;
        }
    }

    pub async fn commit(mut self) -> bool {
        let expected = self.end - self.start + 1;
        if self.written != expected {
            self.abort().await;
            return false;
        }
        if self.file.flush().await.is_err() || self.file.sync_all().await.is_err() {
            self.abort().await;
            return false;
        }
        self.meta.segments.push((self.start, self.end));
        self.meta.segments.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(self.meta.segments.len());
        for (start, end) in self.meta.segments.drain(..) {
            if let Some((_, prev_end)) = merged.last_mut() {
                if start <= prev_end.saturating_add(1) {
                    *prev_end = (*prev_end).max(end);
                    continue;
                }
            }
            merged.push((start, end));
        }
        self.meta.segments = merged;
        self.meta.complete = self
            .meta
            .covers(0, self.meta.content_length.saturating_sub(1));
        self.meta.stored_at = now_unix();
        let Ok(meta_bytes) = serde_json::to_vec(&self.meta) else {
            self.abort().await;
            return false;
        };
        if write_atomic(&self.meta_path, &meta_bytes).await.is_err() {
            self.abort().await;
            return false;
        }
        if self.new_entry {
            self.cache.used_bytes.fetch_add(
                self.meta.content_length + meta_bytes.len() as u64,
                Ordering::Relaxed,
            );
            self.cache.entries.fetch_add(1, Ordering::Relaxed);
        }
        self.committed = true;
        self.cache.evict_overflow().await;
        true
    }

    async fn abort(&mut self) {
        if self.new_entry {
            let _ = fs::remove_file(&self.data_path).await;
            let _ = fs::remove_file(&self.meta_path).await;
        }
    }
}

impl Drop for RangeWriter {
    fn drop(&mut self) {
        if self.new_entry && !self.committed {
            let _ = std::fs::remove_file(&self.data_path);
            let _ = std::fs::remove_file(&self.meta_path);
        }
    }
}

pub struct LargeCache {
    root: PathBuf,
    min_object_bytes: u64,
    max_object_bytes: u64,
    max_bytes: u64,
    used_bytes: AtomicU64,
    entries: AtomicUsize,
    evict_lock: Mutex<()>,
}

impl LargeCache {
    pub async fn open(
        dir: impl AsRef<Path>,
        min_object_bytes: u64,
        max_object_bytes: u64,
        max_bytes: u64,
    ) -> anyhow::Result<Arc<Self>> {
        let root = dir.as_ref().to_path_buf();
        fs::create_dir_all(&root).await?;
        let min_object_bytes = min_object_bytes.max(1024 * 1024);
        let max_object_bytes = max_object_bytes.max(min_object_bytes);
        let max_bytes = max_bytes.max(max_object_bytes);
        let (used, count) = scan_usage(&root).await.unwrap_or((0, 0));
        tracing::info!(
            path = %root.display(),
            used,
            count,
            min_object_bytes,
            max_object_bytes,
            max_bytes,
            "large object cache ready"
        );
        Ok(Arc::new(Self {
            root,
            min_object_bytes,
            max_object_bytes,
            max_bytes,
            used_bytes: AtomicU64::new(used),
            entries: AtomicUsize::new(count),
            evict_lock: Mutex::new(()),
        }))
    }

    pub fn accepts(&self, len: u64) -> bool {
        len >= self.min_object_bytes && len <= self.max_object_bytes
    }

    pub async fn has(&self, key: &str) -> bool {
        let (data_path, meta_path) = self.paths_for_key(key);
        let Ok(meta_bytes) = fs::read(&meta_path).await else {
            return false;
        };
        let Ok(meta) = serde_json::from_slice::<LargeMeta>(&meta_bytes) else {
            return false;
        };
        meta.complete
            && meta.key == key
            && now_unix() <= meta.stale_until
            && fs::metadata(&data_path).await.is_ok()
    }

    pub fn max_object_bytes(&self) -> u64 {
        self.max_object_bytes
    }

    fn release_bytes(&self, bytes: u64) {
        self.used_bytes
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                Some(used.saturating_sub(bytes))
            })
            .ok();
    }

    fn paths_for_key(&self, key: &str) -> (PathBuf, PathBuf) {
        let hash = stable_hash_str(key);
        let sub = format!("{:02x}", hash % 256);
        let dir = self.root.join(sub);
        let base = format!("{hash:016x}");
        (
            dir.join(format!("{base}.data")),
            dir.join(format!("{base}.meta.json")),
        )
    }

    pub async fn get(&self, key: &str) -> Option<LargeEntry> {
        let entry = self.get_any(key).await?;
        entry.meta.complete.then_some(entry)
    }

    pub async fn get_any(&self, key: &str) -> Option<LargeEntry> {
        let (data_path, meta_path) = self.paths_for_key(key);
        let meta_bytes = fs::read(&meta_path).await.ok()?;
        let meta: LargeMeta = serde_json::from_slice(&meta_bytes).ok()?;
        if meta.key != key || now_unix() > meta.stale_until {
            let data_len = fs::metadata(&data_path).await.map(|m| m.len()).unwrap_or(0);
            if fs::remove_file(&data_path).await.is_ok() {
                self.release_bytes(data_len + meta_bytes.len() as u64);
                self.entries
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                        Some(n.saturating_sub(1))
                    })
                    .ok();
            }
            let _ = fs::remove_file(&meta_path).await;
            return None;
        }
        let file = File::open(&data_path).await.ok()?;
        Some(LargeEntry { meta, file })
    }

    pub async fn begin(
        self: &Arc<Self>,
        key: &str,
        status: u16,
        headers: Vec<(String, String)>,
        content_length: u64,
        fresh_secs: u64,
        swr_secs: u64,
    ) -> Option<LargeWriter> {
        if !self.accepts(content_length) {
            return None;
        }
        let (data_path, meta_path) = self.paths_for_key(key);
        let parent = data_path.parent()?;
        if fs::create_dir_all(parent).await.is_err() {
            return None;
        }
        let temp_path = parent.join(format!(
            "{}.part.{}.{}",
            data_path.file_stem()?.to_string_lossy(),
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)
            .await
            .ok()?;
        let now = now_unix();
        let fresh = fresh_secs.max(1);
        let meta = LargeMeta {
            key: key.to_string(),
            status,
            headers,
            content_length,
            fresh_until: now + fresh,
            stale_until: now + fresh + swr_secs,
            stored_at: 0,
            complete: false,
            segments: Vec::new(),
        };
        Some(LargeWriter {
            cache: self.clone(),
            meta,
            file,
            temp_path,
            data_path,
            meta_path,
            written: 0,
            failed: false,
        })
    }

    pub async fn begin_range(
        self: &Arc<Self>,
        key: &str,
        status: u16,
        headers: Vec<(String, String)>,
        content_length: u64,
        start: u64,
        end: u64,
        fresh_secs: u64,
        swr_secs: u64,
    ) -> Option<RangeWriter> {
        if content_length == 0
            || !self.accepts(content_length)
            || start > end
            || end >= content_length
        {
            return None;
        }
        let (data_path, meta_path) = self.paths_for_key(key);
        let parent = data_path.parent()?;
        if fs::create_dir_all(parent).await.is_err() {
            return None;
        }
        let data_ok = fs::metadata(&data_path)
            .await
            .map(|m| m.len() >= content_length)
            .unwrap_or(false);
        let existing = match fs::read(&meta_path).await {
            Ok(bytes) => serde_json::from_slice::<LargeMeta>(&bytes)
                .ok()
                .filter(|m| data_ok && m.key == key && m.content_length == content_length),
            Err(_) => None,
        };
        if let Some(meta) = &existing {
            if meta.covers(start, end) {
                return None;
            }
        }
        let new_entry = existing.is_none();
        if new_entry {
            let _ = fs::remove_file(&data_path).await;
            let _ = fs::remove_file(&meta_path).await;
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&data_path)
            .await
            .ok()?;
        if new_entry && file.set_len(content_length).await.is_err() {
            return None;
        }
        file.seek(std::io::SeekFrom::Start(start)).await.ok()?;
        let now = now_unix();
        let fresh = fresh_secs.max(1);
        let meta = existing.unwrap_or_else(|| LargeMeta {
            key: key.to_string(),
            status,
            headers,
            content_length,
            fresh_until: now + fresh,
            stale_until: now + fresh + swr_secs,
            stored_at: 0,
            complete: false,
            segments: Vec::new(),
        });
        Some(RangeWriter {
            cache: self.clone(),
            meta,
            file,
            data_path,
            meta_path,
            start,
            end,
            written: 0,
            new_entry,
            committed: false,
        })
    }

    pub async fn purge_patterns(&self, patterns: &[String]) -> u64 {
        if patterns.is_empty() {
            return 0;
        }
        let mut victims = Vec::new();
        let mut stack = vec![self.root.clone()];
        while let Some(dir) = stack.pop() {
            let Ok(mut rd) = fs::read_dir(&dir).await else {
                continue;
            };
            while let Ok(Some(ent)) = rd.next_entry().await {
                let Ok(ft) = ent.file_type().await else {
                    continue;
                };
                let path = ent.path();
                if ft.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().is_some_and(|e| e == "json")
                    && path.to_string_lossy().ends_with(".meta.json")
                {
                    let Ok(bytes) = fs::read(&path).await else {
                        continue;
                    };
                    let Ok(meta) = serde_json::from_slice::<LargeMeta>(&bytes) else {
                        continue;
                    };
                    if meta.key.is_empty() || !patterns.iter().any(|p| meta.key.contains(p)) {
                        continue;
                    }
                    let base = path
                        .to_string_lossy()
                        .trim_end_matches(".meta.json")
                        .to_string();
                    let data = PathBuf::from(format!("{base}.data"));
                    victims.push((path, data, bytes.len() as u64));
                }
            }
        }
        let mut n = 0;
        for (meta, data, meta_len) in victims {
            let data_len = fs::metadata(&data).await.map(|m| m.len()).unwrap_or(0);
            if fs::remove_file(&data).await.is_ok() || fs::remove_file(&meta).await.is_ok() {
                n += 1;
                self.release_bytes(data_len + meta_len);
                self.entries
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                        Some(n.saturating_sub(1))
                    })
                    .ok();
            }
            let _ = fs::remove_file(&meta).await;
        }
        n
    }

    pub async fn clear(&self) {
        let _ = fs::remove_dir_all(&self.root).await;
        let _ = fs::create_dir_all(&self.root).await;
        self.used_bytes.store(0, Ordering::Relaxed);
        self.entries.store(0, Ordering::Relaxed);
    }

    pub fn len(&self) -> usize {
        self.entries.load(Ordering::Relaxed)
    }

    pub async fn evict_overflow(&self) {
        if self.max_bytes == 0 || self.used_bytes.load(Ordering::Relaxed) <= self.max_bytes {
            return;
        }
        let _guard = self.evict_lock.lock().await;
        let used = self.used_bytes.load(Ordering::Relaxed);
        if used <= self.max_bytes {
            return;
        }
        let target = self.max_bytes / 10 * 9;
        let mut files = Vec::new();
        let mut stack = vec![self.root.clone()];
        while let Some(dir) = stack.pop() {
            let Ok(mut rd) = fs::read_dir(&dir).await else {
                continue;
            };
            while let Ok(Some(ent)) = rd.next_entry().await {
                let Ok(ft) = ent.file_type().await else {
                    continue;
                };
                let path = ent.path();
                if ft.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "data") {
                    let Ok(meta) = ent.metadata().await else {
                        continue;
                    };
                    let mtime = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    files.push((mtime, path));
                }
            }
        }
        files.sort_by_key(|(mtime, _)| *mtime);
        let mut freed = 0u64;
        let mut victims = 0usize;
        for (_, data) in files {
            if used.saturating_sub(freed) <= target {
                break;
            }
            let meta = data.with_extension("meta.json");
            let data_len = fs::metadata(&data).await.map(|m| m.len()).unwrap_or(0);
            let meta_len = fs::metadata(&meta).await.map(|m| m.len()).unwrap_or(0);
            if fs::remove_file(&data).await.is_ok() {
                freed += data_len + meta_len;
                victims += 1;
            }
            let _ = fs::remove_file(&meta).await;
        }
        self.release_bytes(freed);
        self.entries
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_sub(victims))
            })
            .ok();
        if victims > 0 {
            tracing::warn!(freed, victims, "large object cache evicted oldest entries");
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension(format!(
        "{}.tmp{}",
        path.extension().and_then(|e| e.to_str()).unwrap_or("meta"),
        std::process::id()
    ));
    fs::write(&tmp, data).await?;
    match fs::rename(&tmp, path).await {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(path).await;
            let retry = fs::rename(&tmp, path).await;
            if retry.is_err() {
                let _ = fs::remove_file(&tmp).await;
            }
            retry.map_err(|_| e)
        }
    }
}

async fn scan_usage(root: &Path) -> anyhow::Result<(u64, usize)> {
    let mut total = 0u64;
    let mut count = 0usize;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(mut rd) = fs::read_dir(&dir).await else {
            continue;
        };
        while let Ok(Some(ent)) = rd.next_entry().await {
            let ft = ent.file_type().await?;
            let path = ent.path();
            if ft.is_dir() {
                stack.push(path);
            } else if let Ok(meta) = ent.metadata().await {
                total += meta.len();
                if path.extension().is_some_and(|e| e == "data") {
                    count += 1;
                }
            }
        }
    }
    Ok((total, count))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn streams_complete_object_and_purges() {
        let dir = std::env::temp_dir().join(format!(
            "lagran-large-cache-test-{}-{}",
            std::process::id(),
            now_unix()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let cache = LargeCache::open(&dir, 1024 * 1024, 4 * 1024 * 1024, 16 * 1024 * 1024)
            .await
            .unwrap();
        let key = "GET:large.test:/movie.bin";
        let body = vec![7_u8; 2 * 1024 * 1024];
        let mut writer = cache
            .begin(
                key,
                200,
                vec![("content-type".into(), "application/octet-stream".into())],
                body.len() as u64,
                60,
                0,
            )
            .await
            .expect("writer");
        writer.write_all(&body).await;
        assert!(writer.commit().await);
        assert_eq!(cache.len(), 1);

        let mut entry = cache.get(key).await.expect("entry");
        let first = entry.read_at(0, 1024).await.unwrap().unwrap();
        assert_eq!(first.len(), 1024);
        assert_eq!(first[0], 7);
        let tail = entry
            .read_at(body.len() as u64 - 1024, 1024)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tail.len(), 1024);

        assert_eq!(cache.purge_patterns(&["large.test".into()]).await, 1);
        assert!(cache.get(key).await.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn partial_ranges_accumulate_and_become_complete() {
        let dir = std::env::temp_dir().join(format!(
            "lagran-partial-cache-test-{}-{}",
            std::process::id(),
            now_unix()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let cache = LargeCache::open(&dir, 1024 * 1024, 4 * 1024 * 1024, 16 * 1024 * 1024)
            .await
            .unwrap();
        let key = "GET:video.test:/movie.mp4";
        let total = 2_u64 * 1024 * 1024;

        let mut first = cache
            .begin_range(
                key,
                200,
                vec![("content-type".into(), "video/mp4".into())],
                total,
                0,
                1023,
                60,
                0,
            )
            .await
            .expect("first range");
        first.write_all(&vec![1_u8; 1024]).await;
        assert!(first.commit().await);

        let entry = cache.get_any(key).await.expect("partial entry");
        assert!(entry.covers(0, 1023));
        assert!(!entry.covers(0, 1024));

        let mut second = cache
            .begin_range(key, 200, Vec::new(), total, 1024, 2047, 60, 0)
            .await
            .expect("second range");
        second.write_all(&vec![2_u8; 1024]).await;
        assert!(second.commit().await);

        let entry = cache.get_any(key).await.expect("accumulated entry");
        assert!(entry.covers(0, 2047));
        assert!(!entry.covers(0, total - 1));

        let mut last = cache
            .begin_range(key, 200, Vec::new(), total, 2048, total - 1, 60, 0)
            .await
            .expect("last range");
        last.write_all(&vec![3_u8; (total - 2048) as usize]).await;
        assert!(last.commit().await);

        let mut entry = cache.get(key).await.expect("complete entry");
        assert_eq!(entry.meta.segments, vec![(0, total - 1)]);
        let chunk = entry.read_at(2048, 16).await.unwrap().unwrap();
        assert_eq!(&chunk[..], &[3_u8; 16]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
