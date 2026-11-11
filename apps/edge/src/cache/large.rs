//! Disk-backed cache for large objects.
//!
//! Unlike `CacheEntry`, this store never buffers the full object in memory:
//! origin bytes are streamed into a sparse file and a reader streams committed
//! ranges back in bounded chunks. The sidecar records inclusive byte segments,
//! so bounded Range responses, open-ended prefixes and suffix tails can be
//! served independently without treating a partial object as complete.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{Mutex, OwnedMutexGuard};

use super::policy::stable_hash_str;

/// How many directory entries one eviction pass may examine.
///
/// Eviction runs on the commit path, so its cost must not scale with the number
/// of cached objects. A pass samples shard directories from a rotating cursor
/// and stops here; any remaining overflow is handled by the next commit.
/// Sized against [`EVICT_VICTIM_BUDGET`]: large enough that a sample reliably
/// yields old victims, small enough to stay sub-millisecond.
const EVICT_ENTRY_BUDGET: usize = 256;

/// How many objects one eviction pass may delete.
///
/// Each victim costs two `unlink` calls plus a sidecar read. Capping the count
/// keeps the commit path's tail latency predictable; any remaining overflow is
/// trimmed by subsequent commits.
const EVICT_VICTIM_BUDGET: usize = 16;

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

    /// Bytes resident in the sparse data file, not the sparse file's logical
    /// length. This keeps eviction fair when a 700 MB video only has a 32 MiB
    /// prefix cached.
    pub fn stored_bytes(&self) -> u64 {
        if self.complete {
            return self.content_length;
        }
        self.segments
            .iter()
            .map(|(start, end)| end.saturating_sub(*start).saturating_add(1))
            .sum()
    }

    /// End of the cached contiguous run that contains start, if any.
    /// Used to splice a cached prefix with an origin remainder.
    pub fn contiguous_end(&self, start: u64) -> Option<u64> {
        if self.complete {
            return self.content_length.checked_sub(1);
        }
        self.segments
            .iter()
            .find(|(s, e)| *s <= start && *e >= start)
            .map(|(_, e)| *e)
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
    fresh_secs: u64,
    swr_secs: u64,
    _range_guard: OwnedMutexGuard<()>,
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
        let old_meta_len = fs::metadata(&self.meta_path)
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        let old_stored = fs::read(&self.meta_path)
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice::<LargeMeta>(&bytes).ok())
            .map(|meta| meta.stored_bytes())
            .unwrap_or(0);
        let old_len = old_stored + old_meta_len;
        if fs::rename(&self.temp_path, &self.data_path).await.is_err() {
            let _ = fs::remove_file(&self.temp_path).await;
            return false;
        }
        self.meta.complete = true;
        let committed_at = now_unix();
        // TTL must start when the object is committed, not when the transfer
        // began. A slow large download can otherwise finish already expired.
        self.meta.fresh_until = committed_at + self.fresh_secs.max(1);
        self.meta.stale_until = self.meta.fresh_until + self.swr_secs;
        self.meta.stored_at = committed_at;
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
/// existing or new partial object. Only bytes actually written are recorded in
/// the sidecar metadata; a disconnected client can leave a committed prefix.
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
    start_stored: u64,
    fresh_secs: u64,
    swr_secs: u64,
    _range_guard: OwnedMutexGuard<()>,
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

    /// Commit only when the complete planned range was received.
    pub async fn commit(self) -> bool {
        let expected = self.end - self.start + 1;
        if self.written != expected {
            let mut writer = self;
            writer.abort().await;
            return false;
        }
        let written = self.written;
        self.finish(written).await
    }

    /// Commit a prefix received before the client disconnected or the fill
    /// queue overflowed. Only bytes actually written are recorded, so a
    /// truncated range is never advertised as complete.
    pub async fn commit_partial(self) -> bool {
        if self.written == 0 {
            let mut writer = self;
            writer.abort().await;
            return false;
        }
        let written = self.written;
        self.finish(written).await
    }

    async fn finish(mut self, written: u64) -> bool {
        if written == 0 {
            self.abort().await;
            return false;
        }
        if self.file.flush().await.is_err() || self.file.sync_all().await.is_err() {
            self.abort().await;
            return false;
        }
        let segment_end = self.start.saturating_add(written).saturating_sub(1);
        self.meta.segments.push((self.start, segment_end));
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
        let committed_at = now_unix();
        self.meta.fresh_until = committed_at + self.fresh_secs.max(1);
        self.meta.stale_until = self.meta.fresh_until + self.swr_secs;
        self.meta.stored_at = committed_at;
        let Ok(meta_bytes) = serde_json::to_vec(&self.meta) else {
            self.abort().await;
            return false;
        };
        if write_atomic(&self.meta_path, &meta_bytes).await.is_err() {
            self.abort().await;
            return false;
        }
        let stored = self.meta.stored_bytes();
        if self.new_entry {
            self.cache
                .used_bytes
                .fetch_add(stored + meta_bytes.len() as u64, Ordering::Relaxed);
            self.cache.entries.fetch_add(1, Ordering::Relaxed);
        } else if stored > self.start_stored {
            self.cache
                .used_bytes
                .fetch_add(stored - self.start_stored, Ordering::Relaxed);
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
    /// Shard index the next eviction pass starts from.
    evict_cursor: AtomicUsize,
    /// One active range writer per object. A second request on the same key
    /// streams from origin normally instead of racing the sparse file/meta.
    range_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
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
        let removed_parts = cleanup_stale_parts(&root, 6 * 60 * 60).await.unwrap_or(0);
        if removed_parts > 0 {
            tracing::warn!(path = %root.display(), removed_parts, "removed stale large-cache part files");
        }
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
            evict_cursor: AtomicUsize::new(0),
            range_locks: Mutex::new(HashMap::new()),
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

    /// Headers that must never land in a cached entry.
    ///
    /// `Set-Cookie` is the important one: storing an origin response that sets a
    /// session cookie and replaying it from cache hands the *origin's* session
    /// to every later client that hits the same key. That is session fixation,
    /// and it was reachable through this cache because the large-object writer
    /// copied upstream headers verbatim while the small-object path filtered
    /// them elsewhere.
    pub(crate) fn cacheable_header(name: &str) -> bool {
        !matches!(
            name.to_ascii_lowercase().as_str(),
            "set-cookie"
                | "set-cookie2"
                | "content-length"
                | "transfer-encoding"
                | "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "proxy-connection"
                | "te"
                | "trailer"
                | "trailers"
                | "upgrade"
                | "age"
                | "date"
                | "x-lagran-cache-reason"
                | "x-lagran-validator-source"
        )
    }

    /// Drop uncacheable headers from a header list before it is persisted.
    pub(crate) fn prune_uncacheable(headers: &[(String, String)]) -> Vec<(String, String)> {
        headers
            .iter()
            .filter(|(name, _)| Self::cacheable_header(name))
            .cloned()
            .collect()
    }

    /// Headers that may be replayed to a client from a stored entry.
    ///
    /// Entries written by an older build can still contain `Set-Cookie`, so the
    /// replay side filters independently of the write side.
    pub(crate) fn replayable_header(name: &str) -> bool {
        !name.to_ascii_lowercase().starts_with("set-cookie")
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
            let stored = meta.stored_bytes();
            if fs::remove_file(&data_path).await.is_ok() {
                self.release_bytes(stored + meta_bytes.len() as u64);
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

    /// Refresh a complete large object after an origin 304. The data file is
    /// not rewritten; only the sidecar metadata/TTL/validators are updated.
    pub async fn refresh_meta(
        &self,
        key: &str,
        headers: &[(String, String)],
        fresh_secs: u64,
        swr_secs: u64,
    ) -> bool {
        let (_data_path, meta_path) = self.paths_for_key(key);
        let Ok(meta_bytes) = fs::read(&meta_path).await else {
            return false;
        };
        let Ok(mut meta) = serde_json::from_slice::<LargeMeta>(&meta_bytes) else {
            return false;
        };
        if meta.key != key || !meta.complete {
            return false;
        }
        for (name, value) in headers {
            // A 304 can still carry `Set-Cookie`; merging it here would attach
            // fresh session headers to an old cached object.
            if !Self::cacheable_header(name) {
                continue;
            }
            meta.headers
                .retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
            meta.headers.push((name.clone(), value.clone()));
        }
        // Also scrub anything already stored by an older build.
        meta.headers.retain(|(name, _)| Self::cacheable_header(name));
        let now = now_unix();
        meta.fresh_until = now + fresh_secs.max(1);
        meta.stale_until = now + fresh_secs.max(1) + swr_secs;
        meta.stored_at = now;
        let Ok(meta_bytes) = serde_json::to_vec(&meta) else {
            return false;
        };
        write_atomic(&meta_path, &meta_bytes).await.is_ok()
    }

    pub async fn delete(&self, key: &str) -> bool {
        let (data_path, meta_path) = self.paths_for_key(key);
        let data_len = fs::metadata(&data_path)
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        let meta_len = fs::metadata(&meta_path)
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        let stored = fs::read(&meta_path)
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice::<LargeMeta>(&bytes).ok())
            .map(|meta| meta.stored_bytes())
            .unwrap_or(data_len);
        let data_removed = fs::remove_file(&data_path).await.is_ok();
        let meta_removed = fs::remove_file(&meta_path).await.is_ok();
        if data_removed || meta_removed {
            self.release_bytes(stored + meta_len);
            self.entries
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                    Some(n.saturating_sub(1))
                })
                .ok();
            return true;
        }
        false
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
        // Defense in depth: callers are expected to filter already, but a single
        // missed call site would otherwise cache a `Set-Cookie` response.
        let headers = Self::prune_uncacheable(&headers);
        let (data_path, meta_path) = self.paths_for_key(key);
        let parent = data_path.parent()?;
        if fs::create_dir_all(parent).await.is_err() {
            return None;
        }
        let key_lock = {
            let mut locks = self.range_locks.lock().await;
            locks.retain(|_, lock| Arc::strong_count(lock) > 1);
            locks
                .entry(key.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        let range_guard = key_lock.try_lock_owned().ok()?;
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
            fresh_secs: fresh,
            swr_secs,
            _range_guard: range_guard,
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
            || content_length < self.min_object_bytes
            || start > end
            || end >= content_length
            || end.saturating_sub(start).saturating_add(1) > self.max_object_bytes
        {
            return None;
        }
        let (data_path, meta_path) = self.paths_for_key(key);
        let parent = data_path.parent()?;
        if fs::create_dir_all(parent).await.is_err() {
            return None;
        }
        let key_lock = {
            let mut locks = self.range_locks.lock().await;
            locks.retain(|_, lock| Arc::strong_count(lock) > 1);
            locks
                .entry(key.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        let range_guard = key_lock.try_lock_owned().ok()?;
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
        let start_stored = existing.as_ref().map(LargeMeta::stored_bytes).unwrap_or(0);
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
            start_stored,
            fresh_secs: fresh,
            swr_secs,
            _range_guard: range_guard,
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
                    victims.push((path, data, meta.stored_bytes(), bytes.len() as u64));
                }
            }
        }
        let mut n = 0;
        for (meta, data, stored, meta_len) in victims {
            if fs::remove_file(&data).await.is_ok() || fs::remove_file(&meta).await.is_ok() {
                n += 1;
                self.release_bytes(stored + meta_len);
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

    /// Evict least-recently-used objects until usage is back under 90% of the
    /// cap, examining at most [`EVICT_ENTRY_BUDGET`] directory entries.
    ///
    /// Large-object eviction runs on the write path, right after an object
    /// commits. The previous version recursively walked the whole tree,
    /// stat'ed and re-read every sidecar, then sorted every path while holding
    /// `evict_lock` — with a full cache of large files that is a multi-second
    /// stall that also blocks every other writer. This pass samples shard
    /// directories from a rotating cursor and finishes any remaining overflow
    /// on the next commit.
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

        let shards = 256usize;
        let start = self.evict_cursor.load(Ordering::Relaxed) % shards;
        // Sample on a blocking thread: every candidate needs a `stat` and a
        // sidecar read, and awaiting those individually on the runtime made a
        // single pass cost ~100 ms of sequential syscalls.
        let root = self.root.clone();
        let sample = tokio::task::spawn_blocking(move || {
            // (mtime, accounted bytes, data path, meta path)
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
                    if !path.to_string_lossy().ends_with(".meta.json") {
                        continue;
                    }
                    let Ok(meta_stat) = ent.metadata() else {
                        continue;
                    };
                    let mtime = meta_stat
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let base = path
                        .to_string_lossy()
                        .trim_end_matches(".meta.json")
                        .to_string();
                    let data = PathBuf::from(format!("{base}.data"));
                    // `stored_bytes()` is the resident size of a sparse file,
                    // which can be far smaller than the logical length. Reading
                    // the sidecar keeps accounting honest.
                    let stored = std::fs::read(&path)
                        .ok()
                        .and_then(|bytes| serde_json::from_slice::<LargeMeta>(&bytes).ok())
                        .map(|row| row.stored_bytes())
                        .unwrap_or_else(|| {
                            std::fs::metadata(&data).map(|m| m.len()).unwrap_or(0)
                        });
                    candidates.push((mtime, stored + meta_stat.len(), data, path));
                }
            }
            (candidates, examined, cursor)
        })
        .await
        .unwrap_or_default();
        let (mut candidates, examined, cursor) = sample;
        self.evict_cursor
            .store((cursor + 1) % shards, Ordering::Relaxed);
        candidates.sort_unstable_by_key(|(mtime, _, _, _)| *mtime);

        let mut freed = 0u64;
        let mut victims = 0usize;
        for (_, size, data, meta) in candidates {
            if used.saturating_sub(freed) <= target || victims >= EVICT_VICTIM_BUDGET {
                break;
            }
            let data_removed = fs::remove_file(&data).await.is_ok();
            let meta_removed = fs::remove_file(&meta).await.is_ok();
            if data_removed || meta_removed {
                freed += size;
                victims += 1;
            }
        }
        self.release_bytes(freed);
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
                "large object cache evicted oldest sampled entries"
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

async fn cleanup_stale_parts(root: &Path, max_age_secs: u64) -> anyhow::Result<u64> {
    let now = SystemTime::now();
    let mut removed = 0u64;
    let mut stack = vec![root.to_path_buf()];
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
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !name.contains(".part.") {
                continue;
            }
            let Ok(meta) = ent.metadata().await else {
                continue;
            };
            let age = meta
                .modified()
                .ok()
                .and_then(|modified| now.duration_since(modified).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if age >= max_age_secs && fs::remove_file(&path).await.is_ok() {
                removed += 1;
            }
        }
    }
    Ok(removed)
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
                continue;
            }
            if !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".meta.json"))
            {
                continue;
            }
            let Ok(meta_bytes) = fs::read(&path).await else {
                continue;
            };
            let Ok(meta) = serde_json::from_slice::<LargeMeta>(&meta_bytes) else {
                continue;
            };
            total += meta.stored_bytes() + meta_bytes.len() as u64;
            count += 1;
        }
    }
    Ok((total, count))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Storing an origin response that sets a session cookie and replaying it
    /// from cache hands that session to every later client: session fixation.
    #[test]
    fn set_cookie_is_never_cached() {
        let headers = vec![
            ("content-type".to_string(), "text/html".to_string()),
            ("set-cookie".to_string(), "sid=secret; Path=/".to_string()),
            ("Set-Cookie2".to_string(), "legacy=1".to_string()),
            ("age".to_string(), "42".to_string()),
            ("cache-control".to_string(), "max-age=60".to_string()),
        ];
        let pruned = LargeCache::prune_uncacheable(&headers);

        assert!(pruned.iter().any(|(n, _)| n == "content-type"));
        assert!(pruned.iter().any(|(n, _)| n == "cache-control"));
        for (name, _) in &pruned {
            assert!(
                !name.to_ascii_lowercase().starts_with("set-cookie"),
                "{name} must not be cached"
            );
        }
        assert!(!pruned.iter().any(|(n, _)| n == "age"));
    }

    /// Entries written by an older build can still contain `Set-Cookie`, so the
    /// replay path filters independently.
    #[test]
    fn set_cookie_is_never_replayed() {
        for name in ["set-cookie", "Set-Cookie", "SET-COOKIE", "set-cookie2"] {
            assert!(
                !LargeCache::replayable_header(name),
                "{name} must not be replayed"
            );
        }
        for name in ["content-type", "etag", "cache-control"] {
            assert!(LargeCache::replayable_header(name));
        }
    }

    #[test]
    fn contiguous_segments_expose_splice_boundary() {
        let meta = LargeMeta {
            key: "GET:video.test:/movie.mp4".into(),
            status: 206,
            headers: Vec::new(),
            content_length: 1024,
            fresh_until: u64::MAX,
            stale_until: u64::MAX,
            stored_at: 0,
            complete: false,
            segments: vec![(0, 255), (512, 767)],
        };
        assert_eq!(meta.contiguous_end(0), Some(255));
        assert_eq!(meta.contiguous_end(128), Some(255));
        assert_eq!(meta.contiguous_end(256), None);
        assert_eq!(meta.contiguous_end(600), Some(767));
        assert_eq!(meta.stored_bytes(), 512);
    }

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
    async fn ttl_starts_at_commit_not_transfer_start() {
        let dir = std::env::temp_dir().join(format!(
            "lagran-large-cache-ttl-test-{}-{}",
            std::process::id(),
            now_unix()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let cache = LargeCache::open(&dir, 1024 * 1024, 4 * 1024 * 1024, 16 * 1024 * 1024)
            .await
            .unwrap();
        let key = "GET:large.test:/slow.bin";
        let mut writer = cache
            .begin(key, 200, Vec::new(), 1024 * 1024, 1, 0)
            .await
            .expect("writer");
        // Simulate a slow transfer: the TTL would expire before commit if it
        // were measured from `begin`.
        tokio::time::sleep(Duration::from_secs(2)).await;
        writer.write_all(&vec![1_u8; 1024 * 1024]).await;
        assert!(writer.commit().await);
        assert!(cache.get(key).await.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn partial_range_allows_object_above_complete_object_limit() {
        let dir = std::env::temp_dir().join(format!(
            "lagran-large-object-partial-test-{}-{}",
            std::process::id(),
            now_unix()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let cache = LargeCache::open(&dir, 1024 * 1024, 4 * 1024 * 1024, 16 * 1024 * 1024)
            .await
            .unwrap();
        let key = "GET:video.test:/huge.mp4";
        let total = 8_u64 * 1024 * 1024;
        assert!(cache
            .begin(key, 200, Vec::new(), total, 60, 0)
            .await
            .is_none());
        let mut writer = cache
            .begin_range(key, 206, Vec::new(), total, 0, 1024 * 1024 - 1, 60, 0)
            .await
            .expect("partial range above complete-object limit");
        writer.write_all(&vec![9_u8; 1024 * 1024]).await;
        assert!(writer.commit().await);
        let mut entry = cache.get_any(key).await.expect("partial entry");
        assert!(entry.covers(0, 1024 * 1024 - 1));
        assert_eq!(entry.read_at(0, 8).await.unwrap().unwrap()[..], [9_u8; 8]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn interrupted_range_commits_only_completed_prefix() {
        let dir = std::env::temp_dir().join(format!(
            "lagran-partial-prefix-test-{}-{}",
            std::process::id(),
            now_unix()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let cache = LargeCache::open(&dir, 1024 * 1024, 4 * 1024 * 1024, 16 * 1024 * 1024)
            .await
            .unwrap();
        let key = "GET:video.test:/interrupted.mp4";
        let total = 2_u64 * 1024 * 1024;
        let mut writer = cache
            .begin_range(key, 206, Vec::new(), total, 0, total - 1, 60, 0)
            .await
            .expect("writer");
        writer.write_all(&vec![4_u8; 1024 * 1024]).await;
        assert!(writer.commit_partial().await);

        let mut entry = cache.get_any(key).await.expect("partial entry");
        assert!(entry.covers(0, 1024 * 1024 - 1));
        assert!(!entry.covers(0, total - 1));
        assert_eq!(entry.read_at(0, 16).await.unwrap().unwrap()[..], [4_u8; 16]);

        let mut rest = cache
            .begin_range(key, 206, Vec::new(), total, 1024 * 1024, total - 1, 60, 0)
            .await
            .expect("rest writer");
        rest.write_all(&vec![5_u8; 1024 * 1024]).await;
        assert!(rest.commit().await);
        assert!(cache.get(key).await.is_some());
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

    /// Incremental eviction must converge: after enough commits the large
    /// cache has to be back under its cap rather than hovering just above it.
    #[tokio::test]
    async fn incremental_eviction_converges_under_cap() {
        let dir = std::env::temp_dir().join(format!(
            "lagran-large-converge-{}-{}",
            std::process::id(),
            now_unix()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let min = 1024 * 1024;
        let cap = 8 * min;
        let cache = LargeCache::open(&dir, min, 4 * min, cap).await.unwrap();
        let body = vec![9_u8; min as usize];
        for i in 0..24 {
            let key = format!("GET:big.test:/obj{i}.bin");
            let mut writer = cache
                .begin(&key, 200, Vec::new(), min, 60, 0)
                .await
                .expect("writer");
            writer.write_all(&body).await;
            assert!(writer.commit().await);
        }
        assert!(
            cache.used_bytes.load(Ordering::Relaxed) <= cap,
            "usage must settle at or below the cap, got {}",
            cache.used_bytes.load(Ordering::Relaxed)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A victim is removed as a `.data`/`.meta.json` pair, so eviction never
    /// leaves a body without metadata (or vice versa) and the entry count
    /// matches the sidecars on disk.
    #[tokio::test]
    async fn eviction_leaves_no_orphan_files() {
        let dir = std::env::temp_dir().join(format!(
            "lagran-large-orphan-{}-{}",
            std::process::id(),
            now_unix()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let min = 1024 * 1024;
        let cache = LargeCache::open(&dir, min, 2 * min, 6 * min).await.unwrap();
        let body = vec![4_u8; min as usize];
        for i in 0..16 {
            let key = format!("GET:orph.test:/o{i}.bin");
            let mut writer = cache
                .begin(&key, 200, Vec::new(), min, 60, 0)
                .await
                .expect("writer");
            writer.write_all(&body).await;
            assert!(writer.commit().await);
        }

        let mut data_files = 0usize;
        let mut meta_files = 0usize;
        let mut stack = vec![dir.clone()];
        while let Some(current) = stack.pop() {
            let mut rd = tokio::fs::read_dir(&current).await.unwrap();
            while let Some(ent) = rd.next_entry().await.unwrap() {
                let ft = ent.file_type().await.unwrap();
                let path = ent.path();
                if ft.is_dir() {
                    stack.push(path);
                    continue;
                }
                let name = path.to_string_lossy();
                if name.ends_with(".meta.json") {
                    meta_files += 1;
                } else if name.ends_with(".data") {
                    data_files += 1;
                }
            }
        }
        assert_eq!(data_files, meta_files, "no orphaned data or sidecar files");
        assert_eq!(meta_files, cache.len(), "entry count must match sidecars");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
