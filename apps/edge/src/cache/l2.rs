//! Redis L2 cache shared by all edge nodes.
//!
//! The local backend remains the hot path. On a local miss the L2 is checked,
//! and successful L2 hits are promoted into the local cache. Writes go to both
//! layers. Redis failures fall back to local-only behavior so a degraded L2
//! never takes the data plane down.
//!
//! Values use a versioned binary payload (`L2` magic + version) under a
//! versioned key namespace. Bumping either never misparses entries written by
//! an older edge; they simply age out by TTL or are removed by `clear`/purge.

use async_trait::async_trait;
use bytes::Bytes;
use lagran_cache::{CacheBackend, CacheEntry, CacheGetResult, CacheSource, SharedCache};
use redis::AsyncCommands;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Read timeout stays short so a degraded L2 cannot add latency to hits.
const REDIS_TIMEOUT: Duration = Duration::from_millis(250);
/// Writes can be large and may cross regions. A 250ms timeout caused every
/// medium object to fail on remote Redis.
const REDIS_WRITE_TIMEOUT: Duration = Duration::from_secs(3);
const REDIS_ADMIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Payload magic + version stored at the front of every L2 value.
const L2_MAGIC: [u8; 2] = *b"L2";
const L2_FORMAT_VERSION: u8 = 2;
/// Redis key namespace tag. Bumping the payload format also bumps this so old
/// values age out by TTL instead of being misparsed.
const L2_KEY_VERSION: &str = "v2";

struct L2Entry {
    status: u16,
    headers: Vec<(String, String)>,
    body: Bytes,
    stored_at: u64,
    fresh_until: u64,
    stale_until: u64,
}

/// `prefix:version:key`. Kept as a free function so the namespace can be
/// asserted in tests without a Redis connection.
fn namespaced_key(prefix: &str, key: &str) -> String {
    format!("{prefix}:{L2_KEY_VERSION}:{key}")
}

/// Binary payload encoding.
///
/// The previous format was JSON with the body base64-encoded: a 100 KiB object
/// became ~140 KiB on the wire and cost a base64 decode on every L2 hit.
/// Fixed-width big-endian fields are deterministic, ~1.1x the body size, and
/// decode without a parser.
fn encode_entry(entry: &L2Entry) -> Vec<u8> {
    let mut headers = Vec::new();
    let mut header_count = 0u16;
    for (name, value) in &entry.headers {
        let (Ok(name_len), Ok(value_len)) = (u16::try_from(name.len()), u32::try_from(value.len()))
        else {
            continue;
        };
        if header_count == u16::MAX {
            break;
        }
        header_count += 1;
        headers.extend_from_slice(&name_len.to_be_bytes());
        headers.extend_from_slice(name.as_bytes());
        headers.extend_from_slice(&value_len.to_be_bytes());
        headers.extend_from_slice(value.as_bytes());
    }
    let body_len = u32::try_from(entry.body.len()).unwrap_or(u32::MAX) as usize;

    let mut out =
        Vec::with_capacity(L2_MAGIC.len() + 1 + 2 + 8 * 3 + 2 + headers.len() + 4 + body_len);
    out.extend_from_slice(&L2_MAGIC);
    out.push(L2_FORMAT_VERSION);
    out.extend_from_slice(&entry.status.to_be_bytes());
    out.extend_from_slice(&entry.stored_at.to_be_bytes());
    out.extend_from_slice(&entry.fresh_until.to_be_bytes());
    out.extend_from_slice(&entry.stale_until.to_be_bytes());
    out.extend_from_slice(&header_count.to_be_bytes());
    out.extend_from_slice(&headers);
    out.extend_from_slice(&(body_len as u32).to_be_bytes());
    out.extend_from_slice(&entry.body[..body_len]);
    out
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_be_bytes)
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_be_bytes)
    }

    fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .and_then(|b| b.try_into().ok())
            .map(u64::from_be_bytes)
    }
}

fn decode_entry(raw: &[u8]) -> Option<L2Entry> {
    let mut cur = Cursor::new(raw);
    if cur.take(L2_MAGIC.len())? != L2_MAGIC {
        return None;
    }
    if cur.u8()? != L2_FORMAT_VERSION {
        return None;
    }
    let status = cur.u16()?;
    let stored_at = cur.u64()?;
    let fresh_until = cur.u64()?;
    let stale_until = cur.u64()?;
    let header_count = cur.u16()? as usize;
    // Cap the pre-allocation: a corrupt header count must not reserve 64k slots.
    let mut headers = Vec::with_capacity(header_count.min(128));
    for _ in 0..header_count {
        let name_len = cur.u16()? as usize;
        let name = String::from_utf8(cur.take(name_len)?.to_vec()).ok()?;
        let value_len = cur.u32()? as usize;
        let value = String::from_utf8(cur.take(value_len)?.to_vec()).ok()?;
        headers.push((name, value));
    }
    let body_len = cur.u32()? as usize;
    let body = Bytes::copy_from_slice(cur.take(body_len)?);
    Some(L2Entry {
        status,
        headers,
        body,
        stored_at,
        fresh_until,
        stale_until,
    })
}

pub struct RedisL2Cache {
    local: SharedCache,
    conn: redis::aio::ConnectionManager,
    prefix: String,
    max_body: usize,
    read_timeout: Duration,
    write_timeout: Duration,
    fail_until_ms: Arc<AtomicU64>,
}

impl RedisL2Cache {
    pub async fn connect(
        local: SharedCache,
        url: &str,
        prefix: String,
        max_body: usize,
    ) -> Result<Self, String> {
        let client =
            redis::Client::open(url).map_err(|e| format!("invalid CACHE_REDIS_URL: {e}"))?;
        let conn = tokio::time::timeout(Duration::from_secs(2), client.get_connection_manager())
            .await
            .map_err(|_| "cache redis connection timeout".to_string())?
            .map_err(|e| format!("cache redis connection failed: {e}"))?;
        // A successful connection is not enough: ACLs, read-only replicas or
        // maxmemory=noeviction can make every cache write fail. Probe one
        // short-lived key so startup fails over to local cache instead of
        // claiming L2 is enabled while silently dropping writes.
        let mut probe_conn = conn.clone();
        let probe_key = format!("{}:__probe:{}", prefix, std::process::id());
        let _: () = tokio::time::timeout(
            Duration::from_millis(500),
            probe_conn.set_ex(probe_key, "1", 5_u64),
        )
        .await
        .map_err(|_| "cache redis write probe timeout".to_string())?
        .map_err(|e| format!("cache redis write probe failed: {e}"))?;
        Ok(Self {
            local,
            conn,
            prefix,
            max_body: max_body.clamp(1024, 64 * 1024 * 1024),
            read_timeout: std::env::var("CACHE_L2_READ_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .map(|ms| Duration::from_millis(ms.clamp(50, 10_000)))
                .unwrap_or(REDIS_TIMEOUT),
            write_timeout: std::env::var("CACHE_L2_WRITE_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .map(|ms| Duration::from_millis(ms.clamp(250, 30_000)))
                .unwrap_or(REDIS_WRITE_TIMEOUT),
            fail_until_ms: Arc::new(AtomicU64::new(0)),
        })
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn namespace(&self) -> String {
        format!("{}:{}:", self.prefix, L2_KEY_VERSION)
    }

    fn key(&self, key: &str) -> String {
        namespaced_key(&self.prefix, key)
    }

    /// Escape Redis glob metacharacters so a purge path containing `?`, `*`,
    /// `[` or `]` cannot delete unrelated keys.
    fn glob_escape(value: &str) -> String {
        let mut out = String::with_capacity(value.len());
        for ch in value.chars() {
            if matches!(ch, '*' | '?' | '[' | ']' | '\\') {
                out.push('\\');
            }
            out.push(ch);
        }
        out
    }

    fn tag_index_key(&self, tag: &str) -> String {
        format!("{}tagidx:{}", self.namespace(), tag.to_ascii_lowercase())
    }

    fn cache_tags(headers: &[(String, String)]) -> Vec<String> {
        let mut tags = Vec::new();
        for (name, value) in headers {
            if !["surrogate-key", "cache-tag", "x-cache-tag"]
                .iter()
                .any(|n| name.eq_ignore_ascii_case(n))
            {
                continue;
            }
            for tag in value
                .split(|c: char| c == ',' || c.is_whitespace())
                .map(str::trim)
                .filter(|tag| !tag.is_empty())
            {
                let tag = tag.to_ascii_lowercase();
                if !tags.contains(&tag) {
                    tags.push(tag);
                }
            }
        }
        tags
    }
    fn unhealthy(&self) -> bool {
        Self::now_ms() < self.fail_until_ms.load(Ordering::Relaxed)
    }

    fn mark_failed(&self) {
        self.fail_until_ms
            .store(Self::now_ms() + 5_000, Ordering::Relaxed);
    }

    async fn redis_get(&self, key: &str) -> Option<L2Entry> {
        if self.unhealthy() {
            return None;
        }
        let mut conn = self.conn.clone();
        let raw: Option<Vec<u8>> =
            match tokio::time::timeout(self.read_timeout, conn.get(self.key(key))).await {
                Ok(Ok(value)) => value,
                _ => {
                    if !self.unhealthy() {
                        tracing::warn!(key = %key, "Redis L2 read failed; using local cache");
                    }
                    self.mark_failed();
                    return None;
                }
            };
        decode_entry(&raw?)
    }

    /// Write the payload and its tag index in one pipeline.
    ///
    /// The previous implementation issued a `SET` and then a second pipeline for
    /// the tag index, doubling the round trips on every cache fill.
    async fn redis_write(&self, key: &str, entry: &L2Entry, tags: &[String]) {
        if self.unhealthy() || (entry.body.is_empty() && entry.headers.is_empty()) {
            return;
        }
        let ttl = entry.stale_until.saturating_sub(Self::now_secs()).max(1);
        let raw = encode_entry(entry);
        if raw.len() > self.max_body {
            tracing::warn!(
                key = %key,
                raw_len = raw.len(),
                max_body = self.max_body,
                "Redis L2 object exceeds CACHE_L2_MAX_BODY; local cache only"
            );
            return;
        }
        let redis_key = self.key(key);
        let mut pipe = redis::pipe();
        pipe.cmd("SET")
            .arg(&redis_key)
            .arg(raw.as_slice())
            .arg("EX")
            .arg(ttl)
            .ignore();
        let index_ttl = ttl.saturating_add(300).min(i64::MAX as u64) as i64;
        for tag in tags {
            let index = self.tag_index_key(tag);
            // Store the bare cache key: `purge_tags` maps members back through
            // `self.key()` and deletes them. Storing the namespaced key here
            // would double-prefix on purge.
            pipe.cmd("SADD").arg(&index).arg(key).ignore();
            pipe.cmd("EXPIRE").arg(&index).arg(index_ttl).ignore();
        }
        let mut conn = self.conn.clone();
        let result: redis::RedisResult<()> =
            tokio::time::timeout(self.write_timeout, pipe.query_async(&mut conn))
                .await
                .unwrap_or_else(|_| {
                    Err(redis::RedisError::from(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "cache redis set timeout",
                    )))
                });
        if let Err(e) = &result {
            if !self.unhealthy() {
                tracing::warn!(error = %e, key = %key, "Redis L2 write failed; keeping local cache only");
            }
            self.mark_failed();
        }
    }

    async fn redis_del(&self, key: &str) {
        if self.unhealthy() {
            return;
        }
        let mut conn = self.conn.clone();
        let result: redis::RedisResult<usize> =
            match tokio::time::timeout(REDIS_ADMIN_TIMEOUT, conn.del(self.key(key))).await {
                Ok(result) => result,
                Err(_) => {
                    self.mark_failed();
                    return;
                }
            };
        if result.is_err() {
            self.mark_failed();
        }
    }

    async fn redis_scan_keys(&self, pattern: &str) -> Vec<String> {
        if self.unhealthy() {
            return Vec::new();
        }
        let mut conn = self.conn.clone();
        let mut cursor = 0_u64;
        let mut keys = Vec::new();
        loop {
            let result: redis::RedisResult<(u64, Vec<String>)> = tokio::time::timeout(
                REDIS_ADMIN_TIMEOUT,
                redis::cmd("SCAN")
                    .arg(cursor)
                    .arg("MATCH")
                    .arg(format!("{}:{}", self.prefix, pattern))
                    .arg("COUNT")
                    .arg(500)
                    .query_async(&mut conn),
            )
            .await
            .unwrap_or_else(|_| {
                Err(redis::RedisError::from(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "cache redis scan timeout",
                )))
            });
            let (next, batch) = match result {
                Ok(value) => value,
                Err(_) => {
                    self.mark_failed();
                    return Vec::new();
                }
            };
            keys.extend(batch);
            if next == 0 {
                break;
            }
            cursor = next;
        }
        keys
    }
}

#[async_trait]
impl CacheBackend for RedisL2Cache {
    async fn get_result(&self, key: &str) -> CacheGetResult {
        self.get_result_with_source(key).await.0
    }

    async fn get_result_with_source(&self, key: &str) -> (CacheGetResult, CacheSource) {
        match self.local.get_result(key).await {
            CacheGetResult::Hit(entry) => return (CacheGetResult::Hit(entry), CacheSource::L1),
            CacheGetResult::Stale(entry) => return (CacheGetResult::Stale(entry), CacheSource::L1),
            CacheGetResult::Expired | CacheGetResult::Miss => {}
        }
        let Some(entry) = self.redis_get(key).await else {
            return (CacheGetResult::Miss, CacheSource::Unknown);
        };
        let now = Self::now_secs();
        if now > entry.stale_until {
            self.redis_del(key).await;
            return (CacheGetResult::Miss, CacheSource::Unknown);
        }
        let L2Entry {
            status,
            headers,
            body,
            stored_at,
            fresh_until,
            stale_until,
        } = entry;
        let fresh = now <= fresh_until;
        let ttl = fresh_until.saturating_sub(now).max(1);
        let swr = stale_until.saturating_sub(fresh_until);
        let local_entry = CacheEntry {
            status,
            headers,
            body,
            stored_at_epoch_secs: stored_at,
            fresh_until_epoch_secs: fresh_until,
            stale_until_epoch_secs: stale_until,
        };
        self.local
            .set_with_swr(key, local_entry.clone(), ttl, swr)
            .await;
        if fresh {
            (CacheGetResult::Hit(local_entry), CacheSource::L2)
        } else {
            (CacheGetResult::Stale(local_entry), CacheSource::L2)
        }
    }

    async fn has_local(&self, key: &str) -> bool {
        // Delegate to the local backend's non-promoting probe. Falling back to
        // `get_result` here would take the L1 LRU lock and refresh recency for
        // a read that only asks "is a lock needed?".
        self.local.has_local(key).await
    }

    async fn set(&self, key: &str, entry: CacheEntry, ttl_secs: u64) {
        self.set_with_swr(key, entry, ttl_secs, 0).await;
    }

    async fn set_with_swr(&self, key: &str, entry: CacheEntry, fresh_secs: u64, swr_secs: u64) {
        let tags = Self::cache_tags(&entry.headers);
        let body_len = entry.body.len();
        tracing::debug!(key = %key, body_len, tags = tags.len(), "Redis L2 write");
        self.local
            .set_with_swr(key, entry.clone(), fresh_secs, swr_secs)
            .await;
        let now = Self::now_secs();
        let l2 = L2Entry {
            status: entry.status,
            headers: entry.headers,
            body: entry.body,
            stored_at: now,
            fresh_until: now + fresh_secs.max(1),
            stale_until: now + fresh_secs.max(1) + swr_secs,
        };
        self.redis_write(key, &l2, &tags).await;
    }

    async fn delete(&self, key: &str) {
        self.local.delete(key).await;
        self.redis_del(key).await;
    }

    async fn clear(&self) {
        self.local.clear().await;
        let keys = self.redis_scan_keys("*").await;
        if keys.is_empty() {
            return;
        }
        let mut conn = self.conn.clone();
        let _: redis::RedisResult<usize> =
            tokio::time::timeout(REDIS_ADMIN_TIMEOUT, conn.del(keys))
                .await
                .unwrap_or(Ok(0));
    }

    async fn purge_matching(&self, patterns: &[String]) -> u64 {
        let mut removed = self.local.purge_matching(patterns).await;
        for pattern in patterns {
            let keys = self
                .redis_scan_keys(&format!("*{}*", Self::glob_escape(pattern)))
                .await;
            if keys.is_empty() {
                continue;
            }
            let mut conn = self.conn.clone();
            if let Ok(Ok(n)) =
                tokio::time::timeout(REDIS_ADMIN_TIMEOUT, conn.del::<_, usize>(keys)).await
            {
                removed += n as u64;
            }
        }
        removed
    }

    async fn purge_tags(&self, tags: &[String], domain: &str) -> u64 {
        let removed = self.local.purge_tags(tags, domain).await;
        let wanted: Vec<String> = tags.iter().map(|t| t.to_ascii_lowercase()).collect();
        if wanted.is_empty() {
            return removed;
        }
        let mut conn = self.conn.clone();
        let mut candidates: HashSet<String> = HashSet::new();
        for tag in &wanted {
            let result: redis::RedisResult<Vec<String>> =
                tokio::time::timeout(self.read_timeout, conn.smembers(self.tag_index_key(tag)))
                    .await
                    .unwrap_or(Ok(Vec::new()));
            if let Ok(keys) = result {
                candidates.extend(keys);
            }
        }
        // Entries written before the tag index existed have no members yet.
        // Fall back to a domain scan only in that case.
        if candidates.is_empty() {
            // `redis_scan_keys` returns fully qualified Redis keys, while the
            // rest of this function works with bare cache keys.
            let namespace = self.namespace();
            for full in self
                .redis_scan_keys(&format!("*{}*", Self::glob_escape(domain)))
                .await
            {
                if let Some(raw) = full.strip_prefix(&namespace) {
                    candidates.insert(raw.to_string());
                }
            }
        }
        let mut victims = Vec::new();
        for key in candidates {
            if !key.contains(domain) {
                continue;
            }
            let Ok(Ok(Some(raw))) = tokio::time::timeout(
                REDIS_ADMIN_TIMEOUT,
                conn.get::<_, Option<Vec<u8>>>(self.key(&key)),
            )
            .await
            else {
                continue;
            };
            let Some(entry) = decode_entry(&raw) else {
                continue;
            };
            if Self::cache_tags(&entry.headers)
                .iter()
                .any(|tag| wanted.iter().any(|w| w == tag))
            {
                victims.push(key);
            }
        }
        if victims.is_empty() {
            return removed;
        }
        let mut pipe = redis::pipe();
        for tag in &wanted {
            let index = self.tag_index_key(tag);
            for key in &victims {
                pipe.srem(&index, key).ignore();
            }
        }
        match tokio::time::timeout(REDIS_ADMIN_TIMEOUT, pipe.query_async::<()>(&mut conn)).await {
            Ok(Ok(_)) => {}
            _ => self.mark_failed(),
        }
        let redis_keys: Vec<String> = victims.iter().map(|key| self.key(key)).collect();
        let n: usize = tokio::time::timeout(REDIS_ADMIN_TIMEOUT, conn.del::<_, usize>(redis_keys))
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(0);
        removed + n as u64
    }

    async fn len(&self) -> usize {
        self.local.len().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lagran_cache::MemoryCache;

    fn sample_entry(body: &'static [u8]) -> L2Entry {
        L2Entry {
            status: 200,
            headers: vec![
                ("content-type".into(), "text/html; charset=utf-8".into()),
                ("x-empty".into(), String::new()),
            ],
            body: Bytes::from_static(body),
            stored_at: 1_700_000_000,
            fresh_until: 1_700_000_060,
            stale_until: 1_700_000_120,
        }
    }

    #[test]
    fn binary_payload_roundtrips() {
        let entry = sample_entry(b"hello world");
        let raw = encode_entry(&entry);
        let decoded = decode_entry(&raw).expect("decode");
        assert_eq!(decoded.status, entry.status);
        assert_eq!(decoded.headers, entry.headers);
        assert_eq!(decoded.body, entry.body);
        assert_eq!(decoded.stored_at, entry.stored_at);
        assert_eq!(decoded.fresh_until, entry.fresh_until);
        assert_eq!(decoded.stale_until, entry.stale_until);
    }

    /// The body must be stored verbatim: base64 used to inflate every object by
    /// 33% and cost a decode on every L2 hit.
    #[test]
    fn binary_payload_does_not_inflate_the_body() {
        let body = vec![7_u8; 100_000];
        let entry = L2Entry {
            body: Bytes::from(body.clone()),
            ..sample_entry(b"")
        };
        let raw = encode_entry(&entry);
        assert_eq!(&raw[..2], b"L2");
        assert!(
            raw.len() < body.len() + 256,
            "payload {} should not inflate a {} byte body",
            raw.len(),
            body.len()
        );
        assert_eq!(decode_entry(&raw).unwrap().body, Bytes::from(body));
    }

    #[test]
    fn payload_rejects_wrong_magic_version_or_truncation() {
        let raw = encode_entry(&sample_entry(b"payload"));

        let mut bad_magic = raw.clone();
        bad_magic[0] = b'X';
        assert!(decode_entry(&bad_magic).is_none());

        let mut bad_version = raw.clone();
        bad_version[2] = 99;
        assert!(
            decode_entry(&bad_version).is_none(),
            "format version must match"
        );

        for cut in [0, 1, 5, raw.len() / 2, raw.len() - 1] {
            assert!(
                decode_entry(&raw[..cut]).is_none(),
                "truncated payload at {cut} must not decode"
            );
        }
    }

    #[test]
    fn keys_are_namespaced_by_format_version() {
        assert_eq!(
            namespaced_key("lagran:cache", "GET:a.test/x"),
            format!("lagran:cache:{L2_KEY_VERSION}:GET:a.test/x")
        );
        // The namespace is part of the key, so a format bump cannot collide
        // with (or misparse) entries written by the previous format.
        assert!(namespaced_key("p", "k").starts_with("p:v"));
    }

    #[tokio::test]
    async fn l2_is_shared_between_local_instances() {
        let url = std::env::var("CACHE_REDIS_URL")
            .or_else(|_| std::env::var("REDIS_URL"))
            .unwrap_or_else(|_| "redis://127.0.0.1/".into());
        let prefix = format!("lagran:test:l2:{}", std::process::id());
        let local1 = Arc::new(MemoryCache::new(10)) as SharedCache;
        let local2 = Arc::new(MemoryCache::new(10)) as SharedCache;
        let c1 = match RedisL2Cache::connect(local1, &url, prefix.clone(), 1024 * 1024).await {
            Ok(c) => c,
            Err(_) => return,
        };
        let c2 = match RedisL2Cache::connect(local2, &url, prefix.clone(), 1024 * 1024).await {
            Ok(c) => c,
            Err(_) => return,
        };
        let entry = CacheEntry::new(
            200,
            vec![("x".into(), "y".into())],
            Bytes::from_static(b"hello"),
        );
        c1.set("k", entry, 60).await;
        let (result, source) = c2.get_result_with_source("k").await;
        match result {
            CacheGetResult::Hit(e) => assert_eq!(e.body, Bytes::from_static(b"hello")),
            other => panic!("expected L2 hit, got {other:?}"),
        }
        assert_eq!(source, CacheSource::L2);
        let (_, source) = c2.get_result_with_source("k").await;
        assert_eq!(source, CacheSource::L1);
        c1.clear().await;
    }

    #[tokio::test]
    async fn l2_tag_index_purges_without_scan() {
        let url = std::env::var("CACHE_REDIS_URL")
            .or_else(|_| std::env::var("REDIS_URL"))
            .unwrap_or_else(|_| "redis://127.0.0.1/".into());
        let prefix = format!("lagran:test:l2tag:{}", std::process::id());
        let c1 = match RedisL2Cache::connect(
            Arc::new(MemoryCache::new(10)) as SharedCache,
            &url,
            prefix.clone(),
            1024 * 1024,
        )
        .await
        {
            Ok(c) => c,
            Err(_) => return,
        };
        let c2 = RedisL2Cache::connect(
            Arc::new(MemoryCache::new(10)) as SharedCache,
            &url,
            prefix.clone(),
            1024 * 1024,
        )
        .await
        .unwrap();
        let entry = CacheEntry::new(
            200,
            vec![("surrogate-key".into(), "foo bar".into())],
            Bytes::from_static(b"tagged"),
        );
        c1.set("GET:tag.test:/x", entry, 60).await;
        assert!(c2.purge_tags(&["foo".into()], "tag.test").await >= 1);
        assert!(matches!(
            c2.get_result("GET:tag.test:/x").await,
            CacheGetResult::Miss
        ));
        c1.clear().await;
    }
}
