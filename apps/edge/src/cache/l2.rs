//! Redis L2 cache shared by all edge nodes.
//!
//! The local backend remains the hot path. On a local miss the L2 is checked,
//! and successful L2 hits are promoted into the local cache. Writes go to both
//! layers. Redis failures fall back to local-only behavior so a degraded L2
//! never takes the data plane down.

use async_trait::async_trait;
use base64::Engine;
use bytes::Bytes;
use lagran_cache::{CacheBackend, CacheEntry, CacheGetResult, SharedCache};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const REDIS_TIMEOUT: Duration = Duration::from_millis(250);

#[derive(Serialize, Deserialize)]
struct L2Entry {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
    stored_at: u64,
    fresh_until: u64,
    stale_until: u64,
}

pub struct RedisL2Cache {
    local: SharedCache,
    conn: redis::aio::ConnectionManager,
    prefix: String,
    max_body: usize,
    fail_until_ms: Arc<AtomicU64>,
}

impl RedisL2Cache {
    pub async fn connect(
        local: SharedCache,
        url: &str,
        prefix: String,
        max_body: usize,
    ) -> Result<Self, String> {
        let client = redis::Client::open(url).map_err(|e| format!("invalid CACHE_REDIS_URL: {e}"))?;
        let conn = tokio::time::timeout(Duration::from_secs(2), client.get_connection_manager())
            .await
            .map_err(|_| "cache redis connection timeout".to_string())?
            .map_err(|e| format!("cache redis connection failed: {e}"))?;
        Ok(Self {
            local,
            conn,
            prefix,
            max_body: max_body.clamp(1024, 64 * 1024 * 1024),
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

    fn key(&self, key: &str) -> String {
        format!("{}:{}", self.prefix, key)
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
        format!("{}:tagidx:{}", self.prefix, tag.to_ascii_lowercase())
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
        let raw: Option<String> = match tokio::time::timeout(
            REDIS_TIMEOUT,
            conn.get(self.key(key)),
        )
        .await
        {
            Ok(Ok(value)) => value,
            _ => {
                self.mark_failed();
                return None;
            }
        };
        let raw = raw?;
        match serde_json::from_str::<L2Entry>(&raw) {
            Ok(entry) => Some(entry),
            Err(_) => None,
        }
    }

    async fn redis_set(&self, key: &str, entry: L2Entry) {
        if self.unhealthy() || entry.body.is_empty() && entry.headers.is_empty() {
            return;
        }
        let ttl = entry.stale_until.saturating_sub(Self::now_secs()).max(1);
        let Ok(raw) = serde_json::to_string(&entry) else {
            return;
        };
        if raw.len() > self.max_body {
            return;
        }
        let mut conn = self.conn.clone();
        let result: redis::RedisResult<()> = tokio::time::timeout(
            REDIS_TIMEOUT,
            conn.set_ex(self.key(key), raw, ttl),
        )
        .await
        .unwrap_or_else(|_| Err(redis::RedisError::from(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "cache redis set timeout",
        ))));
        if result.is_err() {
            self.mark_failed();
        }
    }

    async fn redis_del(&self, key: &str) {
        if self.unhealthy() {
            return;
        }
        let mut conn = self.conn.clone();
        let result: redis::RedisResult<usize> =
            match tokio::time::timeout(REDIS_TIMEOUT, conn.del(self.key(key))).await {
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

    async fn redis_scan_keys(&self, pattern: &str) -> Vec<String> {        if self.unhealthy() {
            return Vec::new();
        }
        let mut conn = self.conn.clone();
        let mut cursor = 0_u64;
        let mut keys = Vec::new();
        loop {
            let result: redis::RedisResult<(u64, Vec<String>)> = tokio::time::timeout(
                REDIS_TIMEOUT,
                redis::cmd("SCAN")
                    .arg(cursor)
                    .arg("MATCH")
                    .arg(format!("{}:{}", self.prefix, pattern))
                    .arg("COUNT")
                    .arg(500)
                    .query_async(&mut conn),
            )
            .await
            .unwrap_or_else(|_| Err(redis::RedisError::from(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "cache redis scan timeout",
            ))));
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

impl RedisL2Cache {
    async fn index_tags(&self, key: &str, tags: &[String], ttl_secs: u64) {
        if tags.is_empty() || self.unhealthy() {
            return;
        }
        let mut pipe = redis::pipe();
        for tag in tags {
            let index = self.tag_index_key(tag);
            pipe.sadd(&index, key).ignore();
            pipe.expire(&index, ttl_secs.max(60) as i64).ignore();
        }
        let mut conn = self.conn.clone();
        match tokio::time::timeout(REDIS_TIMEOUT, pipe.query_async::<()>(&mut conn)).await {
            Ok(Ok(_)) => {}
            _ => self.mark_failed(),
        }
    }


}
#[async_trait]
impl CacheBackend for RedisL2Cache {
    async fn get_result(&self, key: &str) -> CacheGetResult {
        match self.local.get_result(key).await {
            CacheGetResult::Hit(entry) => return CacheGetResult::Hit(entry),
            CacheGetResult::Stale(entry) => return CacheGetResult::Stale(entry),
            CacheGetResult::Expired | CacheGetResult::Miss => {}
        }
        let Some(entry) = self.redis_get(key).await else {
            return CacheGetResult::Miss;
        };
        let now = Self::now_secs();
        if now > entry.stale_until {
            self.redis_del(key).await;
            return CacheGetResult::Miss;
        }
        let body = B64.decode(entry.body.as_bytes()).unwrap_or_default();
        let local_entry = CacheEntry {
            status: entry.status,
            headers: entry.headers,
            body: Bytes::from(body),
            stored_at_epoch_secs: entry.stored_at,
            fresh_until_epoch_secs: entry.fresh_until,
            stale_until_epoch_secs: entry.stale_until,
        };
        let fresh = now <= entry.fresh_until;
        let ttl = entry.fresh_until.saturating_sub(now).max(1);
        let swr = entry.stale_until.saturating_sub(entry.fresh_until);
        self.local
            .set_with_swr(key, local_entry.clone(), ttl, swr)
            .await;
        if fresh {
            CacheGetResult::Hit(local_entry)
        } else {
            CacheGetResult::Stale(local_entry)
        }
    }

    async fn set(&self, key: &str, entry: CacheEntry, ttl_secs: u64) {
        self.set_with_swr(key, entry, ttl_secs, 0).await;
    }

    async fn set_with_swr(&self, key: &str, entry: CacheEntry, fresh_secs: u64, swr_secs: u64) {
        let tags = Self::cache_tags(&entry.headers);
        self.local
            .set_with_swr(key, entry.clone(), fresh_secs, swr_secs)
            .await;
        let now = Self::now_secs();
        let l2 = L2Entry {
            status: entry.status,
            headers: entry.headers,
            body: B64.encode(&entry.body),
            stored_at: now,
            fresh_until: now + fresh_secs.max(1),
            stale_until: now + fresh_secs.max(1) + swr_secs,
        };
        self.redis_set(key, l2).await;
        self.index_tags(key, &tags, fresh_secs.max(1) + swr_secs + 300).await;
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
            tokio::time::timeout(REDIS_TIMEOUT, conn.del(keys)).await.unwrap_or(Ok(0));
    }

    async fn purge_matching(&self, patterns: &[String]) -> u64 {
        let mut removed = self.local.purge_matching(patterns).await;
        for pattern in patterns {
            let keys = self.redis_scan_keys(&format!("*{}*", Self::glob_escape(pattern))).await;
            if keys.is_empty() {
                continue;
            }
            let mut conn = self.conn.clone();
            if let Ok(Ok(n)) = tokio::time::timeout(REDIS_TIMEOUT, conn.del::<_, usize>(keys)).await {
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
            let result: redis::RedisResult<Vec<String>> = tokio::time::timeout(
                REDIS_TIMEOUT,
                conn.smembers(self.tag_index_key(tag)),
            )
            .await
            .unwrap_or(Ok(Vec::new()));
            if let Ok(keys) = result {
                candidates.extend(keys);
            }
        }
        // Entries written before the tag index existed have no members yet.
        // Fall back to a domain scan only in that case.
        if candidates.is_empty() {
            candidates.extend(
                self.redis_scan_keys(&format!("*{}*", Self::glob_escape(domain)))
                    .await,
            );
        }
        let mut victims = Vec::new();
        for key in candidates {
            if !key.contains(domain) {
                continue;
            }
            let Ok(Ok(Some(raw))) =
                tokio::time::timeout(REDIS_TIMEOUT, conn.get::<_, Option<String>>(self.key(&key)))
                    .await
            else {
                continue;
            };
            let Ok(entry) = serde_json::from_str::<L2Entry>(&raw) else {
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
        match tokio::time::timeout(REDIS_TIMEOUT, pipe.query_async::<()>(&mut conn)).await {
            Ok(Ok(_)) => {}
            _ => self.mark_failed(),
        }
        let redis_keys: Vec<String> = victims.iter().map(|key| self.key(key)).collect();
        let n: usize = tokio::time::timeout(REDIS_TIMEOUT, conn.del::<_, usize>(redis_keys))
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
        match c2.get_result("k").await {
            CacheGetResult::Hit(e) => assert_eq!(e.body, Bytes::from_static(b"hello")),
            other => panic!("expected L2 hit, got {other:?}"),
        }
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
        assert!(matches!(c2.get_result("GET:tag.test:/x").await, CacheGetResult::Miss));
        c1.clear().await;
    }
}
