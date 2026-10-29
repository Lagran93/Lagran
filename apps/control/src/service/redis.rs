//! Optional Redis integration for shared ephemeral state.
//!
//! Redis is deliberately optional: every caller must degrade to PostgreSQL or
//! the existing in-process fallback when `REDIS_URL` is unset or Redis becomes
//! unavailable. Redis is never used as the source of truth.

use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Script};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::time::Duration;
use uuid::Uuid;

const OP_TIMEOUT: Duration = Duration::from_millis(50);

#[derive(Clone)]
pub struct RedisService {
    conn: ConnectionManager,
}

pub struct LockToken {
    pub key: String,
    pub token: String,
}

impl RedisService {
    pub async fn connect(url: &str) -> Result<Self, String> {
        let client = redis::Client::open(url).map_err(|e| format!("invalid REDIS_URL: {e}"))?;
        let conn = tokio::time::timeout(
            Duration::from_secs(2),
            client.get_connection_manager(),
        )
        .await
        .map_err(|_| "redis connection timeout".to_string())?
        .map_err(|e| format!("redis connection failed: {e}"))?;
        Ok(Self { conn })
    }

    async fn conn(&self) -> ConnectionManager {
        self.conn.clone()
    }

    pub async fn get(&self, key: &str) -> Option<String> {
        let mut conn = self.conn().await;
        tokio::time::timeout(OP_TIMEOUT, conn.get(key))
            .await
            .ok()?
            .ok()
            .flatten()
    }

    pub async fn set_ex(&self, key: &str, value: &str, ttl_secs: u64) -> bool {
        let mut conn = self.conn().await;
        matches!(
            tokio::time::timeout(
                OP_TIMEOUT,
                conn.set_ex::<_, _, ()>(key, value, ttl_secs),
            )
            .await,
            Ok(Ok(()))
        )
    }

    pub async fn getdel(&self, key: &str) -> Option<String> {
        let mut conn = self.conn().await;
        let result: Option<Result<Option<String>, redis::RedisError>> = tokio::time::timeout(
            OP_TIMEOUT,
            redis::cmd("GETDEL")
                .arg(key)
                .query_async::<Option<String>>(&mut conn),
        )
        .await
        .ok();
        result?.ok()?
    }

    /// Same as `getdel`, but distinguishes an absent key (`Ok(None)`) from a
    /// Redis error (`Err`). Used where Redis must remain authoritative.
    pub async fn getdel_checked(&self, key: &str) -> Result<Option<String>, ()> {
        let mut conn = self.conn().await;
        let result = tokio::time::timeout(
            OP_TIMEOUT,
            redis::cmd("GETDEL")
                .arg(key)
                .query_async::<Option<String>>(&mut conn),
        )
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
        Ok(result)
    }

    pub async fn del(&self, key: &str) {
        let mut conn = self.conn().await;
        let _ = tokio::time::timeout(OP_TIMEOUT, conn.del::<_, i64>(key)).await;
    }

    pub async fn invalidate_session(&self, user_id: Uuid) {
        self.del(&format!("lagran:session:{user_id}")).await;
    }

    pub async fn incr_with_ttl(&self, key: &str, ttl_secs: u64) -> Option<i64> {
        let script = Script::new(
            r#"
            local n = redis.call("INCR", KEYS[1])
            if n == 1 then
                redis.call("EXPIRE", KEYS[1], ARGV[1])
            end
            return n
            "#,
        );
        let mut conn = self.conn().await;
        tokio::time::timeout(
            OP_TIMEOUT,
            script.key(key).arg(ttl_secs as i64).invoke_async::<i64>(&mut conn),
        )
        .await
        .ok()?
        .ok()
    }

    pub async fn get_json<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        let raw = self.get(key).await?;
        serde_json::from_str(&raw).ok()
    }

    pub async fn set_json<T: Serialize>(&self, key: &str, value: &T, ttl_secs: u64) -> bool {
        match serde_json::to_string(value) {
            Ok(raw) => self.set_ex(key, &raw, ttl_secs).await,
            Err(_) => false,
        }
    }

    /// SET NX PX. Returns a token only when the caller acquired the lock.
    /// `Ok(None)` means another replica holds the lock; `Err(())` means Redis
    /// is unavailable and the caller should run its normal fallback path.
    pub async fn try_lock(&self, key: &str, ttl: Duration) -> Result<Option<LockToken>, ()> {
        let token = Uuid::new_v4().to_string();
        let mut conn = self.conn().await;
        let result: Result<Option<String>, _> = tokio::time::timeout(
            OP_TIMEOUT,
            redis::cmd("SET")
                .arg(key)
                .arg(&token)
                .arg("NX")
                .arg("PX")
                .arg(ttl.as_millis() as u64)
                .query_async(&mut conn),
        )
        .await
        .map_err(|_| ())?;
        match result {
            Ok(Some(_)) => Ok(Some(LockToken {
                key: key.to_string(),
                token,
            })),
            Ok(None) => Ok(None),
            Err(_) => Err(()),
        }
    }

    pub async fn unlock(&self, lock: &LockToken) {
        let script = Script::new(
            r#"
            if redis.call("GET", KEYS[1]) == ARGV[1] then
                return redis.call("DEL", KEYS[1])
            end
            return 0
            "#,
        );
        let mut conn = self.conn().await;
        let _ = tokio::time::timeout(
            OP_TIMEOUT,
            script.key(&lock.key).arg(&lock.token).invoke_async::<i64>(&mut conn),
        )
        .await;
    }

    /// Increment realtime global/per-domain counters. Failures are ignored by
    /// the caller; PostgreSQL remains the durable metrics store.
    pub async fn record_realtime_metrics(
        &self,
        minute: i64,
        rows: &[(String, i64, i64, i64, i64)],
    ) -> bool {
        if rows.is_empty() {
            return true;
        }
        let mut conn = self.conn().await;
        let mut pipe = redis::pipe();
        for (domain, requests, hits, misses, bytes) in rows {
            for key in [
                format!("lagran:rt:{minute}:__all"),
                format!("lagran:rt:{minute}:{domain}"),
            ] {
                pipe.hincr(&key, "requests", *requests)
                    .ignore()
                    .hincr(&key, "cache_hits", *hits)
                    .ignore()
                    .hincr(&key, "cache_misses", *misses)
                    .ignore()
                    .hincr(&key, "bytes_sent", *bytes)
                    .ignore()
                    .expire(&key, 7200)
                    .ignore();
            }
            pipe.sadd("lagran:rt:domains", domain).ignore();
        }
        pipe.expire("lagran:rt:domains", 7200).ignore();
        matches!(
            tokio::time::timeout(Duration::from_millis(300), pipe.query_async::<()>(&mut conn)).await,
            Ok(Ok(()))
        )
    }

    pub async fn realtime_totals(&self, minute: i64) -> Option<(i64, i64, i64, i64)> {
        let mut conn = self.conn().await;
        let fields: std::collections::HashMap<String, i64> = tokio::time::timeout(
            OP_TIMEOUT,
            conn.hgetall(format!("lagran:rt:{minute}:__all")),
        )
        .await
        .ok()?
        .ok()?;
        Some((
            *fields.get("requests").unwrap_or(&0),
            *fields.get("cache_hits").unwrap_or(&0),
            *fields.get("cache_misses").unwrap_or(&0),
            *fields.get("bytes_sent").unwrap_or(&0),
        ))
    }

    pub async fn realtime_domains(&self) -> Vec<String> {
        let mut conn = self.conn().await;
        tokio::time::timeout(OP_TIMEOUT, conn.smembers("lagran:rt:domains"))
            .await
            .ok()
            .and_then(|r| r.ok())
            .unwrap_or_default()
    }

    pub async fn realtime_domain_totals(
        &self,
        minute: i64,
        domain: &str,
    ) -> Option<(i64, i64, i64, i64)> {
        let mut conn = self.conn().await;
        let fields: std::collections::HashMap<String, i64> = tokio::time::timeout(
            OP_TIMEOUT,
            conn.hgetall(format!("lagran:rt:{minute}:{domain}")),
        )
        .await
        .ok()?
        .ok()?;
        Some((
            *fields.get("requests").unwrap_or(&0),
            *fields.get("cache_hits").unwrap_or(&0),
            *fields.get("cache_misses").unwrap_or(&0),
            *fields.get("bytes_sent").unwrap_or(&0),
        ))
    }
}

pub fn redis_enabled(state: &crate::state::AppState) -> bool {
    state.redis.is_some()
}
