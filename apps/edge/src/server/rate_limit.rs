//! Per-host token-bucket rate limiter.
//!
//! The process-local bucket remains the fallback. When `REDIS_URL` is set and
//! reachable, the same token bucket is evaluated atomically in Redis so all
//! edge nodes share one budget per domain. The Redis script uses Redis `TIME`
//! as the clock, avoiding skew between edge hosts.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

const REDIS_TIMEOUT: Duration = Duration::from_millis(10);
const REDIS_FAILURE_COOLDOWN_MS: u64 = 5_000;

#[derive(Clone, Default)]
pub struct RateLimiter {
    inner: Arc<Mutex<HashMap<String, Bucket>>>,
    /// Global default RPS (0 = off)
    default_rps: u32,
    default_burst: u32,
    redis: Option<RedisRateLimiter>,
}

struct Bucket {
    tokens: f64,
    last: Instant,
    rps: f64,
    burst: f64,
}

/// Redis-backed token bucket shared by all edge nodes.
#[derive(Clone)]
pub struct RedisRateLimiter {
    conn: redis::aio::ConnectionManager,
    prefix: String,
    /// After a timeout/error, skip Redis for a short cooldown so a degraded
    /// Redis cannot add the timeout to every request.
    fail_until_ms: Arc<AtomicU64>,
}

impl RedisRateLimiter {
    pub async fn connect(url: &str) -> Result<Self, String> {
        let client = redis::Client::open(url).map_err(|e| format!("invalid REDIS_URL: {e}"))?;
        let conn = tokio::time::timeout(Duration::from_secs(2), client.get_connection_manager())
            .await
            .map_err(|_| "redis connection timeout".to_string())?
            .map_err(|e| format!("redis connection failed: {e}"))?;
        let prefix = std::env::var("RATE_LIMIT_REDIS_PREFIX")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "lagran:rate".to_string());
        Ok(Self {
            conn,
            prefix,
            fail_until_ms: Arc::new(AtomicU64::new(0)),
        })
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn mark_failed(&self) {
        self.fail_until_ms
            .store(Self::now_ms() + REDIS_FAILURE_COOLDOWN_MS, Ordering::Relaxed);
    }

    /// Returns `None` when Redis is unavailable or timed out, so the caller can
    /// fall back to the local bucket. A returned `false` is authoritative.
    async fn check(&self, key: &str, rps: u32, burst: u32) -> Option<bool> {
        if rps == 0 {
            return Some(true);
        }
        if Self::now_ms() < self.fail_until_ms.load(Ordering::Relaxed) {
            return None;
        }
        let burst = burst.max(1);
        // Keep state long enough for the bucket to refill, but never forever.
        let ttl_ms = ((f64::from(burst) / f64::from(rps)) * 2000.0)
            .ceil()
            .max(60_000.0) as i64;
        let mut conn = self.conn.clone();
        let script = redis::Script::new(
            r#"
            local t = redis.call('TIME')
            local now = (tonumber(t[1]) * 1000) + math.floor(tonumber(t[2]) / 1000)
            local rate = tonumber(ARGV[1])
            local capacity = tonumber(ARGV[2])
            local ttl = tonumber(ARGV[3])
            local data = redis.call('HMGET', KEYS[1], 'tokens', 'last')
            local tokens = tonumber(data[1])
            local last = tonumber(data[2])
            if not tokens or not last then
                tokens = capacity
                last = now
            end
            local elapsed = math.max(0, now - last) / 1000
            tokens = math.min(capacity, tokens + elapsed * rate)
            local allowed = 0
            if tokens >= 1 then
                tokens = tokens - 1
                allowed = 1
            end
            redis.call('HMSET', KEYS[1], 'tokens', tostring(tokens), 'last', tostring(now))
            redis.call('PEXPIRE', KEYS[1], ttl)
            return allowed
            "#,
        );
        let redis_key = format!("{}:limit:{}", self.prefix, key);
        let result: i64 = match tokio::time::timeout(
            REDIS_TIMEOUT,
            script
                .key(redis_key)
                .arg(f64::from(rps))
                .arg(f64::from(burst))
                .arg(ttl_ms)
                .invoke_async(&mut conn),
        )
        .await
        {
            Ok(Ok(value)) => value,
            _ => {
                self.mark_failed();
                return None;
            }
        };
        Some(result != 0)
    }
}

impl RateLimiter {
    pub fn new(default_rps: u32, default_burst: u32) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            default_rps,
            default_burst,
            redis: None,
        }
    }

    pub async fn with_redis_url(mut self, url: &str) -> Self {
        if url.trim().is_empty() {
            return self;
        }
        match RedisRateLimiter::connect(url).await {
            Ok(redis) => {
                tracing::info!("distributed token-bucket rate limiter enabled");
                self.redis = Some(redis);
            }
            Err(e) => {
                tracing::warn!(error = %e, "rate-limit Redis unavailable; using in-process buckets");
            }
        }
        self
    }

    /// Check and consume one token. Returns true if allowed.
    pub async fn check(&self, key: &str, rps: u32, burst: u32) -> bool {
        let rps = if rps > 0 { rps } else { self.default_rps };
        let burst = if burst > 0 {
            burst
        } else if self.default_burst > 0 {
            self.default_burst
        } else {
            rps.max(1) * 2
        };
        if rps == 0 {
            return true; // unlimited
        }

        if let Some(redis) = self.redis.as_ref() {
            if let Some(allowed) = redis.check(key, rps, burst).await {
                return allowed;
            }
            // Redis outage: fail open to the local bucket rather than taking
            // the whole edge offline.
        }

        let mut map = self.inner.lock().await;
        let now = Instant::now();
        let b = map.entry(key.to_string()).or_insert_with(|| Bucket {
            tokens: burst as f64,
            last: now,
            rps: rps as f64,
            burst: burst as f64,
        });
        // update config if changed
        b.rps = rps as f64;
        b.burst = burst as f64;

        let elapsed = now.duration_since(b.last).as_secs_f64();
        b.last = now;
        b.tokens = (b.tokens + elapsed * b.rps).min(b.burst);
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_bucket_enforces_burst_then_refills() {
        let limiter = RateLimiter::new(0, 0);
        assert!(limiter.check("a.test", 2, 2).await);
        assert!(limiter.check("a.test", 2, 2).await);
        assert!(!limiter.check("a.test", 2, 2).await);
        tokio::time::sleep(Duration::from_millis(550)).await;
        assert!(limiter.check("a.test", 2, 2).await);
    }

    #[tokio::test]
    async fn redis_bucket_is_shared_when_configured() {
        let Ok(url) = std::env::var("REDIS_TEST_URL") else {
            return;
        };
        let key = format!(
            "test:{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let a = RedisRateLimiter::connect(&url).await.expect("redis A");
        let b = RedisRateLimiter::connect(&url).await.expect("redis B");
        assert_eq!(a.check(&key, 2, 2).await, Some(true));
        assert_eq!(b.check(&key, 2, 2).await, Some(true));
        assert_eq!(a.check(&key, 2, 2).await, Some(false));
    }

    #[tokio::test]
    async fn rate_limiter_wires_redis_for_all_edges() {
        let Ok(url) = std::env::var("REDIS_TEST_URL") else {
            return;
        };
        let key = format!(
            "wired:{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let a = RateLimiter::new(0, 0).with_redis_url(&url).await;
        let b = RateLimiter::new(0, 0).with_redis_url(&url).await;
        assert!(a.check(&key, 2, 2).await);
        assert!(b.check(&key, 2, 2).await);
        assert!(!a.check(&key, 2, 2).await);
    }
}
