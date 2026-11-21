//! In-process login/register rate limit by client key (email or IP).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::service::redis::RedisService;

const WINDOW: Duration = Duration::from_secs(60);
const MAX_ATTEMPTS: u32 = 20;
/// Per-client-IP budget. Higher than the per-email one so a shared NAT is not
/// locked out by one user, but low enough to make spraying expensive.
pub const LOGIN_IP_LIMIT: u32 = 60;

#[derive(Default)]
struct Bucket {
    count: u32,
    window_start: Option<Instant>,
}

pub struct LoginLimiter {
    inner: Mutex<HashMap<String, Bucket>>,
}

impl LoginLimiter {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Shared Redis counter when configured, local bucket otherwise.
    #[allow(dead_code)]
    pub async fn check_shared(&self, redis: Option<&RedisService>, key: &str) -> bool {
        if let Some(redis) = redis {
            if let Some(count) = redis
                .incr_with_ttl(&format!("lagran:rl:{key}"), WINDOW.as_secs())
                .await
            {
                return count <= i64::from(MAX_ATTEMPTS);
            }
        }
        self.check(key)
    }

    /// Whether the key is currently below `limit`, without consuming a slot.
    pub async fn peek_shared(
        &self,
        redis: Option<&RedisService>,
        key: &str,
        limit: u32,
    ) -> bool {
        if let Some(redis) = redis {
            if let Some(raw) = redis.get(&format!("lagran:rl:{key}")).await {
                if let Ok(count) = raw.parse::<i64>() {
                    return count < i64::from(limit);
                }
            }
            return true;
        }
        self.peek(key, limit)
    }

    pub fn peek(&self, key: &str, limit: u32) -> bool {
        let map = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return true,
        };
        let Some(bucket) = map.get(key) else {
            return true;
        };
        match bucket.window_start {
            Some(start) if start.elapsed() < WINDOW => bucket.count < limit,
            _ => true,
        }
    }

    /// Record one failure (the window is created on the first failure).
    pub async fn record_failure_shared(&self, redis: Option<&RedisService>, key: &str) {
        if let Some(redis) = redis {
            let _ = redis
                .incr_with_ttl(&format!("lagran:rl:{key}"), WINDOW.as_secs())
                .await;
        } else {
            self.record_failure(key);
        }
    }

    /// Increment a local failure counter without applying `MAX_ATTEMPTS`.
    ///
    /// `check` is the registration gate and stops incrementing at 20. Reusing it
    /// here capped the IP bucket at 20, so `peek(key, LOGIN_IP_LIMIT)` kept
    /// returning true after the 20th failure and never enforced the 60/min IP
    /// budget. The login handler applies its own limit via `peek`.
    fn record_failure(&self, key: &str) {
        let mut map = match self.inner.lock() {
            Ok(map) => map,
            Err(_) => return,
        };
        let now = Instant::now();
        if map.len() > 10_000 {
            map.retain(|_, bucket| {
                bucket
                    .window_start
                    .map(|start| now.duration_since(start) < WINDOW * 2)
                    .unwrap_or(false)
            });
        }
        let bucket = map.entry(key.to_string()).or_default();
        match bucket.window_start {
            Some(start) if now.duration_since(start) < WINDOW => {
                bucket.count = bucket.count.saturating_add(1);
            }
            _ => {
                bucket.window_start = Some(now);
                bucket.count = 1;
            }
        }
    }

    pub async fn clear_shared(&self, redis: Option<&RedisService>, key: &str) {
        if let Some(redis) = redis {
            redis.del(&format!("lagran:rl:{key}")).await;
        } else if let Ok(mut map) = self.inner.lock() {
            map.remove(key);
        }
    }

    /// Returns false when the key is over the limit.
    pub fn check(&self, key: &str) -> bool {
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return true,
        };
        let now = Instant::now();
        // opportunistic cleanup
        if map.len() > 10_000 {
            map.retain(|_, b| {
                b.window_start
                    .map(|s| now.duration_since(s) < WINDOW * 2)
                    .unwrap_or(false)
            });
        }
        let b = map.entry(key.to_string()).or_default();
        match b.window_start {
            Some(start) if now.duration_since(start) < WINDOW => {
                if b.count >= MAX_ATTEMPTS {
                    return false;
                }
                b.count += 1;
                true
            }
            _ => {
                b.window_start = Some(now);
                b.count = 1;
                true
            }
        }
    }
}

impl Default for LoginLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The local fallback must be able to count past the 20-attempt
    /// registration limit; otherwise the 60/min IP budget is never reached.
    #[tokio::test]
    async fn local_failures_reach_the_ip_budget() {
        let limiter = LoginLimiter::new();
        let key = "login-ip:203.0.113.9";
        for _ in 0..MAX_ATTEMPTS {
            limiter.record_failure_shared(None, key).await;
        }
        assert!(limiter.peek(key, LOGIN_IP_LIMIT));

        for _ in MAX_ATTEMPTS..LOGIN_IP_LIMIT {
            limiter.record_failure_shared(None, key).await;
        }
        assert!(!limiter.peek(key, LOGIN_IP_LIMIT));
    }

    #[tokio::test]
    async fn cleared_bucket_starts_over() {
        let limiter = LoginLimiter::new();
        let key = "login:test@example.com";
        for _ in 0..MAX_ATTEMPTS {
            limiter.record_failure_shared(None, key).await;
        }
        assert!(!limiter.peek(key, MAX_ATTEMPTS));
        limiter.clear_shared(None, key).await;
        assert!(limiter.peek(key, MAX_ATTEMPTS));
    }
}
