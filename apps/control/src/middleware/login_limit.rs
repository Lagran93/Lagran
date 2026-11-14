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
            let _ = self.check(key);
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
