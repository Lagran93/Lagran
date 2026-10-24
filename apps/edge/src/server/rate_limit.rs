//! Per-host token-bucket rate limiter

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

#[derive(Clone, Default)]
pub struct RateLimiter {
    inner: Arc<Mutex<HashMap<String, Bucket>>>,
    /// Global default RPS (0 = off)
    default_rps: u32,
    default_burst: u32,
}

struct Bucket {
    tokens: f64,
    last: Instant,
    rps: f64,
    burst: f64,
}

impl RateLimiter {
    pub fn new(default_rps: u32, default_burst: u32) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            default_rps,
            default_burst,
        }
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
