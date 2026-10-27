//! In-process login/register rate limit by client key (email or IP).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(60);
const MAX_ATTEMPTS: u32 = 20;

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
