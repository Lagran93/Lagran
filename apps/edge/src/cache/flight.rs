//! Cross-node request coalescing via Redis SET NX locks.
//!
//! A cold cache miss on many edges can otherwise trigger the same origin fetch
//! on every node. The leader holds a short Redis lock; followers wait for the
//! shared L2 entry instead of racing the origin.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

const LOCK_TTL_MS: u64 = 30_000;
#[cfg(not(test))]
const LOCK_WAIT: Duration = Duration::from_secs(5);
#[cfg(test)]
const LOCK_WAIT: Duration = Duration::from_millis(100);

pub struct RedisFlight {
    conn: redis::aio::ConnectionManager,
    prefix: String,
    seq: AtomicU64,
}

pub struct FlightGuard {
    flight: Arc<RedisFlight>,
    key: String,
    token: String,
}

impl Drop for FlightGuard {
    fn drop(&mut self) {
        let flight = self.flight.clone();
        let key = self.key.clone();
        let token = self.token.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                flight.release(&key, &token).await;
            });
        }
    }
}

impl RedisFlight {
    pub async fn connect(url: &str, prefix: String) -> Result<Arc<Self>, String> {
        let client = redis::Client::open(url).map_err(|e| format!("invalid flight redis url: {e}"))?;
        let conn = tokio::time::timeout(Duration::from_secs(2), client.get_connection_manager())
            .await
            .map_err(|_| "flight redis connection timeout".to_string())?
            .map_err(|e| format!("flight redis connection failed: {e}"))?;
        Ok(Arc::new(Self {
            conn,
            prefix,
            seq: AtomicU64::new(0),
        }))
    }

    fn key(&self, key: &str) -> String {
        format!("{}:flight:{}", self.prefix, key)
    }

    async fn acquire(self: &Arc<Self>, key: &str) -> Result<Option<FlightGuard>, ()> {
        let token = format!(
            "{}:{}",
            std::process::id(),
            self.seq.fetch_add(1, Ordering::Relaxed)
        );
        let mut conn = self.conn.clone();
        let result: Option<String> = tokio::time::timeout(
            Duration::from_millis(250),
            redis::cmd("SET")
                .arg(self.key(key))
                .arg(&token)
                .arg("NX")
                .arg("PX")
                .arg(LOCK_TTL_MS)
                .query_async(&mut conn),
        )
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
        Ok(result.map(|_| FlightGuard {
            flight: self.clone(),
            key: key.to_string(),
            token,
        }))
    }

    async fn release(&self, key: &str, token: &str) {
        let mut conn = self.conn.clone();
        let script = redis::Script::new(
            r#"
            if redis.call('GET', KEYS[1]) == ARGV[1] then
                return redis.call('DEL', KEYS[1])
            end
            return 0
            "#,
        );
        let _: Result<i64, _> = tokio::time::timeout(
            Duration::from_millis(250),
            script.key(self.key(key)).arg(token).invoke_async(&mut conn),
        )
        .await
        .unwrap_or(Ok(0));
    }
}

/// Try to become the cross-node leader. `None` means another node holds the
/// lock, or Redis is unavailable and the caller should proceed locally.
pub async fn acquire(
    flight: &Arc<RedisFlight>,
    key: &str,
    cache: &dyn lagran_cache::CacheBackend,
) -> Option<FlightGuard> {
    match flight.acquire(key).await {
        Ok(Some(guard)) => return Some(guard),
        Err(_) => return None,
        Ok(None) => {}
    }
    // Follower: wait for the leader to populate shared L2.
    let deadline = tokio::time::Instant::now() + LOCK_WAIT;
    while tokio::time::Instant::now() < deadline {
        if !matches!(
            cache.get_result(key).await,
            lagran_cache::CacheGetResult::Miss
                | lagran_cache::CacheGetResult::Expired
        ) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}


#[cfg(test)]
mod tests {
    use super::*;
    use lagran_cache::MemoryCache;

    #[tokio::test]
    async fn redis_flight_is_exclusive() {
        let url = std::env::var("CACHE_REDIS_URL")
            .or_else(|_| std::env::var("REDIS_URL"))
            .unwrap_or_else(|_| "redis://127.0.0.1/".into());
        let flight = match RedisFlight::connect(
            &url,
            format!("lagran:test:flight:{}", std::process::id()),
        )
        .await
        {
            Ok(f) => f,
            Err(_) => return,
        };
        let cache = MemoryCache::new(10);
        let key = "GET:flight.test:/a";
        let guard = acquire(&flight, key, &cache).await;
        assert!(guard.is_some());
        assert!(acquire(&flight, key, &cache).await.is_none());
        drop(guard);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(acquire(&flight, key, &cache).await.is_some());
    }
}
