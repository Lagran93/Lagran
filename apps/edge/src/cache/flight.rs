//! Cross-node request coalescing via Redis SET NX locks.
//!
//! A cold cache miss on many edges can otherwise trigger the same origin fetch
//! on every node. The leader holds a short Redis lock; followers wait for the
//! shared L2 entry instead of racing the origin.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// How long a leader may hold the lock, relative to its origin timeout.
///
/// The TTL has to cover the leader's own fetch, otherwise the lock expires while
/// the leader is still working and a second node starts the same fetch — the
/// opposite of what coalescing is for. A small margin covers the write of the
/// response into L2 after the fetch returns.
const LOCK_TTL_MARGIN_MS: u64 = 2_000;

/// Lower bound for the lock TTL, so a very short origin timeout still leaves the
/// follower something to wait on.
const LOCK_TTL_MIN_MS: u64 = 3_000;

/// Upper bound, matching the largest origin timeout the control plane accepts.
const LOCK_TTL_MAX_MS: u64 = 65_000;

/// How long a follower keeps polling for the leader's result.
///
/// This used to be a fixed 5 s while the lock lived 30 s, so a follower always
/// gave up long before the lock could be released: waiting bought nothing on a
/// cold object and added five seconds of latency on top of the origin fetch it
/// then went on to perform itself. It is now derived from the same timeout as the
/// TTL, and capped just under it so the follower never outlives the lock.
const LOCK_WAIT_RATIO_NUM: u64 = 4;
const LOCK_WAIT_RATIO_DEN: u64 = 5;

/// TTL for a leader whose origin timeout is `origin_timeout_ms`.
pub(crate) fn lock_ttl_ms(origin_timeout_ms: u64) -> u64 {
    origin_timeout_ms
        .saturating_add(LOCK_TTL_MARGIN_MS)
        .clamp(LOCK_TTL_MIN_MS, LOCK_TTL_MAX_MS)
}

/// Follower wait for that same TTL: four fifths of it.
pub(crate) fn lock_wait(ttl_ms: u64) -> Duration {
    Duration::from_millis(ttl_ms * LOCK_WAIT_RATIO_NUM / LOCK_WAIT_RATIO_DEN)
        .max(Duration::from_millis(100))
}

pub struct RedisFlight {
    conn: redis::aio::ConnectionManager,
    prefix: String,
    seq: AtomicU64,
    /// Timeout for one lock round trip (`SET NX`, `EXISTS`, release `EVAL`).
    ///
    /// 250 ms was hardcoded and is tight for a Redis that is not on the same host:
    /// ordinary latency spikes surface as "flight lock unavailable" and the edge
    /// silently stops coalescing. Configurable so a cross-rack deployment can raise
    /// it instead of living with the warning.
    timeout: Duration,
}

impl std::fmt::Debug for RedisFlight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `ConnectionManager` has no `Debug`; the prefix identifies the instance
        // without exposing connection details.
        f.debug_struct("RedisFlight")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct FlightGuard {
    flight: Arc<RedisFlight>,
    key: String,
    token: String,
}

impl Drop for FlightGuard {
    fn drop(&mut self) {
        // A `Drop` cannot await, so the release is handed to the runtime. If the
        // runtime is already shutting down there is no task to hand it to and the
        // key stays locked until its TTL — bounded now by the origin timeout rather
        // than a fixed 30 s, so the cost of a missed release is a few seconds of
        // coalescing for that one key, not half a minute.
        //
        // The explicit path is `FlightGuard::release_now`, which callers on the
        // normal (non-cancelled) route should use so the lock is dropped before the
        // response is written rather than whenever the runtime gets to it.
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

impl FlightGuard {
    /// Release the lock now, awaiting the Redis call.
    ///
    /// Prefer this over dropping the guard: it makes the release deterministic and
    /// lets a caller free the key before doing slow work (writing the response,
    /// logging) so a follower waiting on the same key is unblocked sooner.
    pub async fn release_now(self) {
        // `Drop` still runs, but `release` is idempotent: the Lua script compares
        // the token and returns 0 when the key is already gone.
        self.flight.release(&self.key, &self.token).await;
    }
}

impl RedisFlight {
    pub async fn connect(
        url: &str,
        prefix: String,
        timeout: Duration,
    ) -> Result<Arc<Self>, String> {
        let client =
            redis::Client::open(url).map_err(|e| format!("invalid flight redis url: {e}"))?;
        let conn = tokio::time::timeout(Duration::from_secs(2), client.get_connection_manager())
            .await
            .map_err(|_| "flight redis connection timeout".to_string())?
            .map_err(|e| format!("flight redis connection failed: {e}"))?;
        Ok(Arc::new(Self {
            conn,
            prefix,
            seq: AtomicU64::new(0),
            timeout,
        }))
    }

    fn key(&self, key: &str) -> String {
        format!("{}:flight:{}", self.prefix, key)
    }

    pub(crate) async fn try_lock(
        self: &Arc<Self>,
        key: &str,
        ttl_ms: u64,
    ) -> Result<Option<FlightGuard>, ()> {
        let token = format!(
            "{}:{}",
            std::process::id(),
            self.seq.fetch_add(1, Ordering::Relaxed)
        );
        let mut conn = self.conn.clone();
        let result: Option<String> = tokio::time::timeout(
            self.timeout,
            redis::cmd("SET")
                .arg(self.key(key))
                .arg(&token)
                .arg("NX")
                .arg("PX")
                .arg(ttl_ms)
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

    /// Wait until the current lock owner releases (or the lock TTL expires).
    /// Used by conditional revalidation, where an old cache entry may still
    /// exist while the leader is validating it.
    pub(crate) async fn wait_unlocked(&self, key: &str, wait: Duration) {
        let deadline = tokio::time::Instant::now() + wait;
        let mut conn = self.conn.clone();
        while tokio::time::Instant::now() < deadline {
            let exists = match tokio::time::timeout(
                self.timeout,
                redis::cmd("EXISTS")
                    .arg(self.key(key))
                    .query_async::<i64>(&mut conn),
            )
            .await
            {
                Ok(Ok(value)) => value,
                // Redis is degraded: do not let a missing lock lookup add
                // another five seconds to every conditional request.
                _ => return,
            };
            if exists == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
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
            self.timeout,
            script.key(self.key(key)).arg(token).invoke_async(&mut conn),
        )
        .await
        .unwrap_or(Ok(0));
    }
}

/// What `acquire` decided for this request.
///
/// The old signature returned `Option<FlightGuard>`, where `None` meant either "a
/// follower that already read the leader's result" or "Redis is unavailable" — two
/// very different situations collapsed into one value. Callers could not tell a
/// degraded path from a healthy one, so a Redis outage was invisible: no metric, no
/// log, and an extra L2 read on every request.
#[derive(Debug)]
pub enum FlightOutcome {
    /// This request owns the fetch.
    Leader(FlightGuard),
    /// Another node is fetching; the caller should read the cache or fetch itself.
    Follower,
    /// The lock could not be taken because Redis failed. The caller proceeds as if
    /// it were alone; coalescing is not happening.
    Degraded,
}

impl FlightOutcome {
    /// The guard, if this request is the leader.
    pub fn into_guard(self) -> Option<FlightGuard> {
        match self {
            FlightOutcome::Leader(guard) => Some(guard),
            _ => None,
        }
    }

    pub fn is_degraded(&self) -> bool {
        matches!(self, FlightOutcome::Degraded)
    }
}

/// Try to become the cross-node leader.
pub async fn acquire(
    flight: &Arc<RedisFlight>,
    key: &str,
    origin_timeout_ms: u64,
    cache: &dyn lagran_cache::CacheBackend,
) -> FlightOutcome {
    let ttl_ms = lock_ttl_ms(origin_timeout_ms);
    match flight.try_lock(key, ttl_ms).await {
        Ok(Some(guard)) => return FlightOutcome::Leader(guard),
        Err(_) => {
            tracing::warn!(
                key,
                "flight lock unavailable; proceeding without cross-node coalescing"
            );
            return FlightOutcome::Degraded;
        }
        Ok(None) => {}
    }
    // Follower: wait for the leader to populate shared L2. The window is derived
    // from the same origin timeout as the lock, so it covers a leader that is
    // simply slow rather than only one that died.
    let deadline = tokio::time::Instant::now() + lock_wait(ttl_ms);
    while tokio::time::Instant::now() < deadline {
        if !matches!(
            cache.get_result(key).await,
            lagran_cache::CacheGetResult::Miss | lagran_cache::CacheGetResult::Expired
        ) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    FlightOutcome::Follower
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
            Duration::from_millis(250),
        )
        .await
        {
            Ok(f) => f,
            Err(_) => return,
        };
        let cache = MemoryCache::new(10);
        let key = "GET:flight.test:/a";
        let guard = acquire(&flight, key, 10_000, &cache).await.into_guard();
        assert!(guard.is_some());
        let second = acquire(&flight, key, 10_000, &cache).await;
        assert!(
            !matches!(second, FlightOutcome::Leader(_)),
            "a second node must not lead while the lock is held"
        );
        assert!(!second.is_degraded(), "Redis is up; this is a follower");
        drop(guard);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(acquire(&flight, key, 10_000, &cache)
            .await
            .into_guard()
            .is_some());
    }

    /// The lock must outlive the fetch it protects.
    ///
    /// The TTL used to be a fixed 30 s while the origin timeout is 10 s by
    /// default, and the follower waited a fixed 5 s — so the wait could never see
    /// a release, and a leader that was merely slow (not dead) still had its
    /// followers give up and duplicate the fetch.
    #[test]
    fn lock_ttl_covers_the_origin_timeout() {
        for origin_ms in [1_000u64, 5_000, 10_000, 30_000, 60_000] {
            let ttl = lock_ttl_ms(origin_ms);
            assert!(
                ttl > origin_ms,
                "ttl {ttl}ms must exceed the {origin_ms}ms origin timeout it guards"
            );
            assert!(
                ttl <= LOCK_TTL_MAX_MS,
                "ttl {ttl}ms must stay within the cap"
            );
        }
        // The default origin timeout derives a TTL that covers it with margin.
        assert_eq!(lock_ttl_ms(10_000), 12_000);
    }

    /// The follower window must fit inside the lock, not exceed it.
    #[test]
    fn follower_wait_fits_inside_the_lock() {
        for origin_ms in [1_000u64, 10_000, 60_000] {
            let ttl = lock_ttl_ms(origin_ms);
            let wait = lock_wait(ttl);
            assert!(
                wait.as_millis() as u64 <= ttl,
                "wait {wait:?} must not outlive the {ttl}ms lock"
            );
            assert!(
                wait.as_millis() as u64 >= ttl / 2,
                "wait {wait:?} is too short to cover a slow leader holding a {ttl}ms lock"
            );
        }
        // A tiny timeout still yields a usable minimum.
        assert!(lock_wait(lock_ttl_ms(0)) >= Duration::from_millis(100));
    }

    /// Short origin timeouts are floored so followers still have a window.
    #[test]
    fn lock_ttl_has_a_floor() {
        assert_eq!(lock_ttl_ms(0), LOCK_TTL_MIN_MS);
        assert!(lock_ttl_ms(200) >= LOCK_TTL_MIN_MS);
    }
    /// A Redis failure is reported as degraded, not as a follower.
    ///
    /// Both used to be `None`, so a Redis outage looked identical to "another node
    /// is fetching": no metric, no log, and an extra L2 read per request.
    #[test]
    fn degraded_is_distinguishable_from_follower() {
        assert!(!FlightOutcome::Follower.is_degraded());
        assert!(FlightOutcome::Degraded.is_degraded());
        assert!(
            FlightOutcome::Follower.into_guard().is_none(),
            "only a leader carries a guard"
        );
    }
}
