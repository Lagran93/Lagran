//! Short-lived DNS cache for native Pingora origin connections.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::lookup_host;
use tokio::sync::RwLock;

struct DnsEntry {
    addresses: Vec<SocketAddr>,
    expires_at: Instant,
}

pub(crate) struct OriginDnsCache {
    entries: RwLock<HashMap<(String, u16), DnsEntry>>,
    /// One async mutex per `(host, port)` so a TTL refresh is performed once.
    ///
    /// Without it every request that arrived while the lookup was in flight
    /// started its own resolver query, so a slow or unreachable DNS server
    /// turned one refresh into a burst of requests, each of which then held a
    /// flight lock for its whole timeout.
    lookups: std::sync::Mutex<HashMap<(String, u16), Arc<tokio::sync::Mutex<()>>>>,
    ttl: Duration,
    /// Bound on one resolver call. `lookup_host` has no timeout of its own and
    /// can sit in the resolver's retry budget for tens of seconds, which is how
    /// a "slow site" wave appeared every DNS TTL.
    timeout: Duration,
    next_address: AtomicUsize,
}

impl OriginDnsCache {
    pub(crate) fn new() -> Self {
        let ttl = std::env::var("ORIGIN_DNS_TTL_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(30)
            .clamp(1, 300);
        let timeout_ms = std::env::var("ORIGIN_DNS_TIMEOUT_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(3_000)
            .clamp(100, 30_000);
        Self::with_ttl_and_timeout(
            Duration::from_secs(ttl),
            Duration::from_millis(timeout_ms),
        )
    }

    #[cfg(test)]
    fn with_ttl(ttl: Duration) -> Self {
        Self::with_ttl_and_timeout(ttl, Duration::from_secs(3))
    }

    fn with_ttl_and_timeout(ttl: Duration, timeout: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            lookups: std::sync::Mutex::new(HashMap::new()),
            ttl,
            timeout,
            next_address: AtomicUsize::new(0),
        }
    }

    pub(crate) async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        self.resolve_with(host, port, |host, port| async move {
            Ok(lookup_host((host.as_str(), port)).await?.collect())
        })
        .await
    }

    async fn resolve_with<F, Fut>(
        &self,
        host: &str,
        port: u16,
        resolver: F,
    ) -> io::Result<Vec<SocketAddr>>
    where
        F: FnOnce(String, u16) -> Fut,
        Fut: std::future::Future<Output = io::Result<Vec<SocketAddr>>>,
    {
        let key = (host.to_ascii_lowercase(), port);
        if let Some(addresses) = self.cached(&key).await {
            return Ok(self.rotate(addresses));
        }

        // Single-flight: the first request after expiry performs the lookup and
        // concurrent requests wait for its result instead of starting their own.
        let gate = {
            let mut lookups = self
                .lookups
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if lookups.len() > 256 {
                lookups.retain(|_, gate| Arc::strong_count(gate) > 1);
            }
            lookups
                .entry(key.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let _gate = gate.lock().await;
        // Another request may have refreshed the entry while this one waited.
        if let Some(addresses) = self.cached(&key).await {
            return Ok(self.rotate(addresses));
        }

        let mut addresses = tokio::time::timeout(self.timeout, resolver(key.0.clone(), port))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "origin DNS lookup for {} timed out after {:?} (ORIGIN_DNS_TIMEOUT_MS)",
                        key.0, self.timeout
                    ),
                )
            })??;
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "origin DNS returned no addresses",
            ));
        }

        let mut entries = self.entries.write().await;
        let now = Instant::now();
        if let Some(entry) = entries.get(&key).filter(|entry| entry.expires_at > now) {
            addresses = entry.addresses.clone();
        } else {
            entries.retain(|_, entry| entry.expires_at > now);
            entries.insert(
                key,
                DnsEntry {
                    addresses: addresses.clone(),
                    expires_at: now + self.ttl,
                },
            );
        }
        drop(entries);
        Ok(self.rotate(addresses))
    }

    async fn cached(&self, key: &(String, u16)) -> Option<Vec<SocketAddr>> {
        self.entries
            .read()
            .await
            .get(key)
            .filter(|entry| entry.expires_at > Instant::now())
            .map(|entry| entry.addresses.clone())
    }

    fn rotate(&self, mut addresses: Vec<SocketAddr>) -> Vec<SocketAddr> {
        if addresses.len() > 1 {
            let start = self.next_address.fetch_add(1, Ordering::Relaxed) % addresses.len();
            addresses.rotate_left(start);
        }
        addresses
    }
}

#[cfg(test)]
mod tests {
    use super::OriginDnsCache;
    use std::io;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    fn address(raw: &str) -> SocketAddr {
        raw.parse().unwrap()
    }

    #[tokio::test]
    async fn caches_all_addresses_and_refreshes_after_ttl() {
        let cache = OriginDnsCache::with_ttl(Duration::from_millis(20));
        let calls = Arc::new(AtomicUsize::new(0));
        let first_call = calls.clone();
        let addresses = cache
            .resolve_with("origin.example", 443, move |_, _| async move {
                first_call.fetch_add(1, Ordering::SeqCst);
                Ok(vec![address("192.0.2.1:443"), address("192.0.2.2:443")])
            })
            .await
            .unwrap();
        assert_eq!(addresses.len(), 2);

        let cached_call = calls.clone();
        let cached = cache
            .resolve_with("ORIGIN.EXAMPLE", 443, move |_, _| async move {
                cached_call.fetch_add(1, Ordering::SeqCst);
                Ok(vec![address("192.0.2.3:443")])
            })
            .await
            .unwrap();
        assert_eq!(cached.len(), 2);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        tokio::time::sleep(Duration::from_millis(30)).await;
        let refreshed_call = calls.clone();
        let refreshed = cache
            .resolve_with("origin.example", 443, move |_, _| async move {
                refreshed_call.fetch_add(1, Ordering::SeqCst);
                Ok(vec![address("192.0.2.3:443")])
            })
            .await
            .unwrap();
        assert_eq!(refreshed, vec![address("192.0.2.3:443")]);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn rotates_the_start_address_without_dropping_candidates() {
        let cache = OriginDnsCache::with_ttl(Duration::from_secs(1));
        let resolve = |_, _| async { Ok(vec![address("192.0.2.1:443"), address("192.0.2.2:443")]) };
        let first = cache
            .resolve_with("origin.example", 443, resolve)
            .await
            .unwrap();
        let second = cache
            .resolve_with("origin.example", 443, resolve)
            .await
            .unwrap();
        assert_ne!(first[0], second[0]);
        assert_eq!(first.len(), 2);
        assert_eq!(second.len(), 2);
    }

    #[tokio::test]
    async fn failed_refresh_does_not_keep_serving_expired_addresses() {
        let cache = OriginDnsCache::with_ttl(Duration::from_millis(10));
        cache
            .resolve_with("origin.example", 443, |_, _| async {
                Ok(vec![address("192.0.2.1:443")])
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let result = cache
            .resolve_with("origin.example", 443, |_, _| async {
                Err(io::Error::new(io::ErrorKind::NotFound, "DNS unavailable"))
            })
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn slow_resolver_is_timed_out() {
        let cache =
            OriginDnsCache::with_ttl_and_timeout(Duration::from_secs(1), Duration::from_millis(20));
        let result = cache
            .resolve_with("slow.example", 443, |_, _| async {
                tokio::time::sleep(Duration::from_millis(200)).await;
                Ok(vec![address("192.0.2.1:443")])
            })
            .await;
        let err = result.expect_err("a resolver that outlives the budget must fail");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    /// One refresh, not one per waiting request.
    ///
    /// Before single-flight, every request that arrived while the lookup was in
    /// flight started its own resolver query. With a slow resolver that became a
    /// burst of lookups, each holding a flight lock for the whole timeout.
    #[tokio::test]
    async fn concurrent_refreshes_share_one_lookup() {
        let cache = Arc::new(OriginDnsCache::with_ttl(Duration::from_secs(1)));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let cache = cache.clone();
            let calls = calls.clone();
            tasks.push(tokio::spawn(async move {
                cache
                    .resolve_with("one.example", 443, move |_, _| async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(30)).await;
                        Ok(vec![address("192.0.2.1:443")])
                    })
                    .await
            }));
        }
        for task in tasks {
            assert_eq!(task.await.unwrap().unwrap().len(), 1);
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a refresh must run once, not once per waiting request"
        );
    }
}
