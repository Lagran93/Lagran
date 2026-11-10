//! Short-lived DNS cache for native Pingora origin connections.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::net::lookup_host;
use tokio::sync::RwLock;

struct DnsEntry {
    addresses: Vec<SocketAddr>,
    expires_at: Instant,
}

pub(crate) struct OriginDnsCache {
    entries: RwLock<HashMap<(String, u16), DnsEntry>>,
    ttl: Duration,
    next_address: AtomicUsize,
}

impl OriginDnsCache {
    pub(crate) fn new() -> Self {
        let ttl = std::env::var("ORIGIN_DNS_TTL_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(30)
            .clamp(1, 300);
        Self::with_ttl(Duration::from_secs(ttl))
    }

    fn with_ttl(ttl: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl,
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

        let mut addresses = resolver(key.0.clone(), port).await?;
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
}
