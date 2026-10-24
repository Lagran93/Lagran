//! Per-domain edge request counters

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Default)]
struct Counters {
    requests: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    bytes_sent: AtomicU64,
}

#[derive(Default)]
pub struct EdgeMetrics {
    by_domain: Mutex<HashMap<String, Arc<Counters>>>,
}

#[derive(Debug, Clone)]
pub struct DomainSnapshot {
    pub domain: String,
    pub requests: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub bytes_sent: u64,
}

impl EdgeMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    async fn bucket(&self, domain: &str) -> Arc<Counters> {
        let key = if domain.is_empty() {
            "(unknown)".to_string()
        } else {
            domain.to_lowercase()
        };
        let mut map = self.by_domain.lock().await;
        map.entry(key)
            .or_insert_with(|| Arc::new(Counters::default()))
            .clone()
    }

    pub async fn record_hit(&self, domain: &str, bytes: u64) {
        let c = self.bucket(domain).await;
        c.requests.fetch_add(1, Ordering::Relaxed);
        c.cache_hits.fetch_add(1, Ordering::Relaxed);
        c.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    pub async fn record_miss(&self, domain: &str, bytes: u64) {
        let c = self.bucket(domain).await;
        c.requests.fetch_add(1, Ordering::Relaxed);
        c.cache_misses.fetch_add(1, Ordering::Relaxed);
        c.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    pub async fn record_bypass(&self, domain: &str, bytes: u64) {
        let c = self.bucket(domain).await;
        c.requests.fetch_add(1, Ordering::Relaxed);
        c.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Snapshot and reset all domain counters for reporting
    pub async fn take_snapshots(&self) -> Vec<DomainSnapshot> {
        let mut map = self.by_domain.lock().await;
        let mut out = Vec::new();
        for (domain, c) in map.iter() {
            let requests = c.requests.swap(0, Ordering::Relaxed);
            let hits = c.cache_hits.swap(0, Ordering::Relaxed);
            let misses = c.cache_misses.swap(0, Ordering::Relaxed);
            let bytes = c.bytes_sent.swap(0, Ordering::Relaxed);
            if requests > 0 || hits > 0 || misses > 0 || bytes > 0 {
                out.push(DomainSnapshot {
                    domain: domain.clone(),
                    requests,
                    cache_hits: hits,
                    cache_misses: misses,
                    bytes_sent: bytes,
                });
            }
        }
        // drop empty buckets to avoid unbounded growth
        map.retain(|_, c| {
            c.requests.load(Ordering::Relaxed) > 0
                || c.cache_hits.load(Ordering::Relaxed) > 0
                || c.cache_misses.load(Ordering::Relaxed) > 0
        });
        out
    }
}
