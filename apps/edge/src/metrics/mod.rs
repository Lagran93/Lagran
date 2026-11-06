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
    origin_timeouts: AtomicU64,
    origin_errors: AtomicU64,
    stream_requests: AtomicU64,
    stream_bytes: AtomicU64,
    stream_errors: AtomicU64,
    datapath_pingora: AtomicU64,
    datapath_legacy: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct GlobalSnapshot {
    pub origin_timeouts: u64,
    pub origin_errors: u64,
    pub stream_requests: u64,
    pub stream_bytes: u64,
    pub stream_errors: u64,
    pub datapath_pingora: u64,
    pub datapath_legacy: u64,
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

    pub fn record_origin_timeout(&self) {
        self.origin_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_origin_error(&self) {
        self.origin_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_stream_start(&self) {
        self.stream_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_stream_bytes(&self, bytes: u64) {
        self.stream_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_stream_error(&self) {
        self.stream_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_pingora_datapath(&self) {
        self.datapath_pingora.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_legacy_datapath(&self) {
        self.datapath_legacy.fetch_add(1, Ordering::Relaxed);
    }

    pub fn global_snapshot(&self) -> GlobalSnapshot {
        GlobalSnapshot {
            origin_timeouts: self.origin_timeouts.load(Ordering::Relaxed),
            origin_errors: self.origin_errors.load(Ordering::Relaxed),
            stream_requests: self.stream_requests.load(Ordering::Relaxed),
            stream_bytes: self.stream_bytes.load(Ordering::Relaxed),
            stream_errors: self.stream_errors.load(Ordering::Relaxed),
            datapath_pingora: self.datapath_pingora.load(Ordering::Relaxed),
            datapath_legacy: self.datapath_legacy.load(Ordering::Relaxed),
        }
    }

    /// Snapshot and reset all domain counters for reporting

    /// Read counters without resetting (for Prometheus scrape).
    pub async fn take_snapshots_peek(&self) -> Vec<DomainSnapshot> {
        let map = self.by_domain.lock().await;
        let mut out = Vec::new();
        for (domain, c) in map.iter() {
            out.push(DomainSnapshot {
                domain: domain.clone(),
                requests: c.requests.load(Ordering::Relaxed),
                cache_hits: c.cache_hits.load(Ordering::Relaxed),
                cache_misses: c.cache_misses.load(Ordering::Relaxed),
                bytes_sent: c.bytes_sent.load(Ordering::Relaxed),
            });
        }
        out
    }

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
