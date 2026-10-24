//! In-process request counters, flushed to control plane

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Default)]
pub struct EdgeMetrics {
    pub requests: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub bytes_sent: AtomicU64,
}

impl EdgeMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn record_hit(&self, bytes: u64) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_miss(&self, bytes: u64) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_bypass(&self, bytes: u64) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Snapshot and reset (for reporting)
    pub fn take_snapshot(&self) -> (u64, u64, u64, u64) {
        (
            self.requests.swap(0, Ordering::Relaxed),
            self.cache_hits.swap(0, Ordering::Relaxed),
            self.cache_misses.swap(0, Ordering::Relaxed),
            self.bytes_sent.swap(0, Ordering::Relaxed),
        )
    }
}
