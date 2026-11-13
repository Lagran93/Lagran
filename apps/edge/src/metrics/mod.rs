//! Per-domain edge request counters

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Default)]
struct Counters {
    requests: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    bytes_sent: AtomicU64,
}

#[derive(Default)]
pub struct EdgeMetrics {
    /// Sharded: every request updates a counter, so a single process-wide lock
    /// would serialise the whole edge on its hottest path.
    by_domain: DashMap<String, Arc<Counters>>,
    origin_timeouts: AtomicU64,
    origin_errors: AtomicU64,
    stream_requests: AtomicU64,
    stream_bytes: AtomicU64,
    stream_errors: AtomicU64,
    downstream_cancels: AtomicU64,
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
    pub downstream_cancels: u64,
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

    /// Find or create the counters for one domain.
    ///
    /// Hosts reach this code already normalized to lower case by both data
    /// planes, so the common path is a borrowed lookup with no allocation.
    fn bucket(&self, domain: &str) -> Arc<Counters> {
        let key = if domain.is_empty() {
            "(unknown)"
        } else {
            domain
        };
        if let Some(counters) = self.by_domain.get(key) {
            return counters.value().clone();
        }
        self.by_domain
            .entry(key.to_lowercase())
            .or_insert_with(|| Arc::new(Counters::default()))
            .value()
            .clone()
    }

    pub fn record_hit(&self, domain: &str, bytes: u64) {
        let c = self.bucket(domain);
        c.requests.fetch_add(1, Ordering::Relaxed);
        c.cache_hits.fetch_add(1, Ordering::Relaxed);
        c.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_miss(&self, domain: &str, bytes: u64) {
        let c = self.bucket(domain);
        c.requests.fetch_add(1, Ordering::Relaxed);
        c.cache_misses.fetch_add(1, Ordering::Relaxed);
        c.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_bypass(&self, domain: &str, bytes: u64) {
        let c = self.bucket(domain);
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

    /// A client stopped reading before the edge finished the response body.
    /// This is not an edge or origin failure; it is tracked separately so
    /// cancellation noise cannot be mistaken for a 5xx regression.
    pub fn record_downstream_cancel(&self) {
        self.downstream_cancels.fetch_add(1, Ordering::Relaxed);
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
            downstream_cancels: self.downstream_cancels.load(Ordering::Relaxed),
            datapath_pingora: self.datapath_pingora.load(Ordering::Relaxed),
            datapath_legacy: self.datapath_legacy.load(Ordering::Relaxed),
        }
    }

    /// Read counters without resetting (for Prometheus scrape).
    pub fn take_snapshots_peek(&self) -> Vec<DomainSnapshot> {
        self.by_domain
            .iter()
            .map(|entry| {
                let counters = entry.value();
                DomainSnapshot {
                    domain: entry.key().clone(),
                    requests: counters.requests.load(Ordering::Relaxed),
                    cache_hits: counters.cache_hits.load(Ordering::Relaxed),
                    cache_misses: counters.cache_misses.load(Ordering::Relaxed),
                    bytes_sent: counters.bytes_sent.load(Ordering::Relaxed),
                }
            })
            .collect()
    }

    /// Subtract a reported batch from the counters.
    ///
    /// Used after a report succeeds: the values were read earlier by
    /// `take_snapshots_peek`, and requests that arrived in between must survive.
    /// A plain `swap(0)` would discard them, and a `merge_back` on failure would
    /// double-count on the retry. Subtracting exactly what was reported keeps the
    /// local counters equal to "everything not yet acknowledged by the control
    /// plane".
    ///
    /// `fetch_sub` can transiently undershoot if more than 2^64 events arrive
    /// between the peek and this call, which is not reachable.
    pub fn subtract_reported(&self, reported: &[DomainSnapshot]) {
        for snap in reported {
            if let Some(counters) = self.by_domain.get(&snap.domain) {
                counters
                    .requests
                    .fetch_sub(snap.requests, Ordering::Relaxed);
                counters
                    .cache_hits
                    .fetch_sub(snap.cache_hits, Ordering::Relaxed);
                counters
                    .cache_misses
                    .fetch_sub(snap.cache_misses, Ordering::Relaxed);
                counters
                    .bytes_sent
                    .fetch_sub(snap.bytes_sent, Ordering::Relaxed);
            }
        }
        // Drop buckets that are now empty, as `take_snapshots` does, so the map
        // does not grow with every domain ever seen.
        self.by_domain.retain(|_, counters| {
            counters.requests.load(Ordering::Relaxed) > 0
                || counters.cache_hits.load(Ordering::Relaxed) > 0
                || counters.cache_misses.load(Ordering::Relaxed) > 0
                || counters.bytes_sent.load(Ordering::Relaxed) > 0
        });
    }

    /// Snapshot and reset all domain counters for reporting.
    pub fn take_snapshots(&self) -> Vec<DomainSnapshot> {
        let mut out = Vec::new();
        for entry in self.by_domain.iter() {
            let counters = entry.value();
            let requests = counters.requests.swap(0, Ordering::Relaxed);
            let hits = counters.cache_hits.swap(0, Ordering::Relaxed);
            let misses = counters.cache_misses.swap(0, Ordering::Relaxed);
            let bytes = counters.bytes_sent.swap(0, Ordering::Relaxed);
            if requests > 0 || hits > 0 || misses > 0 || bytes > 0 {
                out.push(DomainSnapshot {
                    domain: entry.key().clone(),
                    requests,
                    cache_hits: hits,
                    cache_misses: misses,
                    bytes_sent: bytes,
                });
            }
        }
        // Drop empty buckets to bound growth.
        self.by_domain.retain(|_, counters| {
            counters.requests.load(Ordering::Relaxed) > 0
                || counters.cache_hits.load(Ordering::Relaxed) > 0
                || counters.cache_misses.load(Ordering::Relaxed) > 0
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_accumulate_and_snapshots_reset() {
        let metrics = EdgeMetrics::default();
        metrics.record_hit("a.test", 100);
        metrics.record_hit("a.test", 50);
        metrics.record_miss("b.test", 10);
        metrics.record_bypass("a.test", 5);

        let mut snaps = metrics.take_snapshots();
        snaps.sort_by(|a, b| a.domain.cmp(&b.domain));
        assert_eq!(snaps.len(), 2);
        assert_eq!(snaps[0].domain, "a.test");
        assert_eq!(snaps[0].requests, 3);
        assert_eq!(snaps[0].cache_hits, 2);
        assert_eq!(snaps[0].bytes_sent, 155);
        assert_eq!(snaps[1].domain, "b.test");
        assert_eq!(snaps[1].cache_misses, 1);

        // The second read must be empty: `take_snapshots` resets counters.
        assert!(metrics.take_snapshots().is_empty());
    }

    #[test]
    fn domain_lookup_is_case_insensitive() {
        let metrics = EdgeMetrics::default();
        metrics.record_hit("Example.COM", 1);
        metrics.record_hit("example.com", 1);

        let snaps = metrics.take_snapshots_peek();
        assert_eq!(snaps.len(), 1, "both spellings must share one bucket");
        assert_eq!(snaps[0].domain, "example.com");
        assert_eq!(snaps[0].requests, 2);
    }
    /// A peek does not disturb the counters, so a failed report loses nothing.
    ///
    /// `take_snapshots` cleared them before the report was attempted, so a control
    /// plane outage dropped whole batches: the hit-ratio charts showed gaps and the
    /// `cache_hit_ratio` alert, which returns early when `requests <= 0`, could hide
    /// a real problem behind "no data".
    #[test]
    fn peek_leaves_counters_intact() {
        let m = EdgeMetrics::default();
        m.record_hit("a.test", 10);

        let first = m.take_snapshots_peek();
        let second = m.take_snapshots_peek();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].requests, second[0].requests);
        assert_eq!(first[0].requests, 1);
        assert_eq!(first[0].cache_hits, 1);
    }

    /// Subtracting an acknowledged batch keeps requests that arrived meanwhile.
    #[test]
    fn subtract_reported_preserves_newer_events() {
        let m = EdgeMetrics::default();
        m.record_hit("a.test", 10);
        m.record_hit("a.test", 10);
        m.record_hit("a.test", 10);

        // Snapshot the first two as "reported".
        let peeked = m.take_snapshots_peek();
        assert_eq!(peeked[0].requests, 3);

        // A request arrives after the snapshot.
        m.record_miss("a.test", 10);

        // Subtract what was actually reported (3 requests, 3 hits).
        m.subtract_reported(&peeked);

        // The one that arrived in between survives, and its miss is not erased.
        let after = m.take_snapshots_peek();
        assert_eq!(after[0].requests, 1, "the newer request must survive");
        assert_eq!(after[0].cache_hits, 0);
        assert_eq!(after[0].cache_misses, 1);
    }

    /// Fully reported domains drop out of the map, as `take_snapshots` did.
    #[test]
    fn subtract_reported_drops_empty_buckets() {
        let m = EdgeMetrics::default();
        m.record_hit("a.test", 10);
        let peeked = m.take_snapshots_peek();
        m.subtract_reported(&peeked);
        assert!(
            m.take_snapshots_peek().is_empty(),
            "a fully reported domain must not linger"
        );
    }
}
