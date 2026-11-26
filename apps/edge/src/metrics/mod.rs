//! Per-domain edge request counters

use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
struct Counters {
    requests: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    bytes_sent: AtomicU64,
}

/// Why a request left the Pingora data plane for the in-process engine.
///
/// `lagran_edge_datapath_legacy_total` answers *how many*; this answers *which*.
/// Every variant is either a path still to migrate or one deliberately kept, so a
/// non-zero [`LegacyFallback::Other`] means an unclassified path appeared and the
/// migration inventory needs updating. Without this dimension the remaining legacy
/// surface can only be guessed at, and deleting code becomes blind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyFallback {
    /// HEAD requests are still served by the in-process engine.
    Head,
    /// The node is disabled; the 503 page comes from the in-process engine.
    NodeDisabled,
    /// Client-requested revalidation (`no-cache` / `max-age=0`) did not complete.
    StrictRevalidation,
    /// `origin_url` could not be parsed, so no origin target exists.
    ParseOrigin,
    /// Pingora cache storage was not initialised (should be unreachable).
    NativeCacheDisabled,
    /// A fallback path that is not classified yet.
    Other,
}

impl LegacyFallback {
    /// Stable iteration order: metrics output must not move between scrapes.
    pub const ALL: [Self; 6] = [
        Self::Head,
        Self::NodeDisabled,
        Self::StrictRevalidation,
        Self::ParseOrigin,
        Self::NativeCacheDisabled,
        Self::Other,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Head => "head",
            Self::NodeDisabled => "node_disabled",
            Self::StrictRevalidation => "strict_revalidation",
            Self::ParseOrigin => "parse_origin",
            Self::NativeCacheDisabled => "native_cache_disabled",
            Self::Other => "other",
        }
    }
}

/// One counter per reason: the set is fixed, so this is a plain struct rather
/// than a labelled map that would allocate on the request path.
#[derive(Default)]
struct LegacyFallbackCounters {
    head: AtomicU64,
    node_disabled: AtomicU64,
    strict_revalidation: AtomicU64,
    parse_origin: AtomicU64,
    native_cache_disabled: AtomicU64,
    other: AtomicU64,
}

impl LegacyFallbackCounters {
    fn counter(&self, reason: LegacyFallback) -> &AtomicU64 {
        match reason {
            LegacyFallback::Head => &self.head,
            LegacyFallback::NodeDisabled => &self.node_disabled,
            LegacyFallback::StrictRevalidation => &self.strict_revalidation,
            LegacyFallback::ParseOrigin => &self.parse_origin,
            LegacyFallback::NativeCacheDisabled => &self.native_cache_disabled,
            LegacyFallback::Other => &self.other,
        }
    }

    fn snapshot(&self) -> LegacyFallbackSnapshot {
        LegacyFallbackSnapshot {
            head: self.head.load(Ordering::Relaxed),
            node_disabled: self.node_disabled.load(Ordering::Relaxed),
            strict_revalidation: self.strict_revalidation.load(Ordering::Relaxed),
            parse_origin: self.parse_origin.load(Ordering::Relaxed),
            native_cache_disabled: self.native_cache_disabled.load(Ordering::Relaxed),
            other: self.other.load(Ordering::Relaxed),
        }
    }
}

/// Per-reason view of the legacy fallbacks (see [`LegacyFallback`]).
#[derive(Debug, Clone, Copy, Default)]
pub struct LegacyFallbackSnapshot {
    pub head: u64,
    pub node_disabled: u64,
    pub strict_revalidation: u64,
    pub parse_origin: u64,
    pub native_cache_disabled: u64,
    pub other: u64,
}

impl LegacyFallbackSnapshot {
    pub fn get(&self, reason: LegacyFallback) -> u64 {
        match reason {
            LegacyFallback::Head => self.head,
            LegacyFallback::NodeDisabled => self.node_disabled,
            LegacyFallback::StrictRevalidation => self.strict_revalidation,
            LegacyFallback::ParseOrigin => self.parse_origin,
            LegacyFallback::NativeCacheDisabled => self.native_cache_disabled,
            LegacyFallback::Other => self.other,
        }
    }

    /// `(reason, count)` in stable order, for the Prometheus text endpoint.
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, u64)> + '_ {
        LegacyFallback::ALL
            .iter()
            .map(move |reason| (reason.as_str(), self.get(*reason)))
    }

    /// Prometheus exposition for `lagran_edge_legacy_fallback_total`.
    ///
    /// Two listeners render metrics text (the admin Axum app and the Pingora
    /// data-plane management path); the exposition lives here so the two can never
    /// disagree about names or label values.
    pub fn prometheus_lines(&self) -> String {
        let mut out = String::from(
            "# HELP lagran_edge_legacy_fallback_total Requests that left the Pingora data plane, by reason\n\
             # TYPE lagran_edge_legacy_fallback_total counter\n",
        );
        for (reason, count) in self.iter() {
            out.push_str(&format!(
                "lagran_edge_legacy_fallback_total{{reason=\"{reason}\"}} {count}\n"
            ));
        }
        out
    }
}

#[derive(Default)]
pub struct EdgeMetrics {
    /// Sharded: every request updates a counter, so a single process-wide lock
    /// would serialise the whole edge on its hottest path.
    by_domain: DashMap<String, Arc<Counters>>,
    origin_timeouts: AtomicU64,
    origin_errors: AtomicU64,
    /// Requests that could not take the cross-node flight lock because Redis was
    /// unavailable. Non-zero means coalescing is off and origin load is higher than
    /// the topology implies.
    flight_degraded: AtomicU64,
    stream_requests: AtomicU64,
    stream_bytes: AtomicU64,
    stream_errors: AtomicU64,
    downstream_cancels: AtomicU64,
    datapath_pingora: AtomicU64,
    datapath_legacy: AtomicU64,
    /// Why each legacy fallback happened (see [`LegacyFallback`]).
    legacy_fallback: LegacyFallbackCounters,
    /// Requests refused with a 502 because the domain's origin configuration could
    /// not be parsed. A non-zero value means the control plane accepted a domain
    /// whose `origin_url`/`origin` fields do not form a usable origin.
    config_errors: AtomicU64,
    /// Enabled managed rulesets absent from the verified rulepack (M5). The
    /// control plane now falls back to built-in categories, so a non-zero value
    /// means an edge is running an older pairing and may be under-protected.
    rulepack_missing_rulesets: AtomicU64,
    chunk_requests: AtomicU64,
    chunk_origin_runs: AtomicU64,
    chunk_fallbacks: AtomicU64,
    chunk_fill_drops: AtomicU64,
    chunk_fill_dropped_bytes: AtomicU64,
    chunk_fill_drop_queue: AtomicU64,
    chunk_fill_drop_budget: AtomicU64,
    chunk_fill_drop_send: AtomicU64,
    chunk_fill_rejects: AtomicU64,
    chunk_fill_rejected_bytes: AtomicU64,
    chunk_origin_attempts: AtomicU64,
    chunk_origin_failures: AtomicU64,
    requests: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    bytes_sent: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct GlobalSnapshot {
    pub origin_timeouts: u64,
    pub origin_errors: u64,
    pub config_errors: u64,
    pub rulepack_missing_rulesets: u64,
    pub stream_requests: u64,
    pub stream_bytes: u64,
    pub stream_errors: u64,
    pub downstream_cancels: u64,
    pub datapath_pingora: u64,
    pub datapath_legacy: u64,
    /// Per-reason breakdown of `datapath_legacy`.
    pub legacy_fallback: LegacyFallbackSnapshot,
    pub chunk_requests: u64,
    pub chunk_origin_runs: u64,
    pub chunk_fallbacks: u64,
    pub chunk_fill_drops: u64,
    pub chunk_fill_dropped_bytes: u64,
    pub chunk_fill_drop_queue: u64,
    pub chunk_fill_drop_budget: u64,
    pub chunk_fill_drop_send: u64,
    pub chunk_fill_rejects: u64,
    pub chunk_fill_rejected_bytes: u64,
    pub chunk_origin_attempts: u64,
    pub chunk_origin_failures: u64,
    pub requests: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub bytes_sent: u64,
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
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        let c = self.bucket(domain);
        c.requests.fetch_add(1, Ordering::Relaxed);
        c.cache_hits.fetch_add(1, Ordering::Relaxed);
        c.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_miss(&self, domain: &str, bytes: u64) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        let c = self.bucket(domain);
        c.requests.fetch_add(1, Ordering::Relaxed);
        c.cache_misses.fetch_add(1, Ordering::Relaxed);
        c.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_bypass(&self, domain: &str, bytes: u64) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        let c = self.bucket(domain);
        c.requests.fetch_add(1, Ordering::Relaxed);
        c.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Count a request that ran without the cross-node flight lock.
    pub fn record_flight_degraded(&self) {
        self.flight_degraded.fetch_add(1, Ordering::Relaxed);
    }

    pub fn flight_degraded(&self) -> u64 {
        self.flight_degraded.load(Ordering::Relaxed)
    }

    pub fn record_origin_timeout(&self) {
        self.origin_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_origin_error(&self) {
        self.origin_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a request refused because the domain's origin configuration is unusable.
    ///
    /// This is the runtime half of the control-plane `origin_url` validation: if it
    /// ever fires, a bad configuration reached an edge and should be fixed there
    /// rather than silently falling back to the in-process engine.
    pub fn record_config_error(&self) {
        self.config_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn config_errors(&self) -> u64 {
        self.config_errors.load(Ordering::Relaxed)
    }

    /// Store the missing-ruleset count observed for the current config.
    ///
    /// A gauge, not a counter: the same domain is re-applied on every sync, so
    /// adding would inflate the number without anything having changed.
    pub fn set_rulepack_missing_rulesets(&self, count: u64) {
        self.rulepack_missing_rulesets.store(count, Ordering::Relaxed);
    }

    pub fn rulepack_missing_rulesets(&self) -> u64 {
        self.rulepack_missing_rulesets.load(Ordering::Relaxed)
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

    /// Record *why* a request fell back to the in-process engine.
    ///
    /// Called at the Pingora hand-off points, not from the engine itself: the
    /// engine cannot tell a HEAD request from a revalidation that gave up, and a
    /// direct engine caller (cache diagnostics) has no reason to report.
    pub fn record_legacy_fallback(&self, reason: LegacyFallback) {
        self.legacy_fallback
            .counter(reason)
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Read the per-reason fallback counters without resetting them.
    pub fn legacy_fallbacks(&self) -> LegacyFallbackSnapshot {
        self.legacy_fallback.snapshot()
    }

    pub fn record_chunk_request(&self) {
        self.chunk_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_chunk_origin_runs(&self, runs: u64) {
        self.chunk_origin_runs.fetch_add(runs, Ordering::Relaxed);
    }

    /// A fragmented cache exceeded the per-request origin-run budget and fell
    /// back to the initial range path.
    pub fn record_chunk_fallback(&self) {
        self.chunk_fallbacks.fetch_add(1, Ordering::Relaxed);
    }

    /// Bytes discarded because the per-fill queue or process-wide fill budget
    /// was full. The client response is unaffected; the cache simply keeps the
    /// already committed prefix/chunks.
    pub fn record_chunk_fill_drop(&self, bytes: u64) {
        self.chunk_fill_drops.fetch_add(1, Ordering::Relaxed);
        self.chunk_fill_dropped_bytes
            .fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_chunk_fill_drop_queue(&self, bytes: u64) {
        self.chunk_fill_drop_queue.fetch_add(1, Ordering::Relaxed);
        self.record_chunk_fill_drop(bytes);
    }

    pub fn record_chunk_fill_drop_budget(&self, bytes: u64) {
        self.chunk_fill_drop_budget.fetch_add(1, Ordering::Relaxed);
        self.record_chunk_fill_drop(bytes);
    }

    pub fn record_chunk_fill_drop_send(&self, bytes: u64) {
        self.chunk_fill_drop_send.fetch_add(1, Ordering::Relaxed);
        self.record_chunk_fill_drop(bytes);
    }

    /// A fill was rejected before any byte was queued (admission/disk/lock).
    /// These bytes were planned, not actually discarded.
    pub fn record_chunk_fill_reject(&self, bytes: u64) {
        self.chunk_fill_rejects.fetch_add(1, Ordering::Relaxed);
        self.chunk_fill_rejected_bytes
            .fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_chunk_origin_attempt(&self) {
        self.chunk_origin_attempts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_chunk_origin_failure(&self) {
        self.chunk_origin_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn global_snapshot(&self) -> GlobalSnapshot {
        GlobalSnapshot {
            origin_timeouts: self.origin_timeouts.load(Ordering::Relaxed),
            origin_errors: self.origin_errors.load(Ordering::Relaxed),
            config_errors: self.config_errors.load(Ordering::Relaxed),
            rulepack_missing_rulesets: self.rulepack_missing_rulesets.load(Ordering::Relaxed),
            stream_requests: self.stream_requests.load(Ordering::Relaxed),
            stream_bytes: self.stream_bytes.load(Ordering::Relaxed),
            stream_errors: self.stream_errors.load(Ordering::Relaxed),
            downstream_cancels: self.downstream_cancels.load(Ordering::Relaxed),
            datapath_pingora: self.datapath_pingora.load(Ordering::Relaxed),
            datapath_legacy: self.datapath_legacy.load(Ordering::Relaxed),
            legacy_fallback: self.legacy_fallback.snapshot(),
            chunk_requests: self.chunk_requests.load(Ordering::Relaxed),
            chunk_origin_runs: self.chunk_origin_runs.load(Ordering::Relaxed),
            chunk_fallbacks: self.chunk_fallbacks.load(Ordering::Relaxed),
            chunk_fill_drops: self.chunk_fill_drops.load(Ordering::Relaxed),
            chunk_fill_dropped_bytes: self.chunk_fill_dropped_bytes.load(Ordering::Relaxed),
            chunk_fill_drop_queue: self.chunk_fill_drop_queue.load(Ordering::Relaxed),
            chunk_fill_drop_budget: self.chunk_fill_drop_budget.load(Ordering::Relaxed),
            chunk_fill_drop_send: self.chunk_fill_drop_send.load(Ordering::Relaxed),
            chunk_fill_rejects: self.chunk_fill_rejects.load(Ordering::Relaxed),
            chunk_fill_rejected_bytes: self.chunk_fill_rejected_bytes.load(Ordering::Relaxed),
            chunk_origin_attempts: self.chunk_origin_attempts.load(Ordering::Relaxed),
            chunk_origin_failures: self.chunk_origin_failures.load(Ordering::Relaxed),
            requests: self.requests.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
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
    fn chunk_fill_drop_counters_accumulate() {
        let metrics = EdgeMetrics::default();
        metrics.record_chunk_fill_drop(1024);
        metrics.record_chunk_fill_drop(2048);
        metrics.record_chunk_origin_attempt();
        metrics.record_chunk_origin_attempt();
        metrics.record_chunk_origin_failure();
        let snapshot = metrics.global_snapshot();
        assert_eq!(snapshot.chunk_fill_drops, 2);
        assert_eq!(snapshot.chunk_fill_dropped_bytes, 3072);
        assert_eq!(snapshot.chunk_origin_attempts, 2);
        assert_eq!(snapshot.chunk_origin_failures, 1);
    }

    #[test]
    fn global_counters_survive_domain_reporting() {
        let metrics = EdgeMetrics::default();
        metrics.record_hit("a.test", 10);
        metrics.record_miss("b.test", 20);
        let reported = metrics.take_snapshots_peek();
        metrics.subtract_reported(&reported);
        let snapshot = metrics.global_snapshot();
        assert_eq!(snapshot.requests, 2);
        assert_eq!(snapshot.cache_hits, 1);
        assert_eq!(snapshot.cache_misses, 1);
        assert_eq!(snapshot.bytes_sent, 30);
    }

    #[test]
    fn fill_drop_reasons_and_rejects_are_separate() {
        let metrics = EdgeMetrics::default();
        metrics.record_chunk_fill_drop_queue(100);
        metrics.record_chunk_fill_drop_budget(200);
        metrics.record_chunk_fill_drop_send(300);
        metrics.record_chunk_fill_reject(400);
        let snapshot = metrics.global_snapshot();
        assert_eq!(snapshot.chunk_fill_drops, 3);
        assert_eq!(snapshot.chunk_fill_dropped_bytes, 600);
        assert_eq!(snapshot.chunk_fill_drop_queue, 1);
        assert_eq!(snapshot.chunk_fill_drop_budget, 1);
        assert_eq!(snapshot.chunk_fill_drop_send, 1);
        assert_eq!(snapshot.chunk_fill_rejects, 1);
        assert_eq!(snapshot.chunk_fill_rejected_bytes, 400);
    }

    /// The fallback breakdown must stay one counter per reason, and every reason
    /// must be reachable by name: the Prometheus label values are a contract with
    /// the migration plan (`docs/request-pipeline-migration.md`).
    #[test]
    fn legacy_fallback_counters_are_per_reason() {
        let m = EdgeMetrics::default();
        m.record_legacy_fallback(LegacyFallback::Head);
        m.record_legacy_fallback(LegacyFallback::Head);
        m.record_legacy_fallback(LegacyFallback::StrictRevalidation);

        let snapshot = m.legacy_fallbacks();
        assert_eq!(snapshot.head, 2);
        assert_eq!(snapshot.strict_revalidation, 1);
        assert_eq!(snapshot.node_disabled, 0);
        assert_eq!(snapshot.get(LegacyFallback::Head), 2);
        assert_eq!(snapshot.get(LegacyFallback::Other), 0);

        // A reason recorded through the snapshot accessor must match the enum name.
        let rendered: Vec<(&str, u64)> = snapshot.iter().collect();
        assert_eq!(rendered.len(), LegacyFallback::ALL.len());
        assert_eq!(rendered[0], ("head", 2));
        assert_eq!(rendered[2], ("strict_revalidation", 1));
    }

    /// `datapath_legacy_total` and the per-reason counters are separate: the total
    /// also counts direct engine callers (cache diagnostics) that have no reason.
    #[test]
    fn legacy_fallback_does_not_touch_the_datapath_total() {
        let m = EdgeMetrics::default();
        m.record_legacy_fallback(LegacyFallback::NodeDisabled);
        let snapshot = m.global_snapshot();
        assert_eq!(snapshot.datapath_legacy, 0);
        assert_eq!(snapshot.legacy_fallback.node_disabled, 1);
    }

    /// Every label value must be unique, otherwise two reasons would collapse into
    /// one series and the breakdown would silently lose a path.
    #[test]
    fn legacy_fallback_labels_are_unique() {
        let mut names: Vec<&'static str> = LegacyFallback::ALL.iter().map(|r| r.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before);
    }

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
