//! Structured visitor access log: file + ring buffer + optional control report.
//!
//! Request handlers never touch the file system: records go through an
//! unbounded channel to a single writer task, which keeps the hot path free of
//! lock contention and file I/O.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex};

/// How many times one batch may be retried before it is dropped.
///
/// Re-queueing puts the records back at the head, so an unbounded retry count means
/// every `drain` returns the same records for as long as the control plane is down.
pub const MAX_REPORT_ATTEMPTS: u32 = 5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRecord {
    pub ts: String,
    pub node_id: String,
    pub client_ip: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub status: u16,
    pub bytes: u64,
    pub latency_ms: u64,
    pub cache_status: String,
    /// Security/edge action separated from the cache outcome (WAF, CC, WS...).
    pub action: String,
    pub user_agent: String,
    pub referer: String,
    pub request_id: String,
}

#[derive(Clone)]
pub struct AccessLog {
    tx: mpsc::Sender<AccessRecord>,
    /// Records dropped because the writer could not keep up.
    dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Recent entries for local query / batch report
    buffer: Arc<Mutex<VecDeque<AccessRecord>>>,
    buffer_cap: usize,
    node_id: String,
    /// Records accepted by `write`, and records the writer finished.
    ///
    /// A shutdown waits for these to meet so the file is not left short of lines it
    /// had already accepted.
    enqueued: std::sync::Arc<std::sync::atomic::AtomicU64>,
    processed: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl AccessLog {
    pub async fn open(
        path: Option<&str>,
        node_id: &str,
        buffer_cap: usize,
        json_lines: bool,
    ) -> Self {
        let file = if let Some(p) = path.filter(|s| !s.is_empty()) {
            let path = PathBuf::from(p);
            if let Some(parent) = path.parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }
            match tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .await
            {
                Ok(f) => {
                    tracing::info!(path = %path.display(), "access log file opened");
                    Some(f)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "access log file open failed");
                    None
                }
            }
        } else {
            None
        };

        let buffer_cap = buffer_cap.clamp(100, 50_000);
        let buffer = Arc::new(Mutex::new(VecDeque::with_capacity(buffer_cap.min(10_000))));
        // Counters for a clean shutdown: `enqueued` is bumped by `write`,
        // `processed` by the writer, so `flush` can wait for them to meet.
        let enqueued = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let processed = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

        let (tx, mut rx) = mpsc::channel::<AccessRecord>(buffer_cap.clamp(1_000, 20_000));

        {
            let buffer = buffer.clone();
            let processed = processed.clone();
            // Not `spawn_supervised`: the writer owns the file handle and the
            // channel receiver, neither of which can be rebuilt, so restarting it
            // would silently lose the log file. Watch it instead — a panic would
            // otherwise only surface as a rejected `try_send` with no cause.
            let writer = tokio::spawn(async move {
                let mut file = file;
                let mut tick = tokio::time::interval(Duration::from_secs(1));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                        maybe = rx.recv() => {
                            let Some(rec) = maybe else { break };
                            // Format once, only when someone consumes the text
                            // (a file, or the tracing target is enabled).
                            let want_trace =
                                tracing::enabled!(target: "access", tracing::Level::INFO);
                            if file.is_some() || want_trace {
                                let payload = if json_lines {
                                    serde_json::to_string(&rec)
                                        .unwrap_or_else(|_| combined_line(&rec))
                                } else {
                                    combined_line(&rec)
                                };
                                if want_trace {
                                    tracing::info!(
                                        target: "access",
                                        client_ip = %rec.client_ip,
                                        method = %rec.method,
                                        host = %rec.host,
                                        path = %rec.path,
                                        status = rec.status,
                                        bytes = rec.bytes,
                                        latency_ms = rec.latency_ms,
                                        cache = %rec.cache_status,
                                        "{}", payload
                                    );
                                }
                                if let Some(f) = file.as_mut() {
                                    if let Err(e) = f.write_all(payload.as_bytes()).await {
                                        tracing::warn!(error = %e, "access log write failed");
                                    } else if let Err(e) = f.write_all(b"\n").await {
                                        tracing::warn!(error = %e, "access log write failed");
                                    }
                                }
                            }
                            let mut buf = buffer.lock().await;
                            if buf.len() >= buffer_cap {
                                buf.pop_front();
                            }
                            buf.push_back(rec);
                            drop(buf);
                            processed
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        }
                        _ = tick.tick() => {
                            if let Some(f) = file.as_mut() {
                                let _ = f.flush().await;
                            }
                        }
                    }
                }
                if let Some(f) = file.as_mut() {
                    let _ = f.flush().await;
                }
            });
            // Surface a panic with its cause. Without this the only symptom was
            // `try_send` failing with `Closed` and a generic warning.
            tokio::spawn(async move {
                if let Err(e) = writer.await {
                    if e.is_panic() {
                        tracing::error!(
                            "access log writer panicked; access records are no longer persisted"
                        );
                    }
                }
            });
        }

        Self {
            tx,
            dropped: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            buffer,
            buffer_cap,
            node_id: node_id.to_string(),
            enqueued,
            processed,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn split_status(label: &str) -> (&str, &str) {
        match label {
            "HIT" | "MISS" | "EXPIRED" | "DYNAMIC" | "BYPASS" | "REVALIDATED" | "STALE"
            | "UPDATING" | "NONE" | "UNKNOWN" => (label, ""),
            "WS" => ("NONE", "WS"),
            "HTTPS_REDIRECT" => ("NONE", "HTTPS_REDIRECT"),
            "NODE_DISABLED" => ("NONE", "NODE_DISABLED"),
            "WAF" | "CHALLENGE" | "CC" | "CC-BAN" | "CC-CHALLENGE" | "BOT-CHALLENGE" | "ERROR"
            | "TIMEOUT" | "UNHEALTHY" => ("BYPASS", label),
            other => ("UNKNOWN", other),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        client_ip: &str,
        method: &str,
        host: &str,
        path: &str,
        status: u16,
        bytes: u64,
        latency_ms: u64,
        cache_status: &str,
        user_agent: &str,
        referer: &str,
        request_id: &str,
    ) -> AccessRecord {
        let ts = chrono_like_now();
        let (cache, action) = Self::split_status(cache_status);
        AccessRecord {
            ts,
            node_id: self.node_id.clone(),
            client_ip: client_ip.to_string(),
            method: method.to_string(),
            host: host.to_string(),
            path: path.to_string(),
            status,
            bytes,
            latency_ms,
            cache_status: cache.to_string(),
            action: action.to_string(),
            user_agent: truncate(user_agent, 256),
            referer: truncate(referer, 256),
            request_id: truncate(request_id, 64),
        }
    }

    /// Enqueue a record; returns as soon as the writer accepts it.
    ///
    /// All formatting (and the `tracing` event) happens in the writer task. The
    /// request path used to format the line here and the writer formatted it
    /// again, doubling the cost on the hottest path in the process.
    pub async fn write(&self, rec: AccessRecord) {
        // Never block the request path on the log writer.
        //
        // This used to `send().await`, so a slow disk made every request await a
        // bounded channel whose only consumer writes to a file: one stalled
        // write_all() backed up all in-flight requests. Losing a log line under
        // overload is strictly better than stalling the data plane.
        match self.tx.try_send(rec) {
            Ok(()) => {
                self.enqueued
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                // Log sparsely: the queue stays full for as long as the disk is
                // behind, so reporting every drop would itself become the load.
                if dropped % 1000 == 1 {
                    tracing::warn!(dropped, "access log queue full; dropping records");
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::warn!("access log writer stopped; record dropped");
            }
        }
    }

    /// Wait until the writer has processed everything queued, or `timeout` elapses.
    ///
    /// Tracks a counter the writer increments per record rather than inspecting the
    /// ring buffer: the buffer keeps records after writing, so "is it empty" never
    /// becomes true during normal operation.
    ///
    /// Returns the number of records still unprocessed when it gave up (0 on a clean
    /// drain), so a shutdown can log what it might have lost.
    pub async fn flush(&self, timeout: Duration) -> u64 {
        let target = self.enqueued.load(Ordering::SeqCst);
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let processed = self.processed.load(Ordering::SeqCst);
            if processed >= target {
                return 0;
            }
            if tokio::time::Instant::now() >= deadline {
                let remaining = target.saturating_sub(processed);
                tracing::warn!(remaining, "access log flush timed out; records may be lost");
                return remaining;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Recent records, newest first (does not remove them).
    pub async fn snapshot(&self, limit: usize) -> Vec<AccessRecord> {
        let buf = self.buffer.lock().await;
        let n = limit.min(buf.len());
        buf.iter().rev().take(n).cloned().collect()
    }

    /// Drain up to `limit` oldest records for reporting.
    pub async fn drain(&self, limit: usize) -> Vec<AccessRecord> {
        let mut buf = self.buffer.lock().await;
        let n = limit.min(buf.len());
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            if let Some(r) = buf.pop_front() {
                out.push(r);
            }
        }
        out
    }

    /// Put records back at the front after a failed report (oldest first).
    ///
    /// Only for a *bounded* number of attempts. Prepend means the next `drain`
    /// returns the same records, so a control plane that stays down retries the
    /// same batch forever while the rest of the buffer ages out behind it — the
    /// buffer becomes a monument to 500 old lines and every new record is lost. The
    /// reporter uses [`Self::requeue_bounded`] instead, which gives up after a few
    /// attempts and says so.
    pub async fn requeue(&self, records: Vec<AccessRecord>) {
        if records.is_empty() {
            return;
        }
        let mut buf = self.buffer.lock().await;
        // prepend preserving order: push_front in reverse
        for r in records.into_iter().rev() {
            if buf.len() >= self.buffer_cap {
                buf.pop_back();
            }
            buf.push_front(r);
        }
    }

    /// Re-queue a failed batch, or drop it once `attempts` reaches the limit.
    ///
    /// Returns the number of records dropped (0 when they were re-queued).
    ///
    /// Re-queueing puts the records back at the head, so the next `drain` returns
    /// the same batch. Left unbounded, a control plane that stays down pins the
    /// buffer on 500 old records: the live tail ages out unread while
    /// `/__lagran/access-logs` keeps showing the same lines. After
    /// [`MAX_REPORT_ATTEMPTS`] the batch is dropped and counted instead, which keeps
    /// recent logs flowing and makes the loss visible.
    pub async fn requeue_bounded(&self, records: Vec<AccessRecord>, attempts: u32) -> usize {
        if records.is_empty() {
            return 0;
        }
        if attempts > MAX_REPORT_ATTEMPTS {
            let dropped = records.len();
            self.dropped.fetch_add(dropped as u64, Ordering::Relaxed);
            return dropped;
        }
        self.requeue(records).await;
        0
    }

    pub fn capacity(&self) -> usize {
        self.buffer_cap
    }
}

fn combined_line(rec: &AccessRecord) -> String {
    format!(
        "{ts} {ip} \"{method} {host}{path}\" status={status} bytes={bytes} cache={cache} action={action} {ms}ms ua=\"{ua}\" ref=\"{ref}\"",
        ts = rec.ts,
        ip = rec.client_ip,
        method = rec.method,
        host = rec.host,
        path = rec.path,
        status = rec.status,
        bytes = rec.bytes,
        cache = rec.cache_status,
        action = rec.action,
        ms = rec.latency_ms,
        ua = rec.user_agent.replace('"', "'"),
        ref = rec.referer.replace('"', "'"),
    )
}

fn truncate(s: &str, max: usize) -> String {
    // Single pass. The previous version ran `chars().count()` to test the length
    // and then `chars().take(max)` to copy, walking the string twice; for a long
    // attacker-controlled User-Agent or Referer (4 KiB measured) that is ~500 ns
    // versus ~130 ns here.
    //
    // Pure ASCII is the overwhelmingly common case and its byte length already
    // equals its character count, so it needs no scan at all when it fits.
    if s.is_ascii() {
        if s.len() <= max {
            return s.to_string();
        }
        let mut out = String::with_capacity(max + 3);
        out.push_str(&s[..max]);
        out.push('…');
        return out;
    }
    match s.char_indices().nth(max) {
        None => s.to_string(),
        Some((cut, _)) => {
            let mut out = String::with_capacity(cut + 3);
            out.push_str(&s[..cut]);
            out.push('…');
            out
        }
    }
}

fn chrono_like_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_unix(secs)
}

fn format_unix(secs: u64) -> String {
    // Minimal UTC formatter (good enough for logs)
    const DAY: u64 = 86400;
    const HOUR: u64 = 3600;
    const MIN: u64 = 60;
    let days = secs / DAY;
    let rem = secs % DAY;
    let h = rem / HOUR;
    let m = (rem % HOUR) / MIN;
    let s = rem % MIN;
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Howard Hinnant civil_from_days
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_format_is_iso_utc() {
        // 2026-10-25T00:00:00Z
        assert_eq!(format_unix(1_792_886_400), "2026-10-25T00:00:00Z");
    }

    #[test]
    fn security_labels_are_not_cache_statuses() {
        assert_eq!(AccessLog::split_status("WAF"), ("BYPASS", "WAF"));
        assert_eq!(AccessLog::split_status("WS"), ("NONE", "WS"));
        assert_eq!(AccessLog::split_status("REVALIDATED"), ("REVALIDATED", ""));
    }

    #[test]
    fn truncation_keeps_char_boundaries() {
        assert_eq!(truncate("abcdef", 3), "abc…");
        assert_eq!(truncate("ab", 3), "ab");
    }

    #[tokio::test]
    async fn records_reach_ring_buffer() {
        let log = AccessLog::open(None, "n1", 100, false).await;
        log.write(log.record(
            "1.2.3.4", "GET", "a.test", "/x", 200, 10, 5, "HIT", "ua", "", "rid-1",
        ))
        .await;
        // The writer task applies the record asynchronously.
        for _ in 0..50 {
            if !log.snapshot(1).await.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let rows = log.snapshot(10).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].host, "a.test");
        assert_eq!(log.capacity(), 100);
    }
    /// Multi-byte characters must be cut on a character boundary, not a byte one.
    ///
    /// The single-pass rewrite walks `char_indices` for non-ASCII input; a byte
    /// slice at the limit would panic or produce mojibake.
    #[test]
    fn truncation_handles_multibyte_input() {
        // Each CJK character is three bytes.
        let cjk = "字节边界测试";
        assert_eq!(truncate(cjk, 100), cjk, "a short string passes through");
        let cut = truncate(cjk, 3);
        assert_eq!(cut, "字节边…", "three characters plus the ellipsis");
        assert!(cut.chars().count() <= 4);

        // A 4-byte emoji must survive intact.
        let emoji = "😀😀😀😀";
        assert_eq!(truncate(emoji, 2), "😀😀…");
    }

    /// Exactly at the limit is not truncated; one over is.
    #[test]
    fn truncation_boundary_is_exact() {
        assert_eq!(truncate("abc", 3), "abc");
        assert_eq!(truncate("abcd", 3), "abc…");
        assert_eq!(truncate("", 3), "");
    }

    /// A long ASCII string is cut without scanning twice.
    #[test]
    fn truncation_caps_long_ascii() {
        let long = "a".repeat(4096);
        let out = truncate(&long, 256);
        assert_eq!(out.chars().count(), 257, "256 characters plus the ellipsis");
        assert!(out.ends_with('…'));
    }
    fn record(path: &str) -> AccessRecord {
        AccessRecord {
            ts: "2026-11-13T00:00:00Z".into(),
            node_id: "edge-001".into(),
            client_ip: "203.0.113.9".into(),
            method: "GET".into(),
            host: "a.test".into(),
            path: path.into(),
            status: 200,
            bytes: 1,
            latency_ms: 1,
            cache_status: "miss".into(),
            action: String::new(),
            user_agent: String::new(),
            referer: String::new(),
            request_id: String::new(),
        }
    }

    /// A retried batch is dropped after the limit instead of looping forever.
    ///
    /// `requeue` prepends, so the next `drain` returns the same records. Unbounded,
    /// a control plane outage pinned the buffer on 500 old lines while new requests
    /// were silently lost behind them.
    #[tokio::test]
    async fn a_failed_batch_is_dropped_after_the_retry_limit() {
        let log = AccessLog::open(None, "edge-001", 100, false).await;
        let batch: Vec<AccessRecord> = (0..10).map(|i| record(&format!("/{i}"))).collect();

        // Within the limit: records go back into the buffer.
        for attempt in 1..=MAX_REPORT_ATTEMPTS {
            let dropped = log.requeue_bounded(batch.clone(), attempt).await;
            assert_eq!(dropped, 0, "attempt {attempt} must re-queue, not drop");
            assert_eq!(log.drain(100).await.len(), 10, "still in the buffer");
        }

        // Past the limit: dropped and counted.
        let dropped = log
            .requeue_bounded(batch.clone(), MAX_REPORT_ATTEMPTS + 1)
            .await;
        assert_eq!(dropped, 10, "the batch must be dropped after the limit");
        assert!(
            log.drain(100).await.is_empty(),
            "a dropped batch must not return to the buffer"
        );
    }

    /// Dropping a batch keeps the live tail flowing.
    ///
    /// The point of the limit is that new records still get reported, rather than
    /// the buffer being permanently occupied by an unretryable one.
    #[tokio::test]
    async fn new_records_survive_a_dropped_batch() {
        let log = AccessLog::open(None, "edge-001", 100, false).await;
        let stale: Vec<AccessRecord> = (0..10).map(|i| record(&format!("/old{i}"))).collect();
        log.requeue_bounded(stale, MAX_REPORT_ATTEMPTS + 1).await;

        log.write(record("/fresh")).await;
        // `write` hands the record to the writer task, so it reaches the ring buffer
        // asynchronously; poll rather than assume the task has run.
        let mut drained = Vec::new();
        for _ in 0..100 {
            drained = log.drain(100).await;
            if !drained.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(drained.len(), 1, "only the fresh record remains");
        assert_eq!(drained[0].path, "/fresh");
    }
    /// `flush` waits for queued records and reports a clean drain.
    ///
    /// A shutdown relies on this to avoid losing lines the writer had already
    /// accepted. Without it the buffered records die with the process.
    #[tokio::test]
    async fn flush_waits_for_queued_records() {
        let log = AccessLog::open(None, "edge-001", 100, false).await;
        for i in 0..20 {
            log.write(record(&format!("/{i}"))).await;
        }
        let remaining = log.flush(Duration::from_secs(5)).await;
        assert_eq!(remaining, 0, "the writer must drain everything queued");
    }

    /// A flush on an idle log returns immediately.
    #[tokio::test]
    async fn flush_returns_immediately_when_idle() {
        let log = AccessLog::open(None, "edge-001", 100, false).await;
        let started = std::time::Instant::now();
        let remaining = log.flush(Duration::from_secs(5)).await;
        assert_eq!(remaining, 0);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "an empty log must not wait"
        );
    }

}
