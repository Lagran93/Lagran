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
        let (tx, mut rx) = mpsc::channel::<AccessRecord>(buffer_cap.clamp(1_000, 20_000));

        {
            let buffer = buffer.clone();
            tokio::spawn(async move {
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
        }

        Self {
            tx,
            dropped: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            buffer,
            buffer_cap,
            node_id: node_id.to_string(),
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
            Ok(()) => {}
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
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect::<String>() + "…"
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
}
