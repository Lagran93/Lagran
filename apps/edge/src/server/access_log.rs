//! Structured visitor access log: file + ring buffer + optional control report

use serde::Serialize;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize)]
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
    pub user_agent: String,
    pub referer: String,
}

#[derive(Clone)]
pub struct AccessLog {
    file: Arc<Mutex<Option<tokio::fs::File>>>,
    /// Recent entries for local query / batch report
    buffer: Arc<Mutex<VecDeque<AccessRecord>>>,
    buffer_cap: usize,
    json_lines: bool,
    node_id: String,
}

impl AccessLog {
    pub async fn open(path: Option<&str>, node_id: &str, buffer_cap: usize, json_lines: bool) -> Self {
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
        Self {
            file: Arc::new(Mutex::new(file)),
            buffer: Arc::new(Mutex::new(VecDeque::with_capacity(buffer_cap.min(10_000)))),
            buffer_cap: buffer_cap.max(100).min(50_000),
            json_lines,
            node_id: node_id.to_string(),
        }
    }

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
    ) -> AccessRecord {
        let ts = chrono_like_now();
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
            cache_status: cache_status.to_string(),
            user_agent: truncate(user_agent, 256),
            referer: truncate(referer, 256),
        }
    }

    pub async fn write(&self, rec: AccessRecord) {
        // Combined-like text line
        let line = format!(
            "{ts} {ip} \"{method} {host}{path}\" status={status} bytes={bytes} cache={cache} {ms}ms ua=\"{ua}\" ref=\"{ref}\"",
            ts = rec.ts,
            ip = rec.client_ip,
            method = rec.method,
            host = rec.host,
            path = rec.path,
            status = rec.status,
            bytes = rec.bytes,
            cache = rec.cache_status,
            ms = rec.latency_ms,
            ua = rec.user_agent.replace('"', "'"),
            ref = rec.referer.replace('"', "'"),
        );
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
            "{line}"
        );

        let mut guard = self.file.lock().await;
        if let Some(f) = guard.as_mut() {
            let payload = if self.json_lines {
                match serde_json::to_string(&rec) {
                    Ok(s) => s,
                    Err(_) => line.clone(),
                }
            } else {
                line.clone()
            };
            let _ = f.write_all(payload.as_bytes()).await;
            let _ = f.write_all(b"\n").await;
        }
        drop(guard);

        let mut buf = self.buffer.lock().await;
        if buf.len() >= self.buffer_cap {
            buf.pop_front();
        }
        buf.push_back(rec);
    }

    /// Drain up to `limit` records for reporting (does not remove if report fails — caller decides)
    pub async fn snapshot(&self, limit: usize) -> Vec<AccessRecord> {
        let buf = self.buffer.lock().await;
        let n = limit.min(buf.len());
        buf.iter().rev().take(n).cloned().collect()
    }

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
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect::<String>() + "…"
    }
}

fn chrono_like_now() -> String {
    // RFC3339-ish without chrono dep on edge if not present — use system time
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // simple ISO-ish UTC approximation is ok; prefer format via time crate if available
    // Use humantime-free: seconds since epoch as fallback readable
    format_unix(secs)
}

fn format_unix(secs: u64) -> String {
    // Minimal UTC formatter (good enough for logs)
    const DAY: u64 = 86400;
    const HOUR: u64 = 3600;
    const MIN: u64 = 60;
    // days from 1970-01-01
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
