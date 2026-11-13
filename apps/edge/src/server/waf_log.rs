//! WAF event buffer shipped to the control plane.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafEvent {
    pub domain: String,
    pub node_id: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    /// block | monitor | log
    pub action: String,
    /// sqli | xss | traversal | scanners | ip_deny | custom
    pub category: String,
    pub rule_name: String,
    /// block | monitor
    pub mode: String,
}

#[derive(Clone)]
pub struct WafLog {
    inner: Arc<Mutex<VecDeque<WafEvent>>>,
    cap: usize,
    node_id: String,
    /// Events dropped by overflow, so the loss is visible instead of silent.
    dropped: Arc<std::sync::atomic::AtomicU64>,
}

impl WafLog {
    pub fn new(node_id: &str, cap: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(cap.min(10_000)))),
            cap: cap.clamp(100, 20_000),
            node_id: node_id.to_string(),
            dropped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn push(
        &self,
        domain: &str,
        client_ip: &str,
        method: &str,
        path: &str,
        action: &str,
        category: &str,
        rule_name: &str,
        mode: &str,
    ) {
        let mut buf = self.inner.lock().await;
        if buf.len() >= self.cap {
            buf.pop_front();
            self.dropped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        buf.push_back(WafEvent {
            domain: domain.to_string(),
            node_id: self.node_id.clone(),
            client_ip: client_ip.to_string(),
            method: method.to_string(),
            path: truncate(path, 512),
            action: action.to_string(),
            category: category.to_string(),
            rule_name: truncate(rule_name, 128),
            mode: mode.to_string(),
        });
    }

    pub async fn drain(&self, limit: usize) -> Vec<WafEvent> {
        let mut buf = self.inner.lock().await;
        let n = limit.min(buf.len());
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            if let Some(e) = buf.pop_front() {
                out.push(e);
            }
        }
        out
    }

    /// Put a failed batch back at the front.
    ///
    /// Eviction is oldest-first, matching `push`: this used to `pop_back()` here
    /// while `push` did `pop_front()`, so a full buffer dropped the newest events on
    /// one path and the oldest on the other. Dropping the oldest is the consistent
    /// choice — the newest events describe what is happening now.
    ///
    /// Returns how many events were dropped to make room.
    pub async fn requeue(&self, events: Vec<WafEvent>) -> u64 {
        if events.is_empty() {
            return 0;
        }
        let mut buf = self.inner.lock().await;
        let mut dropped = 0u64;
        for ev in events.into_iter().rev() {
            if buf.len() >= self.cap {
                buf.pop_front();
                dropped += 1;
            }
            buf.push_front(ev);
        }
        if dropped > 0 {
            self.dropped
                .fetch_add(dropped, std::sync::atomic::Ordering::Relaxed);
        }
        dropped
    }

    /// Total events dropped by overflow since start.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

fn truncate(s: &str, max: usize) -> String {
    // Single pass, ASCII fast path. See the note on `access_log::truncate`: the
    // two-pass form walked the string twice to learn a length it did not need.
    if s.is_ascii() {
        if s.len() <= max {
            return s.to_string();
        }
        return s[..max].to_string();
    }
    match s.char_indices().nth(max) {
        None => s.to_string(),
        Some((cut, _)) => s[..cut].to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pushes_and_drains_in_order() {
        let log = WafLog::new("node-1", 100);
        log.push(
            "a.test",
            "1.2.3.4",
            "GET",
            "/x",
            "block",
            "sqli",
            "SQL 注入",
            "block",
        )
        .await;
        log.push(
            "a.test", "1.2.3.5", "GET", "/y", "monitor", "xss", "XSS", "monitor",
        )
        .await;
        assert_eq!(log.len().await, 2);
        let drained = log.drain(10).await;
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].client_ip, "1.2.3.4");
        assert_eq!(drained[1].action, "monitor");
        assert_eq!(log.len().await, 0);
    }
}
