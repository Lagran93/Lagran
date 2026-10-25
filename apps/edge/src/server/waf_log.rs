//! WAF event buffer shipped to the control plane.

use serde::Serialize;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize)]
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
}

impl WafLog {
    pub fn new(node_id: &str, cap: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(cap.min(10_000)))),
            cap: cap.clamp(100, 20_000),
            node_id: node_id.to_string(),
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

    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect()
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
