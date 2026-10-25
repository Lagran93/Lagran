//! Background agents: heartbeat, config sync, metrics
pub mod access_report;

pub mod cert_sync;
pub mod config_sync;
pub mod control_client;
pub mod metrics_report;
pub mod origin_health;
pub mod waf_report;

pub use control_client::ControlClient;

use crate::config::EdgeConfig;
use serde::Deserialize;
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Whether this node is allowed to serve traffic. Updated from the heartbeat
/// response so an admin can drain a node from the console.
#[derive(Clone)]
pub struct NodeControl {
    serving: Arc<AtomicBool>,
}

impl NodeControl {
    pub fn new() -> Self {
        Self {
            serving: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn is_serving(&self) -> bool {
        self.serving.load(Ordering::Relaxed)
    }

    /// Returns true when the state actually changed.
    pub fn set_serving(&self, enabled: bool) -> bool {
        let previous = self.serving.swap(enabled, Ordering::Relaxed);
        previous != enabled
    }
}

impl Default for NodeControl {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Deserialize)]
struct HeartbeatReply {
    #[serde(default)]
    accepted: bool,
    #[serde(default)]
    message: String,
    #[serde(default = "default_enabled")]
    enabled: bool,
    #[serde(default)]
    status: String,
}

fn default_enabled() -> bool {
    true
}

pub fn spawn_heartbeat(config: EdgeConfig, control: ControlClient, node_control: NodeControl) {
    tokio::spawn(async move {
        let interval = Duration::from_secs(config.heartbeat_interval_secs.max(5));
        tracing::info!(
            target = %control.endpoint("/api/v1/nodes/heartbeat"),
            node_id = %config.node_id,
            version = env!("CARGO_PKG_VERSION"),
            "heartbeat agent started"
        );

        loop {
            let body = json!({
                "node_id": config.node_id,
                "region": config.region,
                "ip": config.listen_addr,
                "agent_url": config.agent_url,
                "version": env!("CARGO_PKG_VERSION"),
                "cpu_usage": cpu_usage(),
                "memory_usage": memory_usage(),
            });
            match control
                .post_json_for::<_, HeartbeatReply>("/api/v1/nodes/heartbeat", &body)
                .await
            {
                Ok(reply) => {
                    if !reply.accepted {
                        tracing::warn!(message = %reply.message, "heartbeat rejected");
                    }
                    if node_control.set_serving(reply.enabled) {
                        if reply.enabled {
                            tracing::info!(
                                status = %reply.status,
                                "node enabled by control plane; serving traffic"
                            );
                        } else {
                            tracing::warn!(
                                status = %reply.status,
                                "node disabled by control plane; returning 503 until re-enabled"
                            );
                        }
                    }
                }
                Err(e) => tracing::warn!(error = %e, "heartbeat failed"),
            }
            tokio::time::sleep(interval).await;
        }
    });
}

fn cpu_usage() -> Option<f64> {
    let load = std::fs::read_to_string("/proc/loadavg").ok()?;
    let first = load.split_whitespace().next()?.parse::<f64>().ok()?;
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1) as f64;
    Some((((first / cpus) * 100.0 * 10.0).round() / 10.0).clamp(0.0, 100.0))
}

fn memory_usage() -> Option<f64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    let mut total = 0f64;
    let mut available = 0f64;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total = rest.split_whitespace().next()?.parse().ok()?;
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            available = rest.split_whitespace().next()?.parse().ok()?;
        }
    }
    if total <= 0.0 {
        return None;
    }
    Some(((((total - available) / total) * 100.0 * 10.0).round() / 10.0).clamp(0.0, 100.0))
}
