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
use serde_json::json;
use std::time::Duration;

pub fn spawn_heartbeat(config: EdgeConfig, control: ControlClient) {
    tokio::spawn(async move {
        let interval = Duration::from_secs(config.heartbeat_interval_secs.max(5));
        tracing::info!(
            target = %control.endpoint("/api/v1/nodes/heartbeat"),
            node_id = %config.node_id,
            "heartbeat agent started"
        );

        loop {
            let body = json!({
                "node_id": config.node_id,
                "region": config.region,
                "ip": config.listen_addr,
                "agent_url": config.agent_url,
            });
            if let Err(e) = control.post_json("/api/v1/nodes/heartbeat", &body).await {
                tracing::warn!(error = %e, "heartbeat failed");
            }
            tokio::time::sleep(interval).await;
        }
    });
}
