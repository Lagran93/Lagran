//! Batch upload access logs to control plane

use crate::agent::ControlClient;
use crate::config::EdgeConfig;
use crate::server::access_log::AccessLog;
use serde_json::json;
use std::time::Duration;

pub fn spawn_access_report(config: EdgeConfig, control: ControlClient, access_log: AccessLog) {
    if !config.access_log_report {
        tracing::info!("access log remote report disabled");
        return;
    }
    tokio::spawn(async move {
        let interval = Duration::from_secs(config.access_log_report_interval_secs.max(5));
        tracing::info!(url = %control.endpoint("/api/v1/access-logs/report"), ?interval, "access log reporter started");

        loop {
            tokio::time::sleep(interval).await;
            let batch = access_log.drain(500).await;
            if batch.is_empty() {
                continue;
            }
            let body = json!({ "entries": batch });
            if let Err(e) = control.post_json("/api/v1/access-logs/report", &body).await {
                // Records are drained; on failure they are lost (bounded buffer).
                tracing::warn!(error = %e, n = batch.len(), "access log report failed");
            } else {
                tracing::debug!(n = batch.len(), "access logs reported");
            }
        }
    });
}
