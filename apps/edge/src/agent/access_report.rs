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
            let n = batch.len();
            let body = json!({ "entries": batch });
            if let Err(e) = control
                .post_gzip_json("/api/v1/access-logs/report", &body)
                .await
            {
                tracing::warn!(error = %e, n, "access log report failed; re-queueing");
                if let Some(arr) = body.get("entries").cloned() {
                    if let Ok(restored) = serde_json::from_value(arr) {
                        access_log.requeue(restored).await;
                    }
                }
            } else {
                tracing::debug!(n, "access logs reported");
            }
        }
    });
}
