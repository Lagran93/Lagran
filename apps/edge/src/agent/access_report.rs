//! Batch upload access logs to control plane

use crate::agent::ControlClient;
use crate::config::EdgeConfig;
use crate::server::access_log::{AccessLog, MAX_REPORT_ATTEMPTS};
use serde_json::json;
use std::time::Duration;

pub fn spawn_access_report(config: EdgeConfig, control: ControlClient, access_log: AccessLog) {
    if !config.access_log_report {
        tracing::info!("access log remote report disabled");
        return;
    }
    // Supervised: a panic here would silently stop access-log reporting.
    crate::agent::spawn_supervised("access-report", move || {
        let config = config.clone();
        let control = control.clone();
        let access_log = access_log.clone();
        async move {
            let interval = Duration::from_secs(config.access_log_report_interval_secs.max(5));
            tracing::info!(url = %control.endpoint("/api/v1/access-logs/report"), ?interval, "access log reporter started");

            // Consecutive failures, used to decide when to stop re-queueing.
            let mut attempts: u32 = 0;
            loop {
                tokio::time::sleep(interval).await;
                let batch = access_log.drain(500).await;
                if batch.is_empty() {
                    attempts = 0;
                    continue;
                }
                let n = batch.len();
                let body = json!({ "entries": batch });
                if let Err(e) = control
                    .post_gzip_json("/api/v1/access-logs/report", &body)
                    .await
                {
                    attempts = attempts.saturating_add(1);
                    // Re-queueing puts these records back at the head, so the next
                    // `drain` returns the same batch. Left unbounded, a control plane
                    // that stays down pins the buffer on 500 old records: the live
                    // tail ages out unread while `/__lagran/access-logs` keeps
                    // showing the same lines. After a few attempts the batch is
                    // dropped and counted, which keeps recent logs flowing and makes
                    // the loss visible.
                    let restored = body
                        .get("entries")
                        .cloned()
                        .and_then(|arr| serde_json::from_value(arr).ok())
                        .unwrap_or_default();
                    let dropped = access_log.requeue_bounded(restored, attempts).await;
                    if dropped > 0 {
                        tracing::warn!(
                            error = %e,
                            n,
                            attempts,
                            dropped,
                            "access log report failed; batch dropped after {MAX_REPORT_ATTEMPTS} attempts"
                        );
                    } else {
                        tracing::warn!(
                            error = %e,
                            n,
                            attempts,
                            "access log report failed; re-queueing"
                        );
                    }
                } else {
                    attempts = 0;
                    tracing::debug!(n, "access logs reported");
                }
            }
        }
    });
}
