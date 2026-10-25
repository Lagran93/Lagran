//! Ship buffered WAF events to the control plane.

use crate::agent::ControlClient;
use crate::server::waf_log::WafLog;
use serde_json::json;
use std::time::Duration;

pub fn spawn_waf_report(control: ControlClient, log: WafLog, interval_secs: u64) {
    tokio::spawn(async move {
        let interval = Duration::from_secs(interval_secs.max(2));
        tracing::info!(url = %control.endpoint("/api/v1/waf/events"), ?interval, "WAF event reporter started");
        loop {
            tokio::time::sleep(interval).await;
            let events = log.drain(500).await;
            if events.is_empty() {
                continue;
            }
            let body = json!({ "events": events });
            if let Err(e) = control.post_json("/api/v1/waf/events", &body).await {
                tracing::warn!(error = %e, n = events.len(), "WAF event report failed");
            } else {
                tracing::debug!(n = events.len(), "WAF events reported");
            }
        }
    });
}
