//! Batch upload access logs to control plane

use crate::config::EdgeConfig;
use crate::server::access_log::AccessLog;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::json;
use std::time::Duration;

pub fn spawn_access_report(config: EdgeConfig, access_log: AccessLog) {
    if !config.access_log_report {
        tracing::info!("access log remote report disabled");
        return;
    }
    tokio::spawn(async move {
        let mut connector = HttpConnector::new();
        connector.set_nodelay(true);
        let client: Client<HttpConnector, Full<Bytes>> =
            Client::builder(TokioExecutor::new()).build(connector);
        let url = format!(
            "{}/api/v1/access-logs/report",
            config.control_url.trim_end_matches('/')
        );
        let interval = Duration::from_secs(config.access_log_report_interval_secs.max(5));
        tracing::info!(%url, ?interval, "access log reporter started");

        loop {
            tokio::time::sleep(interval).await;
            let batch = access_log.drain(500).await;
            if batch.is_empty() {
                continue;
            }
            let body = json!({ "entries": batch });
            if let Err(e) = post_json(&client, &url, &body, &config.agent_token).await {
                tracing::warn!(error = %e, n = batch.len(), "access log report failed");
                // put back best-effort via re-write (already drained — accept loss on failure for now)
            } else {
                tracing::debug!(n = batch.len(), "access logs reported");
            }
        }
    });
}

async fn post_json(
    client: &Client<HttpConnector, Full<Bytes>>,
    url: &str,
    body: &serde_json::Value,
    token: &str,
) -> Result<(), String> {
    let bytes = Bytes::from(serde_json::to_vec(body).map_err(|e| e.to_string())?);
    let req = Request::builder()
        .method("POST")
        .uri(url)
        .header("content-type", "application/json")
        .header("x-lagran-agent-token", token)
        .body(Full::new(bytes))
        .map_err(|e| e.to_string())?;
    let resp = client.request(req).await.map_err(|e| e.to_string())?;
    let status = resp.status();
    let _ = resp.into_body().collect().await;
    if !status.is_success() {
        return Err(format!("HTTP {status}"));
    }
    Ok(())
}
