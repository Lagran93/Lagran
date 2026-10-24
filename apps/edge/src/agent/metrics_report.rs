//! Flush local counters to control plane

use crate::config::EdgeConfig;
use crate::metrics::EdgeMetrics;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

pub fn spawn_metrics_report(config: EdgeConfig, metrics: Arc<EdgeMetrics>) {
    tokio::spawn(async move {
        let mut connector = HttpConnector::new();
        connector.set_nodelay(true);
        let client: Client<HttpConnector, Full<Bytes>> =
            Client::builder(TokioExecutor::new()).build(connector);

        let url = format!(
            "{}/api/v1/metrics/report",
            config.control_url.trim_end_matches('/')
        );
        let interval = Duration::from_secs(15);
        tracing::info!(%url, "metrics reporter started");

        loop {
            tokio::time::sleep(interval).await;
            let (requests, hits, misses, bytes) = metrics.take_snapshot();
            if requests == 0 && hits == 0 && misses == 0 {
                continue;
            }
            let body = json!({
                "node_id": config.node_id,
                "domain": config.domain,
                "requests": requests,
                "cache_hits": hits,
                "cache_misses": misses,
                "bytes_sent": bytes,
            });
            if let Err(e) = post_json(&client, &url, &body, &config.agent_token).await {
                tracing::warn!(error = %e, "metrics report failed");
                // put counters back roughly by re-adding (best-effort lost on failure)
            } else {
                tracing::debug!(requests, hits, misses, "metrics reported");
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
