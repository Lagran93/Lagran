//! Background agents: heartbeat, config sync, metrics

pub mod cert_sync;
pub mod config_sync;
pub mod metrics_report;
pub mod origin_health;

use crate::config::EdgeConfig;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::json;
use std::time::Duration;

pub fn spawn_heartbeat(config: EdgeConfig) {
    tokio::spawn(async move {
        let mut connector = HttpConnector::new();
        connector.set_nodelay(true);
        let client: Client<HttpConnector, Full<Bytes>> =
            Client::builder(TokioExecutor::new()).build(connector);

        let interval = Duration::from_secs(config.heartbeat_interval_secs.max(5));
        let url = format!(
            "{}/api/v1/nodes/heartbeat",
            config.control_url.trim_end_matches('/')
        );

        tracing::info!(
            target = %url,
            node_id = %config.node_id,
            "heartbeat agent started"
        );

        loop {
            if let Err(e) = send_once(&client, &url, &config).await {
                tracing::warn!(error = %e, "heartbeat failed");
            }
            tokio::time::sleep(interval).await;
        }
    });
}

async fn send_once(
    client: &Client<HttpConnector, Full<Bytes>>,
    url: &str,
    config: &EdgeConfig,
) -> Result<(), String> {
    let body = json!({
        "node_id": config.node_id,
        "region": config.region,
        "ip": config.listen_addr,
        "agent_url": config.agent_url,
    });
    let bytes = Bytes::from(serde_json::to_vec(&body).map_err(|e| e.to_string())?);
    let req = Request::builder()
        .method("POST")
        .uri(url)
        .header("content-type", "application/json")
        .header("x-lagran-agent-token", config.agent_token.as_str())
        .body(Full::new(bytes))
        .map_err(|e| e.to_string())?;
    let resp = client.request(req).await.map_err(|e| e.to_string())?;
    let status = resp.status();
    let body = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    if !status.is_success() {
        return Err(format!(
            "HTTP {}: {}",
            status,
            String::from_utf8_lossy(&body)
        ));
    }
    Ok(())
}
