//! Best-effort notify online edges to pull config / purge immediately.

use crate::repository;
use crate::state::AppState;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::time::Duration;

fn http_client() -> Client<HttpConnector, Full<Bytes>> {
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    connector.set_connect_timeout(Some(Duration::from_secs(3)));
    Client::builder(TokioExecutor::new()).build(connector)
}

/// POST /__lagran/config/reload on every online edge with an agent_url.
pub async fn notify_config_reload(state: &AppState) {
    let nodes = match repository::list_online_nodes_with_agent(&state.pool).await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "list nodes for config notify failed");
            return;
        }
    };
    if nodes.is_empty() {
        return;
    }
    let client = http_client();
    let global = state.config.agent_token.clone();
    for node in nodes {
        let url = format!(
            "{}/__lagran/config/reload",
            node.agent_url.trim_end_matches('/')
        );
        let token = if node.auth_token.is_empty() {
            global.clone()
        } else {
            node.auth_token.clone()
        };
        let client = client.clone();
        tokio::spawn(async move {
            let req = Request::builder()
                .method("POST")
                .uri(&url)
                .header("content-type", "application/json")
                .header("x-lagran-agent-token", &token)
                .body(Full::new(Bytes::from_static(b"{}")))
                .ok();
            let Some(req) = req else { return };
            match client.request(req).await {
                Ok(resp) => {
                    let status = resp.status();
                    let _ = resp.into_body().collect().await;
                    if !status.is_success() {
                        tracing::debug!(%url, %status, "config reload notify non-success");
                    }
                }
                Err(e) => tracing::debug!(%url, error = %e, "config reload notify failed"),
            }
        });
    }
}
