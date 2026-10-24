//! Cache purge — accept request and fan-out to online edge agents

use crate::middleware::AuthUser;
use crate::repository;
use crate::state::AppState;
use axum::{extract::State, Json};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[derive(Deserialize, Clone)]
pub struct PurgeRequest {
    pub domain: String,
    pub urls: Option<Vec<String>>,
    pub prefixes: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    /// If true, clear entire edge cache (use with care)
    pub purge_all: Option<bool>,
}

#[derive(Serialize)]
pub struct NodePurgeResult {
    pub node: String,
    pub agent_url: String,
    pub success: bool,
    pub purged_count: u64,
    pub message: String,
}

#[derive(Serialize)]
pub struct PurgeResponse {
    pub success: bool,
    pub message: String,
    pub purged_count: u64,
    pub nodes: Vec<NodePurgeResult>,
}

#[derive(Serialize)]
struct EdgePurgeBody {
    domain: String,
    urls: Vec<String>,
    prefixes: Vec<String>,
    purge_all: bool,
}

#[derive(Deserialize)]
struct EdgePurgeReply {
    success: bool,
    purged_count: u64,
    message: String,
}

fn http_client() -> &'static Client<HttpConnector, Full<Bytes>> {
    static CLIENT: OnceLock<Client<HttpConnector, Full<Bytes>>> = OnceLock::new();
    CLIENT.get_or_init(|| {
        let mut connector = HttpConnector::new();
        connector.set_nodelay(true);
        Client::builder(TokioExecutor::new()).build(connector)
    })
}

pub async fn purge(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<PurgeRequest>,
) -> Json<PurgeResponse> {
    tracing::info!(
        domain = %req.domain,
        urls = ?req.urls,
        prefixes = ?req.prefixes,
        "purge requested"
    );

    let nodes = match repository::list_online_nodes_with_agent(&state.pool).await {
        Ok(n) => n,
        Err(e) => {
            tracing::error!(error = %e, "list nodes for purge");
            return Json(PurgeResponse {
                success: false,
                message: format!("database error: {e}"),
                purged_count: 0,
                nodes: vec![],
            });
        }
    };

    if nodes.is_empty() {
        return Json(PurgeResponse {
            success: true,
            message: "no online edge agents with agent_url; nothing dispatched".into(),
            purged_count: 0,
            nodes: vec![],
        });
    }

    let body = EdgePurgeBody {
        domain: req.domain.clone(),
        urls: req.urls.clone().unwrap_or_default(),
        prefixes: req.prefixes.clone().unwrap_or_default(),
        purge_all: req.purge_all.unwrap_or(false),
    };
    let body_bytes = Bytes::from(serde_json::to_vec(&body).unwrap_or_default());
    let client = http_client();

    let mut results = Vec::new();
    let mut total = 0u64;
    let mut any_fail = false;

    for node in nodes {
        let url = format!(
            "{}/__lagran/purge",
            node.agent_url.trim_end_matches('/')
        );
        let result = dispatch_one(client, &url, body_bytes.clone(), &state.config.agent_token).await;
        match result {
            Ok(reply) => {
                total += reply.purged_count;
                if !reply.success {
                    any_fail = true;
                }
                results.push(NodePurgeResult {
                    node: node.name.clone(),
                    agent_url: node.agent_url.clone(),
                    success: reply.success,
                    purged_count: reply.purged_count,
                    message: reply.message,
                });
            }
            Err(e) => {
                any_fail = true;
                tracing::warn!(node = %node.name, error = %e, "purge dispatch failed");
                results.push(NodePurgeResult {
                    node: node.name,
                    agent_url: node.agent_url,
                    success: false,
                    purged_count: 0,
                    message: e,
                });
            }
        }
    }

    let detail = format!("domain={} total={} nodes={}", req.domain, total, results.len());
    let _ = repository::insert_audit(&state.pool, &user.0.email, "purge", &req.domain, &detail).await;

    Json(PurgeResponse {
        success: !any_fail,
        message: if any_fail {
            "purge completed with some failures".into()
        } else {
            "purge dispatched to all online agents".into()
        },
        purged_count: total,
        nodes: results,
    })
}

async fn dispatch_one(
    client: &Client<HttpConnector, Full<Bytes>>,
    url: &str,
    body: Bytes,
    token: &str,
) -> Result<EdgePurgeReply, String> {
    let req = Request::builder()
        .method("POST")
        .uri(url)
        .header("content-type", "application/json")
        .header("x-lagran-agent-token", token)
        .body(Full::new(body))
        .map_err(|e| e.to_string())?;

    let resp = client.request(req).await.map_err(|e| e.to_string())?;
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();

    if !status.is_success() {
        return Err(format!(
            "HTTP {}: {}",
            status,
            String::from_utf8_lossy(&bytes)
        ));
    }

    serde_json::from_slice(&bytes).map_err(|e| format!("invalid edge response: {e}"))
}
