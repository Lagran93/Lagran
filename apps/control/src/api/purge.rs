//! Cache purge — accept request and fan-out to online edge agents

use crate::middleware::authz::Actor;
use crate::repository;
use crate::service::agent_http;
use crate::state::AppState;
use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

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
pub struct ErrorBody {
    pub error: String,
}

#[derive(Serialize, Clone)]
struct EdgePurgeBody {
    domain: String,
    urls: Vec<String>,
    prefixes: Vec<String>,
    tags: Vec<String>,
    purge_all: bool,
}

#[derive(Deserialize)]
struct EdgePurgeReply {
    success: bool,
    purged_count: u64,
    message: String,
}

pub async fn purge(
    State(state): State<AppState>,
    actor: Actor,
    Json(req): Json<PurgeRequest>,
) -> Result<Json<PurgeResponse>, (StatusCode, Json<ErrorBody>)> {
    // Purging affects one tenant's cache: require write access to that domain.
    // A global `purge_all` without a domain is admin-only.
    if req.domain.trim().is_empty() {
        if !actor.admin() {
            return Err(forbidden());
        }
    } else if !actor.can_write_domain_name(&state, req.domain.trim()).await {
        return Err(forbidden());
    }

    tracing::info!(
        domain = %req.domain,
        actor = %actor.email,
        urls = ?req.urls,
        prefixes = ?req.prefixes,
        "purge requested"
    );

    let nodes = match repository::list_online_nodes_with_agent(&state.pool).await {
        Ok(n) => n,
        Err(e) => {
            tracing::error!(error = %e, "list nodes for purge");
            return Ok(Json(PurgeResponse {
                success: false,
                message: format!("database error: {e}"),
                purged_count: 0,
                nodes: vec![],
            }));
        }
    };

    if nodes.is_empty() {
        return Ok(Json(PurgeResponse {
            success: true,
            message: "no online edge agents with agent_url; nothing dispatched".into(),
            purged_count: 0,
            nodes: vec![],
        }));
    }

    let body = EdgePurgeBody {
        domain: req.domain.clone(),
        urls: req.urls.clone().unwrap_or_default(),
        prefixes: req.prefixes.clone().unwrap_or_default(),
        tags: req.tags.clone().unwrap_or_default(),
        purge_all: req.purge_all.unwrap_or(false),
    };

    let mut results = Vec::new();
    let mut total = 0u64;
    let mut any_fail = false;

    for node in nodes {
        let url = format!("{}/__lagran/purge", node.agent_url.trim_end_matches('/'));
        let token = if node.auth_token.is_empty() {
            state.config.agent_token.clone()
        } else {
            node.auth_token.clone()
        };
        let result = dispatch_one(&url, &body, &token).await;
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

    let detail = format!(
        "domain={} total={} nodes={}",
        req.domain,
        total,
        results.len()
    );
    let _ =
        repository::insert_audit(&state.pool, &actor.email, "purge", &req.domain, &detail).await;

    Ok(Json(PurgeResponse {
        success: !any_fail,
        message: if any_fail {
            "purge completed with some failures".into()
        } else {
            "purge dispatched to all online agents".into()
        },
        purged_count: total,
        nodes: results,
    }))
}

fn forbidden() -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorBody {
            error: "forbidden".into(),
        }),
    )
}

async fn dispatch_one(
    url: &str,
    body: &EdgePurgeBody,
    token: &str,
) -> Result<EdgePurgeReply, String> {
    agent_http::request_json("POST", url, body, token).await
}
