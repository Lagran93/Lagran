//! Cache purge — accept request and fan-out to online edge agents

use crate::middleware::authz::Actor;
use crate::repository;
use crate::service::agent_http;
use crate::state::AppState;
use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// Maximum number of edge agents contacted at once. A purge should not wait
/// for a slow/offline node before starting the next one, but an unbounded
/// fan-out could exhaust sockets or the control-plane connection pool.
const PURGE_CONCURRENCY: usize = 16;

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
    // `purge_all` clears every tenant's objects, so owning one domain is not
    // enough; without this check any tenant could flush the whole platform.
    if req.purge_all.unwrap_or(false) && !actor.admin() {
        return Err(forbidden());
    }
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

    // Only nodes that are currently online receive the fan-out. Contacting every
    // row that ever had an agent_url meant hundreds of dead addresses, each with a
    // connect timeout plus a retry, and the endpoint reported `success: false` even
    // though every live edge applied the purge. An offline node serves no traffic,
    // so it has nothing to purge; a node that dies mid-dispatch is still covered by
    // the per-node retry queue below.
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
            message: "no edge agents with agent_url; nothing dispatched".into(),
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
    let payload = match serde_json::to_value(&body) {
        Ok(payload) => payload,
        Err(e) => {
            tracing::error!(error = %e, "encode purge payload");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: "encode purge payload".into(),
                }),
            ));
        }
    };

    let expected = nodes.len();
    let concurrency = PURGE_CONCURRENCY.min(expected.max(1));
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut set = JoinSet::new();

    for (index, node) in nodes.into_iter().enumerate() {
        let name = node.name;
        let agent_url = node.agent_url;
        let auth_token = node.auth_token;
        let url = format!("{}/__lagran/purge", agent_url.trim_end_matches('/'));
        let token = if auth_token.is_empty() {
            state.config.agent_token.clone()
        } else {
            auth_token
        };
        let body = body.clone();
        let payload = payload.clone();
        let state = state.clone();
        let semaphore = semaphore.clone();

        set.spawn(async move {
            let _permit = match semaphore.acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => {
                    return (
                        index,
                        NodePurgeResult {
                            node: name,
                            agent_url,
                            success: false,
                            purged_count: 0,
                            message: "purge concurrency gate closed".into(),
                        },
                    );
                }
            };

            match dispatch_one(&url, &body, &token).await {
                Ok(reply) => {
                    if !reply.success {
                        let _ = repository::enqueue_purge_retry(
                            &state.pool,
                            &name,
                            &agent_url,
                            &payload,
                            &reply.message,
                        )
                        .await;
                    }
                    (
                        index,
                        NodePurgeResult {
                            node: name,
                            agent_url,
                            success: reply.success,
                            purged_count: reply.purged_count,
                            message: reply.message,
                        },
                    )
                }
                Err(e) => {
                    tracing::warn!(node = %name, error = %e, "purge dispatch failed; queued for retry");
                    let _ = repository::enqueue_purge_retry(
                        &state.pool,
                        &name,
                        &agent_url,
                        &payload,
                        &e,
                    )
                    .await;
                    (
                        index,
                        NodePurgeResult {
                            node: name,
                            agent_url,
                            success: false,
                            purged_count: 0,
                            message: e,
                        },
                    )
                }
            }
        });
    }

    let mut completed = Vec::with_capacity(expected);
    let mut any_fail = false;
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(item) => completed.push(item),
            Err(error) => {
                // A panicking worker must not leave the endpoint hanging.
                any_fail = true;
                tracing::error!(error = %error, "purge worker failed");
            }
        }
    }
    completed.sort_by_key(|(index, _)| *index);
    let results: Vec<NodePurgeResult> = completed.into_iter().map(|(_, result)| result).collect();
    let total: u64 = results.iter().map(|result| result.purged_count).sum();
    any_fail |= results.iter().any(|result| !result.success);
    any_fail |= results.len() < expected;

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
