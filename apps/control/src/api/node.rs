//! Edge node management
use crate::middleware::agent_auth::AgentAuth;

use crate::repository;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct NodeDto {
    pub id: String,
    pub name: String,
    pub region: String,
    pub ip: String,
    pub status: String,
    pub last_heartbeat: Option<String>,
    pub agent_url: String,
}

#[derive(Deserialize)]
pub struct HeartbeatRequest {
    pub node_id: Option<String>,
    pub region: Option<String>,
    pub ip: Option<String>,
    pub agent_url: Option<String>,
    pub cpu_usage: Option<f64>,
    pub memory_usage: Option<f64>,
    pub active_connections: Option<u64>,
}

#[derive(Serialize)]
pub struct HeartbeatResponse {
    pub accepted: bool,
    pub message: String,
}

pub async fn list(State(state): State<AppState>) -> Json<Vec<NodeDto>> {
    match repository::list_nodes(&state.pool).await {
        Ok(rows) => Json(
            rows.into_iter()
                .map(|r| NodeDto {
                    id: r.id.to_string(),
                    name: r.name,
                    region: r.region,
                    ip: r.ip,
                    status: r.status,
                    last_heartbeat: r.last_heartbeat.map(|t| t.to_rfc3339()),
                    agent_url: r.agent_url,
                })
                .collect(),
        ),
        Err(e) => {
            tracing::error!(error = %e, "list nodes");
            Json(vec![])
        }
    }
}

pub async fn heartbeat(
    State(state): State<AppState>,
    _agent: AgentAuth,
    Json(req): Json<HeartbeatRequest>,
) -> Json<HeartbeatResponse> {
    let node_id = req
        .node_id
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "edge-unknown".into());
    apply_heartbeat(&state, &node_id, &req).await
}

pub async fn heartbeat_by_path(
    State(state): State<AppState>,
    _agent: AgentAuth,
    Path(id): Path<String>,
    Json(req): Json<HeartbeatRequest>,
) -> Json<HeartbeatResponse> {
    apply_heartbeat(&state, &id, &req).await
}

async fn apply_heartbeat(
    state: &AppState,
    node_id: &str,
    req: &HeartbeatRequest,
) -> Json<HeartbeatResponse> {
    let region = req.region.clone().unwrap_or_default();
    let ip = req.ip.clone().unwrap_or_default();
    let agent_url = req.agent_url.clone().unwrap_or_default();

    match repository::upsert_node_heartbeat(&state.pool, node_id, &region, &ip, &agent_url).await {
        Ok(_) => {
            tracing::info!(node = %node_id, %agent_url, "heartbeat ok");
            Json(HeartbeatResponse {
                accepted: true,
                message: "ok".into(),
            })
        }
        Err(e) => {
            tracing::error!(error = %e, node = %node_id, "heartbeat");
            Json(HeartbeatResponse {
                accepted: false,
                message: e.to_string(),
            })
        }
    }
}
