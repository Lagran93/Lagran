//! Public edge endpoints for the onboarding wizard (no agent secrets).

use crate::middleware::authz::Actor;
use crate::repository;
use crate::state::AppState;
use axum::{extract::State, Json};
use serde::Serialize;

#[derive(Serialize)]
pub struct EdgeEndpointDto {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub region: String,
    pub status: String,
    pub cpu_usage: Option<f64>,
    pub memory_usage: Option<f64>,
    pub active_connections: Option<i64>,
    pub last_heartbeat: Option<String>,
}

#[derive(Serialize)]
pub struct EdgeEndpointsResponse {
    pub cname: String,
    pub ips: Vec<String>,
    pub nodes: Vec<EdgeEndpointDto>,
}

/// Any authenticated user may read online node IPs; this is required to show
/// DNS instructions during onboarding without exposing agent URLs/tokens.
pub async fn list(
    State(state): State<AppState>,
    _actor: Actor,
) -> Json<EdgeEndpointsResponse> {
    let nodes = repository::list_nodes(&state.pool).await.unwrap_or_default();
    let mut ips = Vec::new();
    let mut out = Vec::new();
    for node in nodes.into_iter() {
        let online = node.status == "online";
        let ip = crate::utils::normalize_node_ip(&node.public_ip)
            .or_else(|| crate::utils::normalize_node_ip(&node.ip))
            .unwrap_or_default();
        if online && !ip.trim().is_empty() && !ips.contains(&ip) {
            ips.push(ip.clone());
        }
        out.push(EdgeEndpointDto {
            id: node.id.to_string(),
            name: node.name,
            ip,
            region: node.region,
            status: node.status,
            cpu_usage: node.cpu_usage,
            memory_usage: node.memory_usage,
            active_connections: node.active_connections,
            last_heartbeat: node.last_heartbeat.map(|v| v.to_rfc3339()),
        });
    }
    let cname = std::env::var("EDGE_CNAME")
        .or_else(|_| std::env::var("EDGE_ACCESS_DOMAIN"))
        .unwrap_or_default();
    Json(EdgeEndpointsResponse {
        cname,
        ips,
        nodes: out,
    })
}
