//! Public edge endpoints for the onboarding wizard (no agent secrets).

use crate::middleware::authz::Actor;
use crate::repository;
use crate::state::AppState;
use axum::{extract::State, Json};
use serde::Serialize;

#[derive(Serialize)]
pub struct EdgeEndpointDto {
    pub name: String,
    pub ip: String,
    pub region: String,
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
    for node in nodes.into_iter().filter(|n| n.status == "online") {
        let ip = if node.public_ip.trim().is_empty() {
            node.ip.clone()
        } else {
            node.public_ip.clone()
        };
        if !ip.trim().is_empty() && !ips.contains(&ip) {
            ips.push(ip.clone());
        }
        out.push(EdgeEndpointDto {
            name: node.name,
            ip,
            region: node.region,
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
