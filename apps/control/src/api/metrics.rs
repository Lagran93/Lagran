//! Edge metrics ingest

use crate::middleware::agent_auth::AgentAuth;
use crate::repository;
use crate::state::AppState;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct MetricsReport {
    pub node_id: String,
    pub domain: Option<String>,
    pub requests: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub bytes_sent: u64,
}

#[derive(Serialize)]
pub struct MetricsAck {
    pub accepted: bool,
}

pub async fn report(
    State(state): State<AppState>,
    _agent: AgentAuth,
    Json(req): Json<MetricsReport>,
) -> Json<MetricsAck> {
    let domain = req
        .domain
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("(unknown)");

    if let Err(e) = repository::insert_metrics(
        &state.pool,
        &req.node_id,
        domain,
        req.requests as i64,
        req.cache_hits as i64,
        req.cache_misses as i64,
        req.bytes_sent as i64,
    )
    .await
    {
        tracing::error!(error = %e, "insert metrics");
        return Json(MetricsAck { accepted: false });
    }
    tracing::debug!(
        node = %req.node_id,
        domain = %domain,
        reqs = req.requests,
        hits = req.cache_hits,
        "metrics accepted"
    );
    Json(MetricsAck { accepted: true })
}
