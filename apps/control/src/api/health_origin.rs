//! Origin health status (from edge probes)

use crate::middleware::agent_auth::AgentAuth;
use crate::middleware::AuthUser;
use crate::repository;
use crate::state::AppState;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct OriginHealthDto {
    pub domain_name: String,
    pub origin_url: String,
    pub healthy: bool,
    pub latency_ms: i32,
    pub last_check_at: Option<String>,
    pub last_error: String,
    pub consecutive_fails: i32,
}

#[derive(Deserialize)]
pub struct HealthReport {
    pub domain_name: String,
    pub origin_url: String,
    pub healthy: bool,
    pub latency_ms: u32,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct ReportAck {
    pub accepted: bool,
}

pub async fn list(
    State(state): State<AppState>,
    _user: AuthUser,
) -> Json<Vec<OriginHealthDto>> {
    let rows = repository::list_origin_health(&state.pool)
        .await
        .unwrap_or_default();
    Json(
        rows.into_iter()
            .map(|r| OriginHealthDto {
                domain_name: r.domain_name,
                origin_url: r.origin_url,
                healthy: r.healthy,
                latency_ms: r.latency_ms,
                last_check_at: r.last_check_at.map(|t| t.to_rfc3339()),
                last_error: r.last_error,
                consecutive_fails: r.consecutive_fails,
            })
            .collect(),
    )
}

pub async fn report(
    State(state): State<AppState>,
    _agent: AgentAuth,
    Json(req): Json<HealthReport>,
) -> Json<ReportAck> {
    if let Err(e) = repository::upsert_origin_health(
        &state.pool,
        &req.domain_name,
        &req.origin_url,
        req.healthy,
        req.latency_ms as i32,
        req.error.as_deref().unwrap_or(""),
    )
    .await
    {
        tracing::error!(error = %e, "origin health upsert");
        return Json(ReportAck { accepted: false });
    }
    Json(ReportAck { accepted: true })
}
