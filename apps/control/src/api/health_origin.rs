//! Origin health status (from edge probes), scoped to the caller's domains.

use crate::middleware::agent_auth::AgentAuth;
use crate::middleware::authz::Actor;
use crate::repository;
use crate::state::AppState;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

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

pub async fn list(State(state): State<AppState>, actor: Actor) -> Json<Vec<OriginHealthDto>> {
    let rows = repository::list_origin_health(&state.pool)
        .await
        .unwrap_or_default();

    let visible_names: Option<HashSet<String>> = match actor.visible_domain_ids(&state).await {
        None => None,
        Some(ids) => {
            let domains = repository::list_domains(&state.pool).await.unwrap_or_default();
            Some(
                domains
                    .into_iter()
                    .filter(|d| ids.contains(&d.id))
                    .map(|d| d.name)
                    .collect(),
            )
        }
    };

    Json(
        rows.into_iter()
            .filter(|r| match &visible_names {
                None => true,
                Some(names) => names.contains(&r.domain_name),
            })
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
