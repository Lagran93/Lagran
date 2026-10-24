//! Visitor access logs

use crate::middleware::agent_auth::AgentAuth;
use crate::middleware::AuthUser;
use crate::repository;
use crate::state::AppState;
use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct AccessEntryIn {
    pub ts: Option<String>,
    pub node_id: Option<String>,
    pub client_ip: Option<String>,
    pub method: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub status: Option<u16>,
    pub bytes: Option<u64>,
    pub latency_ms: Option<u64>,
    pub cache_status: Option<String>,
    pub user_agent: Option<String>,
    pub referer: Option<String>,
}

#[derive(Deserialize)]
pub struct ReportBody {
    pub entries: Vec<AccessEntryIn>,
}

#[derive(Serialize)]
pub struct ReportAck {
    pub accepted: usize,
}

#[derive(Deserialize)]
pub struct ListQuery {
    pub host: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Serialize)]
pub struct AccessLogDto {
    pub id: i64,
    pub ts: String,
    pub node_id: String,
    pub client_ip: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub status: i32,
    pub bytes: i64,
    pub latency_ms: i32,
    pub cache_status: String,
    pub user_agent: String,
    pub referer: String,
}

pub async fn report(
    State(state): State<AppState>,
    _agent: AgentAuth,
    Json(body): Json<ReportBody>,
) -> Json<ReportAck> {
    let mut rows = Vec::new();
    for e in body.entries {
        rows.push((
            e.ts.unwrap_or_default(),
            e.node_id.unwrap_or_default(),
            e.client_ip.unwrap_or_default(),
            e.method.unwrap_or_default(),
            e.host.unwrap_or_default(),
            e.path.unwrap_or_default(),
            e.status.unwrap_or(0) as i32,
            e.bytes.unwrap_or(0) as i64,
            e.latency_ms.unwrap_or(0) as i32,
            e.cache_status.unwrap_or_default(),
            e.user_agent.unwrap_or_default(),
            e.referer.unwrap_or_default(),
        ));
    }
    let n = rows.len();
    if let Err(e) = repository::insert_access_logs_batch(&state.pool, &rows).await {
        tracing::error!(error = %e, "insert access logs");
        return Json(ReportAck { accepted: 0 });
    }
    Json(ReportAck { accepted: n })
}

pub async fn list(
    State(state): State<AppState>,
    _user: AuthUser,
    Query(q): Query<ListQuery>,
) -> Json<Vec<AccessLogDto>> {
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let rows = repository::list_access_logs(&state.pool, q.host.as_deref(), limit)
        .await
        .unwrap_or_default();
    Json(
        rows.into_iter()
            .map(|r| AccessLogDto {
                id: r.id,
                ts: r.ts.to_rfc3339(),
                node_id: r.node_id,
                client_ip: r.client_ip,
                method: r.method,
                host: r.host,
                path: r.path,
                status: r.status,
                bytes: r.bytes,
                latency_ms: r.latency_ms,
                cache_status: r.cache_status,
                user_agent: r.user_agent,
                referer: r.referer,
            })
            .collect(),
    )
}
