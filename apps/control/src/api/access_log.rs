//! Visitor access logs (agent ingest + tenant-filtered read)

use crate::middleware::agent_auth::AgentAuth;
use crate::middleware::authz::Actor;
use crate::repository;
use crate::state::AppState;
use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};

type AccessLogInsertRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    i32,
    i64,
    i32,
    String,
    String,
    String,
    String,
);

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
    pub action: Option<String>,
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
    /// 2xx / 3xx / 4xx / 5xx
    pub status_class: Option<String>,
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
    pub action: String,
    pub user_agent: String,
    pub referer: String,
}

/// Split an ingest batch into rows that belong to a domain and hostless rows.
///
/// Keeping this pure lets the ingest boundary have a regression test without a
/// database: hostless rows are exactly what produced unattributed `—` entries
/// in the console.
fn partition_domain_rows(entries: Vec<AccessEntryIn>) -> (Vec<AccessLogInsertRow>, usize) {
    let mut rows = Vec::new();
    let mut rejected = 0usize;
    for e in entries {
        let host = e.host.unwrap_or_default();
        if host.trim().is_empty() {
            rejected += 1;
            continue;
        }
        rows.push((
            e.ts.unwrap_or_default(),
            e.node_id.unwrap_or_default(),
            e.client_ip.unwrap_or_default(),
            e.method.unwrap_or_default(),
            host,
            e.path.unwrap_or_default(),
            e.status.unwrap_or(0) as i32,
            e.bytes.unwrap_or(0) as i64,
            e.latency_ms.unwrap_or(0) as i32,
            e.cache_status.unwrap_or_default(),
            e.action.unwrap_or_default(),
            e.user_agent.unwrap_or_default(),
            e.referer.unwrap_or_default(),
        ));
    }
    (rows, rejected)
}

pub async fn report(
    State(state): State<AppState>,
    _agent: AgentAuth,
    Json(body): Json<ReportBody>,
) -> Json<ReportAck> {
    let (rows, rejected) = partition_domain_rows(body.entries);
    let n = rows.len();
    if rejected > 0 {
        tracing::warn!(
            rejected,
            accepted = n,
            "access-log report contained hostless entries; dropped"
        );
    }
    if let Err(e) = repository::insert_access_logs_batch(&state.pool, &rows).await {
        tracing::error!(error = %e, "insert access logs");
        return Json(ReportAck { accepted: 0 });
    }
    Json(ReportAck { accepted: n })
}

pub async fn list(
    State(state): State<AppState>,
    actor: Actor,
    Query(q): Query<ListQuery>,
) -> Json<Vec<AccessLogDto>> {
    // Non-admins only see hosts that belong to their projects.
    let visible_hosts: Option<Vec<String>> = match actor.visible_domain_ids(&state).await {
        None => None,
        Some(ids) => {
            Some(
                repository::domain_names_by_ids(&state.pool, &ids)
                    .await
                    .unwrap_or_default()
                    .into_values()
                    .collect(),
            )
        }
    };

    if let Some(ref hosts) = visible_hosts {
        if let Some(ref h) = q.host {
            if !hosts.contains(h) {
                return Json(vec![]);
            }
        }
    }

    let (status_min, status_max) = match q.status_class.as_deref() {
        Some("2xx") => (Some(200), Some(300)),
        Some("3xx") => (Some(300), Some(400)),
        Some("4xx") => (Some(400), Some(500)),
        Some("5xx") => (Some(500), Some(600)),
        _ => (None, None),
    };
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let rows = repository::list_access_logs(
        &state.pool,
        q.host.as_deref(),
        visible_hosts,
        status_min,
        status_max,
        limit,
    )
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
                action: r.action,
                user_agent: r.user_agent,
                referer: r.referer,
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(host: Option<&str>, path: &str) -> AccessEntryIn {
        AccessEntryIn {
            ts: None,
            node_id: Some("edge-kr-01".into()),
            client_ip: Some("203.0.113.9".into()),
            method: Some("GET".into()),
            host: host.map(str::to_string),
            path: Some(path.into()),
            status: Some(404),
            bytes: Some(0),
            latency_ms: Some(0),
            cache_status: Some("NONE".into()),
            action: Some(String::new()),
            user_agent: Some("curl".into()),
            referer: None,
        }
    }

    #[test]
    fn hostless_ingest_rows_are_rejected() {
        let entries = vec![
            entry(None, "/.env-signed"),
            entry(Some("  "), "/mailjet.env"),
            entry(Some("cdn.example.com"), "/asset.js"),
        ];
        let (rows, rejected) = partition_domain_rows(entries);
        assert_eq!(rejected, 2);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].4, "cdn.example.com");
        assert_eq!(rows[0].5, "/asset.js");
    }
}
