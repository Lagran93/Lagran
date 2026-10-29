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

#[derive(Deserialize)]
pub struct MetricsBatch {
    pub items: Vec<MetricsReport>,
}

#[derive(Serialize)]
pub struct MetricsBatchAck {
    pub accepted: usize,
}

fn domain_or_unknown(domain: Option<&str>) -> &str {
    domain
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("(unknown)")
}

pub async fn report(
    State(state): State<AppState>,
    _agent: AgentAuth,
    Json(req): Json<MetricsReport>,
) -> Json<MetricsAck> {
    let domain = domain_or_unknown(req.domain.as_deref());

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
    if let Some(redis) = state.redis.as_deref() {
        let minute = chrono::Utc::now().timestamp() / 60;
        let _ = redis
            .record_realtime_metrics(
                minute,
                &[(
                    domain.to_string(),
                    req.requests as i64,
                    req.cache_hits as i64,
                    req.cache_misses as i64,
                    req.bytes_sent as i64,
                )],
            )
            .await;
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

/// Edge → control batch ingest. One request per flush instead of one per domain.
pub async fn report_batch(
    State(state): State<AppState>,
    _agent: AgentAuth,
    Json(body): Json<MetricsBatch>,
) -> Json<MetricsBatchAck> {
    let mut rows = Vec::with_capacity(body.items.len().min(1000));
    for req in body.items.into_iter().take(1000) {
        let domain = domain_or_unknown(req.domain.as_deref()).to_string();
        rows.push((
            req.node_id,
            domain,
            req.requests as i64,
            req.cache_hits as i64,
            req.cache_misses as i64,
            req.bytes_sent as i64,
        ));
    }
    if rows.is_empty() {
        return Json(MetricsBatchAck { accepted: 0 });
    }
    let accepted = rows.len();
    if let Err(e) = repository::insert_metrics_batch(&state.pool, &rows).await {
        tracing::error!(error = %e, "insert metrics batch");
        return Json(MetricsBatchAck { accepted: 0 });
    }
    if let Some(redis) = state.redis.as_deref() {
        let minute = chrono::Utc::now().timestamp() / 60;
        let realtime: Vec<(String, i64, i64, i64, i64)> = rows
            .iter()
            .map(|(_, domain, requests, hits, misses, bytes)| {
                (
                    domain.clone(),
                    *requests,
                    *hits,
                    *misses,
                    *bytes,
                )
            })
            .collect();
        let _ = redis.record_realtime_metrics(minute, &realtime).await;
    }
    tracing::debug!(accepted, "metrics batch accepted");
    Json(MetricsBatchAck { accepted })
}
