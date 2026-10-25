use crate::middleware::authz::Actor;
use crate::repository;
use crate::state::AppState;
use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;

#[derive(Serialize)]
pub struct StatsSummary {
    pub total_requests: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub bytes_sent: u64,
    pub hit_ratio: f64,
    pub domain_count: i64,
    pub online_nodes: i64,
}

#[derive(Serialize)]
pub struct ErrorBody {
    pub error: String,
}

/// Domain names the actor may see, or `None` for "all domains".
async fn visible_names(state: &AppState, actor: &Actor) -> Vec<String> {
    let rows = repository::list_domains(&state.pool).await.unwrap_or_default();
    match actor.visible_domain_ids(state).await {
        None => rows.into_iter().map(|d| d.name).collect(),
        Some(ids) => rows
            .into_iter()
            .filter(|d| ids.contains(&d.id))
            .map(|d| d.name)
            .collect(),
    }
}

pub async fn summary(
    State(state): State<AppState>,
    actor: Actor,
) -> Result<Json<StatsSummary>, (StatusCode, Json<ErrorBody>)> {
    let _ = repository::mark_stale_nodes_offline(&state.pool, 60).await;

    if actor.admin() {
        let domain_count = repository::count_domains(&state.pool).await.unwrap_or(0);
        let online_nodes = repository::count_online_nodes(&state.pool).await.unwrap_or(0);
        let (requests, hits, misses, bytes) = repository::sum_metrics(&state.pool)
            .await
            .unwrap_or((0, 0, 0, 0));
        return Ok(Json(build(requests, hits, misses, bytes, domain_count, online_nodes)));
    }

    let names = visible_names(&state, &actor).await;
    if names.is_empty() {
        return Ok(Json(build(0, 0, 0, 0, 0, 0)));
    }
    let (requests, hits, misses, bytes) = repository::sum_metrics_for(&state.pool, &names)
        .await
        .unwrap_or((0, 0, 0, 0));
    Ok(Json(build(
        requests,
        hits,
        misses,
        bytes,
        names.len() as i64,
        0,
    )))
}

fn build(
    requests: i64,
    hits: i64,
    misses: i64,
    bytes: i64,
    domain_count: i64,
    online_nodes: i64,
) -> StatsSummary {
    let total = hits + misses;
    StatsSummary {
        total_requests: requests as u64,
        cache_hits: hits as u64,
        cache_misses: misses as u64,
        bytes_sent: bytes as u64,
        hit_ratio: if total > 0 {
            hits as f64 / total as f64
        } else {
            0.0
        },
        domain_count,
        online_nodes,
    }
}

#[derive(Serialize)]
pub struct DomainMetricsDto {
    pub domain: String,
    pub requests: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub bytes_sent: u64,
    pub hit_ratio: f64,
}

pub async fn by_domain(
    State(state): State<AppState>,
    actor: Actor,
) -> Json<Vec<DomainMetricsDto>> {
    let rows = if actor.admin() {
        repository::metrics_by_domain(&state.pool).await.unwrap_or_default()
    } else {
        let names = visible_names(&state, &actor).await;
        repository::metrics_by_domain_for(&state.pool, &names)
            .await
            .unwrap_or_default()
    };
    Json(
        rows.into_iter()
            .map(|(domain, requests, hits, misses, bytes)| {
                let total = hits + misses;
                DomainMetricsDto {
                    domain,
                    requests: requests as u64,
                    cache_hits: hits as u64,
                    cache_misses: misses as u64,
                    bytes_sent: bytes as u64,
                    hit_ratio: if total > 0 {
                        hits as f64 / total as f64
                    } else {
                        0.0
                    },
                }
            })
            .collect(),
    )
}
