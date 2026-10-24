use crate::middleware::AuthUser;
use crate::repository;
use crate::state::AppState;
use axum::{extract::State, Json};
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

pub async fn summary(
    State(state): State<AppState>,
    _user: AuthUser,
) -> Json<StatsSummary> {
    let _ = repository::mark_stale_nodes_offline(&state.pool, 60).await;

    let domain_count = repository::count_domains(&state.pool).await.unwrap_or(0);
    let online_nodes = repository::count_online_nodes(&state.pool).await.unwrap_or(0);
    let (requests, hits, misses, bytes) =
        repository::sum_metrics(&state.pool).await.unwrap_or((0, 0, 0, 0));

    let total = hits + misses;
    let hit_ratio = if total > 0 {
        hits as f64 / total as f64
    } else {
        0.0
    };

    Json(StatsSummary {
        total_requests: requests as u64,
        cache_hits: hits as u64,
        cache_misses: misses as u64,
        bytes_sent: bytes as u64,
        hit_ratio,
        domain_count,
        online_nodes,
    })
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
    _user: AuthUser,
) -> Json<Vec<DomainMetricsDto>> {
    let rows = repository::metrics_by_domain(&state.pool)
        .await
        .unwrap_or_default();
    Json(
        rows.into_iter()
            .map(|(domain, requests, hits, misses, bytes)| {
                let total = hits + misses;
                let hit_ratio = if total > 0 {
                    hits as f64 / total as f64
                } else {
                    0.0
                };
                DomainMetricsDto {
                    domain,
                    requests: requests as u64,
                    cache_hits: hits as u64,
                    cache_misses: misses as u64,
                    bytes_sent: bytes as u64,
                    hit_ratio,
                }
            })
            .collect(),
    )
}
