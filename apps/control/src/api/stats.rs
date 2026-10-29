use crate::middleware::authz::Actor;
use crate::repository;
use crate::state::AppState;
use axum::{extract::Query, extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    let rows = repository::list_domains(&state.pool)
        .await
        .unwrap_or_default();
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
        let online_nodes = repository::count_online_nodes(&state.pool)
            .await
            .unwrap_or(0);
        let (requests, hits, misses, bytes) = repository::sum_metrics(&state.pool)
            .await
            .unwrap_or((0, 0, 0, 0));
        return Ok(Json(build(
            requests,
            hits,
            misses,
            bytes,
            domain_count,
            online_nodes,
        )));
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

#[derive(Deserialize)]
pub struct RealtimeQuery {
    pub minutes: Option<i64>,
}

#[derive(Serialize)]
pub struct RealtimeDomain {
    pub domain: String,
    pub requests: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub bytes_sent: u64,
}

#[derive(Serialize)]
pub struct RealtimeStats {
    pub enabled: bool,
    pub minutes: i64,
    pub requests: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub bytes_sent: u64,
    pub hit_ratio: f64,
    pub domains: Vec<RealtimeDomain>,
}

/// Redis-backed near-realtime totals for the last N minutes. PostgreSQL is
/// still the durable source; this endpoint is only an accelerator.
pub async fn realtime(
    State(state): State<AppState>,
    actor: Actor,
    Query(query): Query<RealtimeQuery>,
) -> Json<RealtimeStats> {
    let minutes = query.minutes.unwrap_or(5).clamp(1, 60);
    let Some(redis) = state.redis.as_deref() else {
        return Json(empty_realtime(minutes, false));
    };
    let visible: Option<Vec<String>> = if actor.admin() {
        None
    } else {
        Some(visible_names(&state, &actor).await)
    };
    let now = chrono::Utc::now().timestamp() / 60;
    let mut totals = (0_i64, 0_i64, 0_i64, 0_i64);
    let mut domains: HashMap<String, (i64, i64, i64, i64)> = HashMap::new();
    let domains_to_read: Vec<String> = match &visible {
        // Use the tenant's actual domain list, not the Redis discovery set.
        // Redis may have restarted or a domain may not have reported yet, but
        // the normal user must still see every project domain.
        Some(names) => names.clone(),
        None => redis.realtime_domains().await,
    };
    for offset in 0..minutes {
        let minute = now - offset;
        if visible.is_none() {
            if let Some((requests, hits, misses, bytes)) = redis.realtime_totals(minute).await {
                totals.0 += requests;
                totals.1 += hits;
                totals.2 += misses;
                totals.3 += bytes;
            }
        }
        for domain in &domains_to_read {
            if let Some((requests, hits, misses, bytes)) =
                redis.realtime_domain_totals(minute, domain).await
            {
                if requests == 0 && bytes == 0 && hits == 0 && misses == 0 {
                    continue;
                }
                if visible.is_some() {
                    totals.0 += requests;
                    totals.1 += hits;
                    totals.2 += misses;
                    totals.3 += bytes;
                }
                let entry = domains.entry(domain.clone()).or_default();
                entry.0 += requests;
                entry.1 += hits;
                entry.2 += misses;
                entry.3 += bytes;
            }
        }
    }
    let total_hits = totals.1 + totals.2;
    let mut domain_rows: Vec<RealtimeDomain> = domains
        .into_iter()
        .map(
            |(domain, (requests, hits, misses, bytes))| RealtimeDomain {
                domain,
                requests: requests as u64,
                cache_hits: hits as u64,
                cache_misses: misses as u64,
                bytes_sent: bytes as u64,
            },
        )
        .collect();
    domain_rows.sort_by(|a, b| b.requests.cmp(&a.requests));
    domain_rows.truncate(20);
    Json(RealtimeStats {
        enabled: true,
        minutes,
        requests: totals.0 as u64,
        cache_hits: totals.1 as u64,
        cache_misses: totals.2 as u64,
        bytes_sent: totals.3 as u64,
        hit_ratio: if total_hits > 0 {
            totals.1 as f64 / total_hits as f64
        } else {
            0.0
        },
        domains: domain_rows,
    })
}

fn empty_realtime(minutes: i64, enabled: bool) -> RealtimeStats {
    RealtimeStats {
        enabled,
        minutes,
        requests: 0,
        cache_hits: 0,
        cache_misses: 0,
        bytes_sent: 0,
        hit_ratio: 0.0,
        domains: Vec::new(),
    }
}

#[derive(Deserialize)]
pub struct TimeseriesQuery {
    pub hours: Option<i32>,
    pub bucket: Option<i32>,
    #[serde(default)]
    pub compare: bool,
}

#[derive(Serialize)]
pub struct TimeseriesPoint {
    pub ts: String,
    pub requests: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub bytes_sent: u64,
    pub hit_ratio: f64,
}

#[derive(Serialize)]
pub struct TimeseriesResponse {
    pub current: Vec<TimeseriesPoint>,
    pub previous: Vec<TimeseriesPoint>,
    pub hours: i32,
    pub bucket: i32,
}

pub async fn timeseries(
    State(state): State<AppState>,
    actor: Actor,
    Query(query): Query<TimeseriesQuery>,
) -> Json<TimeseriesResponse> {
    let hours = query.hours.unwrap_or(24).clamp(1, 168);
    let bucket = query.bucket.unwrap_or(3600).clamp(60, 86_400);
    let hosts = if actor.admin() {
        None
    } else {
        Some(visible_names(&state, &actor).await)
    };
    let current = repository::metrics_timeseries(
        &state.pool,
        hosts.as_deref(),
        hours,
        0,
        bucket,
    )
    .await
    .unwrap_or_default();
    let previous = if query.compare {
        repository::metrics_timeseries(
            &state.pool,
            hosts.as_deref(),
            hours * 2,
            hours,
            bucket,
        )
        .await
        .unwrap_or_default()
    } else {
        Vec::new()
    };
    Json(TimeseriesResponse {
        current: points(current),
        previous: points(previous),
        hours,
        bucket,
    })
}

fn points(rows: Vec<(chrono::DateTime<chrono::Utc>, i64, i64, i64, i64)>) -> Vec<TimeseriesPoint> {
    rows.into_iter()
        .map(|(ts, requests, hits, misses, bytes)| {
            let total = hits + misses;
            TimeseriesPoint {
                ts: ts.to_rfc3339(),
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
        .collect()
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

pub async fn by_domain(State(state): State<AppState>, actor: Actor) -> Json<Vec<DomainMetricsDto>> {
    let rows = if actor.admin() {
        repository::metrics_by_domain(&state.pool)
            .await
            .unwrap_or_default()
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
