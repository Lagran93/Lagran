//! Config delivery for edge nodes

use crate::repository;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;

#[derive(Serialize)]
pub struct OriginConfig {
    pub host: String,
    pub port: u16,
    pub protocol: String,
}

#[derive(Serialize)]
pub struct CacheRuleConfig {
    pub path_pattern: String,
    pub ttl_seconds: u64,
    pub priority: i32,
}

#[derive(Serialize)]
pub struct DomainConfigResponse {
    pub domain: String,
    pub origin: OriginConfig,
    pub rules: Vec<CacheRuleConfig>,
    pub version: String,
}

#[derive(Serialize)]
pub struct ErrorBody {
    pub error: String,
}

pub async fn get_domain_config(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Result<Json<DomainConfigResponse>, (StatusCode, Json<ErrorBody>)> {
    let row = repository::get_domain_by_name(&state.pool, &domain)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: "database error".into(),
                }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorBody {
                    error: "domain not found".into(),
                }),
            )
        })?;

    let rules = repository::list_rules_for_domain(&state.pool, row.id)
        .await
        .unwrap_or_default();

    let rule_count = rules.len();
    Ok(Json(DomainConfigResponse {
        domain: row.name,
        origin: OriginConfig {
            host: row.origin_host,
            port: row.origin_port as u16,
            protocol: row.origin_proto,
        },
        rules: rules
            .into_iter()
            .map(|r| CacheRuleConfig {
                path_pattern: r.path_pattern,
                ttl_seconds: r.ttl_seconds as u64,
                priority: r.priority,
            })
            .collect(),
        version: format!("{}-r{}", row.id, rule_count),
    }))
}
