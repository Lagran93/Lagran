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
    pub status: String,
    pub version: String,
}

#[derive(Serialize)]
pub struct AllDomainsConfigResponse {
    pub domains: Vec<DomainConfigResponse>,
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
        status: row.status,
        version: format!("{}-r{}", row.id, rule_count),
    }))
}

/// GET /api/v1/config — all accelerated domains for edge bulk sync
pub async fn list_all_configs(
    State(state): State<AppState>,
) -> Result<Json<AllDomainsConfigResponse>, (StatusCode, Json<ErrorBody>)> {
    let rows = repository::list_domains(&state.pool).await.map_err(|e| {
        tracing::error!(error = %e, "list domains for config");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: "database error".into(),
            }),
        )
    })?;

    let mut domains = Vec::with_capacity(rows.len());
    let mut version_parts = Vec::new();

    for row in rows {
        // only active / enabled domains
        if row.status != "active" && row.status != "enabled" && row.status != "ok" {
            // still include "active" default; seed uses status often "active"
            // include all non-disabled
            if row.status == "disabled" || row.status == "deleted" {
                continue;
            }
        }
        let rules = repository::list_rules_for_domain(&state.pool, row.id)
            .await
            .unwrap_or_default();
        let rule_count = rules.len();
        version_parts.push(format!("{}:{}", row.id, rule_count));
        domains.push(DomainConfigResponse {
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
            status: row.status,
            version: format!("{}-r{}", row.id, rule_count),
        });
    }

    let version = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        version_parts.join("|").hash(&mut h);
        format!("{:x}", h.finish())
    };

    Ok(Json(AllDomainsConfigResponse { domains, version }))
}
