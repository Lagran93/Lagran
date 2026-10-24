//! Config delivery for edge nodes

use crate::repository;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

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
    pub rate_limit_rps: u32,
    pub rate_limit_burst: u32,
    pub ignore_query_string: bool,
    pub cors_origins: String,
    pub hotlink_allow_referers: String,
    pub origin_timeout_ms: u32,
    pub custom_headers: String,
    pub backup_origin: Option<OriginConfig>,
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

fn hash_settings(
    rps: u32,
    burst: u32,
    ignore_q: bool,
    cors: &str,
    hotlink: &str,
    timeout: u32,
    headers: &str,
    backup: &Option<OriginConfig>,
    rules: &[CacheRuleConfig],
    origin: &OriginConfig,
    status: &str,
) -> u64 {
    let mut h = DefaultHasher::new();
    rps.hash(&mut h);
    burst.hash(&mut h);
    ignore_q.hash(&mut h);
    cors.hash(&mut h);
    hotlink.hash(&mut h);
    timeout.hash(&mut h);
    headers.hash(&mut h);
    status.hash(&mut h);
    origin.host.hash(&mut h);
    origin.port.hash(&mut h);
    origin.protocol.hash(&mut h);
    if let Some(b) = backup {
        b.host.hash(&mut h);
        b.port.hash(&mut h);
        b.protocol.hash(&mut h);
    }
    for r in rules {
        r.path_pattern.hash(&mut h);
        r.ttl_seconds.hash(&mut h);
        r.priority.hash(&mut h);
    }
    h.finish()
}

async fn build_domain_cfg(
    pool: &sqlx::PgPool,
    row: repository::DomainRow,
) -> DomainConfigResponse {
    let rules_raw = repository::list_rules_for_domain(pool, row.id)
        .await
        .unwrap_or_default();
    let rules: Vec<CacheRuleConfig> = rules_raw
        .into_iter()
        .map(|r| CacheRuleConfig {
            path_pattern: r.path_pattern,
            ttl_seconds: r.ttl_seconds as u64,
            priority: r.priority,
        })
        .collect();
    let settings = repository::get_domain_settings(pool, &row.name)
        .await
        .ok()
        .flatten();
    let (rps, burst, ignore_q, cors, hotlink, timeout, headers) = match settings {
        Some(s) => (
            s.rate_limit_rps.max(0) as u32,
            s.rate_limit_burst.max(0) as u32,
            s.ignore_query_string,
            s.cors_origins,
            s.hotlink_allow_referers,
            s.origin_timeout_ms.max(1000) as u32,
            s.custom_headers,
        ),
        None => (0, 0, false, String::new(), String::new(), 10000, String::new()),
    };
    let backup = repository::get_backup_origin(pool, &row.name)
        .await
        .ok()
        .flatten()
        .map(|(h, p, proto)| OriginConfig {
            host: h,
            port: p as u16,
            protocol: proto,
        });
    let origin = OriginConfig {
        host: row.origin_host,
        port: row.origin_port as u16,
        protocol: row.origin_proto,
    };
    let sh = hash_settings(
        rps,
        burst,
        ignore_q,
        &cors,
        &hotlink,
        timeout,
        &headers,
        &backup,
        &rules,
        &origin,
        &row.status,
    );
    DomainConfigResponse {
        domain: row.name,
        origin,
        rules,
        status: row.status,
        rate_limit_rps: rps,
        rate_limit_burst: burst,
        ignore_query_string: ignore_q,
        cors_origins: cors,
        hotlink_allow_referers: hotlink,
        origin_timeout_ms: timeout,
        custom_headers: headers,
        backup_origin: backup,
        version: format!("{}-{:x}", row.id, sh),
    }
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
    Ok(Json(build_domain_cfg(&state.pool, row).await))
}

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

    let mut domains = Vec::new();
    let mut version_parts = Vec::new();
    for row in rows {
        if row.status == "disabled" || row.status == "deleted" {
            continue;
        }
        let cfg = build_domain_cfg(&state.pool, row).await;
        // Aggregate version includes full per-domain content hash
        version_parts.push(cfg.version.clone());
        domains.push(cfg);
    }

    let version = {
        let mut h = DefaultHasher::new();
        version_parts.join("|").hash(&mut h);
        format!("{:x}", h.finish())
    };

    Ok(Json(AllDomainsConfigResponse { domains, version }))
}
