//! Config delivery for edge nodes (agent token required).
//!
//! The bulk endpoint is called by every edge every 15s, so it builds the whole
//! document from three queries (domains, rules, nothing else) instead of the
//! previous per-domain N+1 lookups.

use crate::middleware::agent_auth::AgentAuth;
use crate::repository;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use uuid::Uuid;

#[derive(Serialize)]
pub struct OriginConfig {
    pub host: String,
    pub port: u16,
    pub protocol: String,
}

#[derive(Serialize, Clone)]
pub struct CacheRuleConfig {
    pub path_pattern: String,
    pub ttl_seconds: u64,
    pub priority: i32,
    pub action: String,
    pub swr_seconds: u64,
    pub enabled: bool,
    pub match_methods: String,
    pub match_query: String,
    pub browser_ttl_seconds: u64,
    pub ignore_query: Option<bool>,
}

#[derive(Serialize, Clone)]
pub struct WafManagedOut {
    pub sqli: bool,
    pub xss: bool,
    pub traversal: bool,
    pub scanners: bool,
}

#[derive(Serialize, Clone)]
pub struct WafRuleOut {
    pub name: String,
    pub field: String,
    pub operator: String,
    pub value: String,
    pub action: String,
    pub priority: i32,
    pub enabled: bool,
}

#[derive(Serialize, Clone)]
pub struct WafConfigOut {
    pub enabled: bool,
    pub mode: String,
    pub managed: WafManagedOut,
    pub rules: Vec<WafRuleOut>,
    pub ip_allow: Vec<String>,
    pub ip_deny: Vec<String>,
    pub challenge_difficulty: u8,
    pub challenge_ttl_secs: u64,
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
    pub waf: Option<WafConfigOut>,
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

fn rule_configs(rows: Vec<repository::CacheRuleRow>) -> Vec<CacheRuleConfig> {
    rows.into_iter()
        .map(|r| CacheRuleConfig {
            path_pattern: r.path_pattern,
            ttl_seconds: r.ttl_seconds.max(0) as u64,
            priority: r.priority,
            action: r.action,
            swr_seconds: r.swr_seconds.max(0) as u64,
            enabled: r.enabled,
            match_methods: r.match_methods,
            match_query: r.match_query,
            browser_ttl_seconds: r.browser_ttl_seconds.max(0) as u64,
            ignore_query: r.ignore_query,
        })
        .collect()
}

fn origin_config(row: &repository::DomainFullRow) -> OriginConfig {
    OriginConfig {
        host: row.origin_host.clone(),
        port: row.origin_port as u16,
        protocol: row.origin_proto.clone(),
    }
}

fn backup_config(row: &repository::DomainFullRow) -> Option<OriginConfig> {
    if row.backup_origin_host.is_empty() || row.backup_origin_port <= 0 {
        return None;
    }
    Some(OriginConfig {
        host: row.backup_origin_host.clone(),
        port: row.backup_origin_port as u16,
        protocol: row.backup_origin_proto.clone(),
    })
}

fn waf_config_from(
    settings: repository::WafSettingsRow,
    rules: Vec<repository::WafRuleRow>,
    ips: Vec<repository::WafIpRow>,
) -> WafConfigOut {
    let mut ip_allow = Vec::new();
    let mut ip_deny = Vec::new();
    for ip in ips {
        if ip.kind == "allow" {
            ip_allow.push(ip.ip);
        } else {
            ip_deny.push(ip.ip);
        }
    }
    WafConfigOut {
        enabled: settings.enabled,
        mode: settings.mode,
        managed: WafManagedOut {
            sqli: settings.sqli,
            xss: settings.xss,
            traversal: settings.traversal,
            scanners: settings.scanners,
        },
        rules: rules
            .into_iter()
            .map(|r| WafRuleOut {
                name: r.name,
                field: r.field,
                operator: r.operator,
                value: r.value,
                action: r.action,
                priority: r.priority,
                enabled: r.enabled,
            })
            .collect(),
        ip_allow,
        ip_deny,
        challenge_difficulty: settings.challenge_difficulty.clamp(1, 6) as u8,
        challenge_ttl_secs: settings.challenge_ttl_secs.clamp(60, 86_400) as u64,
    }
}

fn build(
    row: &repository::DomainFullRow,
    rules: Vec<CacheRuleConfig>,
    waf: Option<WafConfigOut>,
) -> DomainConfigResponse {
    let origin = origin_config(row);
    let backup = backup_config(row);
    let timeout = if row.origin_timeout_ms <= 0 {
        10_000
    } else {
        row.origin_timeout_ms as u32
    };
    let rps = row.rate_limit_rps.max(0) as u32;
    let burst = row.rate_limit_burst.max(0) as u32;

    let mut h = DefaultHasher::new();
    rps.hash(&mut h);
    burst.hash(&mut h);
    row.ignore_query_string.hash(&mut h);
    row.cors_origins.hash(&mut h);
    row.hotlink_allow_referers.hash(&mut h);
    timeout.hash(&mut h);
    row.custom_headers.hash(&mut h);
    row.status.hash(&mut h);
    origin.host.hash(&mut h);
    origin.port.hash(&mut h);
    origin.protocol.hash(&mut h);
    if let Some(ref b) = backup {
        b.host.hash(&mut h);
        b.port.hash(&mut h);
        b.protocol.hash(&mut h);
    }
    for r in &rules {
        r.path_pattern.hash(&mut h);
        r.ttl_seconds.hash(&mut h);
        r.priority.hash(&mut h);
        r.action.hash(&mut h);
        r.swr_seconds.hash(&mut h);
        r.enabled.hash(&mut h);
        r.match_methods.hash(&mut h);
        r.match_query.hash(&mut h);
        r.browser_ttl_seconds.hash(&mut h);
        r.ignore_query.hash(&mut h);
    }
    match &waf {
        Some(w) => {
            w.enabled.hash(&mut h);
            w.mode.hash(&mut h);
            w.managed.sqli.hash(&mut h);
            w.managed.xss.hash(&mut h);
            w.managed.traversal.hash(&mut h);
            w.managed.scanners.hash(&mut h);
            for r in &w.rules {
                r.name.hash(&mut h);
                r.field.hash(&mut h);
                r.operator.hash(&mut h);
                r.value.hash(&mut h);
                r.action.hash(&mut h);
                r.priority.hash(&mut h);
                r.enabled.hash(&mut h);
            }
            for ip in &w.ip_allow {
                ip.hash(&mut h);
            }
            for ip in &w.ip_deny {
                ip.hash(&mut h);
            }
            w.challenge_difficulty.hash(&mut h);
            w.challenge_ttl_secs.hash(&mut h);
        }
        None => "waf-none".hash(&mut h),
    }

    DomainConfigResponse {
        domain: row.name.clone(),
        origin,
        rules,
        status: row.status.clone(),
        rate_limit_rps: rps,
        rate_limit_burst: burst,
        ignore_query_string: row.ignore_query_string,
        cors_origins: row.cors_origins.clone(),
        hotlink_allow_referers: row.hotlink_allow_referers.clone(),
        origin_timeout_ms: timeout,
        custom_headers: row.custom_headers.clone(),
        backup_origin: backup,
        waf,
        version: format!("{}-{:x}", row.id, h.finish()),
    }
}

pub async fn get_domain_config(
    State(state): State<AppState>,
    _agent: AgentAuth,
    Path(domain): Path<String>,
) -> Result<Json<DomainConfigResponse>, (StatusCode, Json<ErrorBody>)> {
    let row = repository::get_domain_full_by_name(&state.pool, &domain)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(not_found)?;
    let rules = repository::list_rules_for_domain(&state.pool, row.id)
        .await
        .unwrap_or_default();
    let waf = match repository::get_waf_settings(&state.pool, row.id)
        .await
        .ok()
        .flatten()
    {
        Some(settings) => {
            let waf_rules = repository::list_waf_rules(&state.pool, row.id)
                .await
                .unwrap_or_default();
            let waf_ips = repository::list_waf_ips(&state.pool, row.id)
                .await
                .unwrap_or_default();
            Some(waf_config_from(settings, waf_rules, waf_ips))
        }
        None => None,
    };
    Ok(Json(build(&row, rule_configs(rules), waf)))
}

pub async fn list_all_configs(
    State(state): State<AppState>,
    _agent: AgentAuth,
) -> Result<Json<AllDomainsConfigResponse>, (StatusCode, Json<ErrorBody>)> {
    let rows = repository::list_domains_full(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "list domains for config");
            db_error()
        })?;
    let all_rules = repository::list_rules_flat(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "list rules for config");
            db_error()
        })?;

    let mut by_domain: HashMap<Uuid, Vec<repository::CacheRuleRow>> = HashMap::new();
    for r in all_rules {
        by_domain.entry(r.domain_id).or_default().push(r);
    }

    let waf_settings = repository::list_waf_settings_all(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "list waf settings for config");
            db_error()
        })?;
    let waf_rules = repository::list_waf_rules_all(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "list waf rules for config");
            db_error()
        })?;
    let waf_ips = repository::list_waf_ips_all(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "list waf ips for config");
            db_error()
        })?;

    let mut waf_settings_by: HashMap<Uuid, repository::WafSettingsRow> =
        waf_settings.into_iter().map(|s| (s.domain_id, s)).collect();
    let mut waf_rules_by: HashMap<Uuid, Vec<repository::WafRuleRow>> = HashMap::new();
    for r in waf_rules {
        waf_rules_by.entry(r.domain_id).or_default().push(r);
    }
    let mut waf_ips_by: HashMap<Uuid, Vec<repository::WafIpRow>> = HashMap::new();
    for ip in waf_ips {
        waf_ips_by.entry(ip.domain_id).or_default().push(ip);
    }

    let mut domains = Vec::with_capacity(rows.len());
    let mut version_parts = Vec::with_capacity(rows.len());
    for row in rows {
        if row.status == "disabled" || row.status == "deleted" {
            continue;
        }
        let rules = by_domain.remove(&row.id).unwrap_or_default();
        let waf = waf_settings_by.remove(&row.id).map(|settings| {
            waf_config_from(
                settings,
                waf_rules_by.remove(&row.id).unwrap_or_default(),
                waf_ips_by.remove(&row.id).unwrap_or_default(),
            )
        });
        let cfg = build(&row, rule_configs(rules), waf);
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

fn db_error() -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorBody {
            error: "database error".into(),
        }),
    )
}

fn not_found() -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorBody {
            error: "domain not found".into(),
        }),
    )
}
