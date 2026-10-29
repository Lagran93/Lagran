//! Config delivery for edge nodes (agent token required).
//!
//! The bulk endpoint is called by every edge every 15s, so it builds the whole
//! document from three queries (domains, rules, nothing else) instead of the
//! previous per-domain N+1 lookups.

use crate::middleware::agent_auth::AgentAuth;
use crate::repository;
use crate::state::AppState;
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone)]
pub struct OriginConfig {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub weight: u32,
    pub priority: i32,
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CacheRuleConfig {
    pub path_pattern: String,
    pub match_type: String,
    pub ttl_seconds: u64,
    pub priority: i32,
    pub action: String,
    pub swr_seconds: u64,
    pub enabled: bool,
    pub match_methods: String,
    pub match_query: String,
    pub browser_ttl_seconds: u64,
    pub ignore_query: Option<bool>,
    pub ignore_cookie: bool,
    pub match_content_type: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct WafManagedOut {
    pub sqli: bool,
    pub xss: bool,
    pub traversal: bool,
    pub scanners: bool,
    pub rce: bool,
    pub ssrf: bool,
    pub xxe: bool,
    pub log4shell: bool,
    pub crlf: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct WafRuleOut {
    pub name: String,
    pub field: String,
    pub operator: String,
    pub value: String,
    pub action: String,
    pub priority: i32,
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct WafConfigOut {
    pub enabled: bool,
    pub mode: String,
    pub managed: WafManagedOut,
    pub rules: Vec<WafRuleOut>,
    pub ip_allow: Vec<String>,
    pub ip_deny: Vec<String>,
    pub challenge_difficulty: u8,
    pub challenge_ttl_secs: u64,
    pub security_level: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CcConfigOut {
    pub enabled: bool,
    pub rps: u32,
    pub burst: u32,
    pub ban_after: u32,
    pub ban_seconds: u64,
    pub mode: String,
    pub allow_ips: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DomainConfigResponse {
    pub domain: String,
    pub origin: OriginConfig,
    pub rules: Vec<CacheRuleConfig>,
    pub status: String,
    pub ssl_enabled: bool,
    pub rate_limit_rps: u32,
    pub rate_limit_burst: u32,
    pub ignore_query_string: bool,
    pub cors_origins: String,
    pub hotlink_allow_referers: String,
    pub origin_timeout_ms: u32,
    pub custom_headers: String,
    pub shield_url: String,
    pub backup_origin: Option<OriginConfig>,
    pub origins: Vec<OriginConfig>,
    pub waf: Option<WafConfigOut>,
    pub cc: CcConfigOut,
    pub version: String,
}

#[derive(Serialize)]
pub struct AllDomainsConfigResponse {
    pub domains: Vec<DomainConfigResponse>,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_id: Option<String>,
}

#[derive(Serialize)]
pub struct ErrorBody {
    pub error: String,
}

fn rule_configs(rows: Vec<repository::CacheRuleRow>) -> Vec<CacheRuleConfig> {
    rows.into_iter()
        .map(|r| CacheRuleConfig {
            path_pattern: r.path_pattern,
            match_type: r.match_type,
            ttl_seconds: r.ttl_seconds.max(0) as u64,
            priority: r.priority,
            action: r.action,
            swr_seconds: r.swr_seconds.max(0) as u64,
            enabled: r.enabled,
            match_methods: r.match_methods,
            match_query: r.match_query,
            browser_ttl_seconds: r.browser_ttl_seconds.max(0) as u64,
            ignore_query: r.ignore_query,
            ignore_cookie: r.ignore_cookie,
            match_content_type: r.match_content_type,
        })
        .collect()
}

fn origin_config(row: &repository::DomainFullRow) -> OriginConfig {
    OriginConfig {
        host: row.origin_host.clone(),
        port: row.origin_port as u16,
        protocol: row.origin_proto.clone(),
        weight: 100,
        priority: 0,
        enabled: true,
    }
}

fn origin_pool(row: &repository::DomainFullRow) -> Vec<OriginConfig> {
    if !row.origins.0.is_empty() {
        return row
            .origins
            .0
            .iter()
            .map(|o| OriginConfig {
                host: o.host.clone(),
                port: o.port,
                protocol: o.proto.clone(),
                weight: o.weight,
                priority: o.priority,
                enabled: o.enabled,
            })
            .collect();
    }
    let mut out = vec![origin_config(row)];
    if !row.backup_origin_host.is_empty() && row.backup_origin_port > 0 {
        out.push(OriginConfig {
            host: row.backup_origin_host.clone(),
            port: row.backup_origin_port as u16,
            protocol: row.backup_origin_proto.clone(),
            weight: 100,
            priority: 1,
            enabled: true,
        });
    }
    out
}

fn backup_config(row: &repository::DomainFullRow) -> Option<OriginConfig> {
    if row.backup_origin_host.is_empty() || row.backup_origin_port <= 0 {
        return None;
    }
    Some(OriginConfig {
        host: row.backup_origin_host.clone(),
        port: row.backup_origin_port as u16,
        protocol: row.backup_origin_proto.clone(),
        weight: 100,
        priority: 1,
        enabled: true,
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
            rce: settings.rce,
            ssrf: settings.ssrf,
            xxe: settings.xxe,
            log4shell: settings.log4shell,
            crlf: settings.crlf,
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
        security_level: settings.security_level,
    }
}

pub(crate) fn build(
    row: &repository::DomainFullRow,
    rules: Vec<CacheRuleConfig>,
    waf: Option<WafConfigOut>,
) -> DomainConfigResponse {
    let origin = origin_config(row);
    let backup = backup_config(row);
    let origins = origin_pool(row);
    let timeout = if row.origin_timeout_ms <= 0 {
        10_000
    } else {
        row.origin_timeout_ms as u32
    };
    let rps = row.rate_limit_rps.max(0) as u32;
    let burst = row.rate_limit_burst.max(0) as u32;
    let cc = CcConfigOut {
        enabled: row.cc_enabled,
        rps: row.cc_rps.max(0) as u32,
        burst: row.cc_burst.max(0) as u32,
        ban_after: row.cc_ban_after.max(0) as u32,
        ban_seconds: row.cc_ban_seconds.max(0) as u64,
        mode: if row.cc_mode.is_empty() {
            "block".into()
        } else {
            row.cc_mode.clone()
        },
        allow_ips: row.cc_allow_ips.clone(),
    };

    let mut h = DefaultHasher::new();
    rps.hash(&mut h);
    burst.hash(&mut h);
    for o in &origins {
        o.host.hash(&mut h);
        o.port.hash(&mut h);
        o.protocol.hash(&mut h);
        o.weight.hash(&mut h);
        o.priority.hash(&mut h);
        o.enabled.hash(&mut h);
    }
    cc.enabled.hash(&mut h);
    cc.rps.hash(&mut h);
    cc.burst.hash(&mut h);
    cc.ban_after.hash(&mut h);
    cc.ban_seconds.hash(&mut h);
    cc.mode.hash(&mut h);
    cc.allow_ips.hash(&mut h);
    row.ignore_query_string.hash(&mut h);
    row.cors_origins.hash(&mut h);
    row.hotlink_allow_referers.hash(&mut h);
    timeout.hash(&mut h);
    row.custom_headers.hash(&mut h);
    row.shield_url.hash(&mut h);
    row.status.hash(&mut h);
    row.ssl_enabled.hash(&mut h);
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
        r.match_type.hash(&mut h);
        r.ttl_seconds.hash(&mut h);
        r.priority.hash(&mut h);
        r.action.hash(&mut h);
        r.swr_seconds.hash(&mut h);
        r.enabled.hash(&mut h);
        r.match_methods.hash(&mut h);
        r.match_query.hash(&mut h);
        r.browser_ttl_seconds.hash(&mut h);
        r.ignore_query.hash(&mut h);
        r.ignore_cookie.hash(&mut h);
        r.match_content_type.hash(&mut h);
    }
    match &waf {
        Some(w) => {
            w.enabled.hash(&mut h);
            w.mode.hash(&mut h);
            w.managed.sqli.hash(&mut h);
            w.managed.xss.hash(&mut h);
            w.managed.traversal.hash(&mut h);
            w.managed.scanners.hash(&mut h);
            w.managed.rce.hash(&mut h);
            w.managed.ssrf.hash(&mut h);
            w.managed.xxe.hash(&mut h);
            w.managed.log4shell.hash(&mut h);
            w.managed.crlf.hash(&mut h);
            w.security_level.hash(&mut h);
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
        ssl_enabled: row.ssl_enabled,
        rate_limit_rps: rps,
        rate_limit_burst: burst,
        ignore_query_string: row.ignore_query_string,
        cors_origins: row.cors_origins.clone(),
        hotlink_allow_referers: row.hotlink_allow_referers.clone(),
        origin_timeout_ms: timeout,
        custom_headers: row.custom_headers.clone(),
        shield_url: row.shield_url.clone(),
        backup_origin: backup,
        origins,
        waf,
        cc,
        version: format!("{}-{:x}", row.id, h.finish()),
    }
}

/// Build one domain's edge config snapshot. Used by version history/releases.
pub async fn snapshot_domain(
    pool: &PgPool,
    name: &str,
) -> sqlx::Result<Option<DomainConfigResponse>> {
    let Some(row) = repository::get_domain_full_by_name(pool, name).await? else {
        return Ok(None);
    };
    let rules = repository::list_rules_for_domain(pool, row.id)
        .await
        .unwrap_or_default();
    let waf = match repository::get_waf_settings(pool, row.id)
        .await
        .ok()
        .flatten()
    {
        Some(settings) => {
            let waf_rules = repository::list_waf_rules(pool, row.id)
                .await
                .unwrap_or_default();
            let waf_ips = repository::list_waf_ips(pool, row.id)
                .await
                .unwrap_or_default();
            Some(waf_config_from(settings, waf_rules, waf_ips))
        }
        None => None,
    };
    Ok(Some(build(&row, rule_configs(rules), waf)))
}

pub async fn get_domain_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    _agent: AgentAuth,
    Path(domain): Path<String>,
) -> Result<Response, (StatusCode, Json<ErrorBody>)> {
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
    let cfg = build(&row, rule_configs(rules), waf);
    let etag = format!("\"{}\"", cfg.version);
    if if_none_match(&headers, &etag) {
        return Ok(not_modified(&etag));
    }
    let mut response = Json(cfg).into_response();
    if let Ok(value) = HeaderValue::from_str(&etag) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    Ok(response)
}

pub async fn list_all_configs(
    State(state): State<AppState>,
    headers: HeaderMap,
    _agent: AgentAuth,
) -> Result<Response, (StatusCode, Json<ErrorBody>)> {
    let node_id = headers
        .get("x-lagran-node-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let active_release = if node_id.is_empty() {
        None
    } else {
        repository::active_release_for_node(&state.pool, &node_id)
            .await
            .unwrap_or(None)
    };
    // Nodes without a release share one document. Nodes pinned to the same
    // release share that release's document. This keeps the cache useful when
    // hundreds of edges poll on the same 15s interval.
    let cache_key = match active_release.as_ref() {
        Some(release) => format!("release:{}", release.id),
        None => "global".to_string(),
    };
    if let Some(cached) = state.config_cache.get(&cache_key) {
        if if_none_match(&headers, &cached.etag) {
            return Ok(not_modified(&cached.etag));
        }
        let mut response = Response::new(Body::from(cached.body));
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        if let Ok(value) = HeaderValue::from_str(&cached.etag) {
            response.headers_mut().insert(header::ETAG, value);
        }
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        return Ok(response);
    }

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

    let mut release_snapshots: HashMap<String, DomainConfigResponse> = HashMap::new();
    let mut release_id = None;
    if let Some(release) = active_release {
        if let Some(map) = release.versions.as_object() {
            for (domain, version_id) in map {
                let Some(version_id) = version_id.as_str().and_then(|v| Uuid::parse_str(v).ok())
                else {
                    continue;
                };
                if let Ok(Some(version)) = repository::get_version(&state.pool, version_id).await {
                    if let Ok(snapshot) =
                        serde_json::from_value::<DomainConfigResponse>(version.snapshot)
                    {
                        release_snapshots.insert(domain.clone(), snapshot);
                    }
                }
            }
        }
        if !release_snapshots.is_empty() {
            release_id = Some(release.id.to_string());
        }
    }
    let mut published_snapshots: HashMap<Uuid, DomainConfigResponse> = HashMap::new();

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
        let mut cfg = build(&row, rule_configs(rules), waf);
        let mut effective_version = row.published_version_id;
        if let Some(snapshot) = release_snapshots.remove(&row.name) {
            cfg = snapshot;
            effective_version = None;
        } else if let Some(version_id) = row.published_version_id {
            if let Some(snapshot) = published_snapshots.get(&version_id) {
                cfg = snapshot.clone();
            } else if let Ok(Some(version)) = repository::get_version(&state.pool, version_id).await
            {
                if let Ok(snapshot) =
                    serde_json::from_value::<DomainConfigResponse>(version.snapshot)
                {
                    published_snapshots.insert(version_id, snapshot.clone());
                    cfg = snapshot;
                }
            }
        }
        version_parts.push(format!(
            "{}:{:?}",
            cfg.version,
            effective_version.or_else(|| release_id.as_ref().map(|_| Uuid::nil()))
        ));
        domains.push(cfg);
    }

    let version = {
        let mut h = DefaultHasher::new();
        version_parts.join("|").hash(&mut h);
        release_id.hash(&mut h);
        format!("{:x}", h.finish())
    };

    let etag = format!("\"{version}\"");
    if if_none_match(&headers, &etag) {
        return Ok(not_modified(&etag));
    }
    let body = serde_json::to_vec(&AllDomainsConfigResponse {
        domains,
        version,
        release_id,
    })
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: "config serialization error".into(),
            }),
        )
    })?;
    state
        .config_cache
        .put(cache_key, etag.clone(), Bytes::from(body.clone()));
    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Ok(value) = HeaderValue::from_str(&etag) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    Ok(response)
}

fn if_none_match(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|part| {
                let part = part.trim();
                part == etag || part.strip_prefix("W/") == Some(etag)
            })
        })
}

fn not_modified(etag: &str) -> Response {
    let mut response = StatusCode::NOT_MODIFIED.into_response();
    if let Ok(value) = HeaderValue::from_str(etag) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    response
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
