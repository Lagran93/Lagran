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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_header: Option<String>,
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
    #[serde(default)]
    pub ignore_key_headers: Option<String>,
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
    pub ssti: bool,
    pub nosql: bool,
    pub ldap: bool,
    pub java: bool,
    pub webshell: bool,
    pub protocol: bool,
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
    #[serde(default)]
    pub expr: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RulepackOut {
    pub version: String,
    pub payload: String,
    pub signature: String,
    pub checksum: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct WafConfigOut {
    pub enabled: bool,
    pub mode: String,
    pub managed: WafManagedOut,
    #[serde(default)]
    pub managed_rulesets: Vec<String>,
    #[serde(default)]
    pub rulepack_version: String,
    #[serde(default)]
    pub rulepack: Option<RulepackOut>,
    pub rules: Vec<WafRuleOut>,
    pub ip_allow: Vec<String>,
    pub ip_deny: Vec<String>,
    /// ISO 3166-1 alpha-2 codes; a match clears the Geo/ASN gate only.
    #[serde(default)]
    pub country_allow: Vec<String>,
    #[serde(default)]
    pub country_deny: Vec<String>,
    /// Autonomous system numbers blocked or allowed by the Geo/ASN layer.
    #[serde(default)]
    pub asn_allow: Vec<u32>,
    #[serde(default)]
    pub asn_deny: Vec<u32>,
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
    pub cache_key_ignore_headers: String,
    pub cors_origins: String,
    pub hotlink_allow_referers: String,
    pub origin_timeout_ms: u32,
    pub custom_headers: String,
    pub shield_url: String,
    pub signed_url_enabled: bool,
    pub signed_url_mode: String,
    pub signed_url_paths: String,
    pub signed_url_secret: String,
    pub signed_url_previous_secret: String,
    pub signed_url_ttl_secs: u32,
    pub origin_auth_header: String,
    pub origin_auth_value: String,
    pub hotlink_signature_enabled: bool,
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
            ignore_key_headers: r.ignore_key_headers,
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
        sni: None,
        host_header: None,
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
                sni: o.sni.clone(),
                host_header: o.host_header.clone(),
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
            sni: None,
            host_header: None,
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
        sni: None,
        host_header: None,
    })
}

fn waf_config_from(
    domain: &str,
    settings: repository::WafSettingsRow,
    rules: Vec<repository::WafRuleRow>,
    ips: Vec<repository::WafIpRow>,
    geo: Vec<repository::WafGeoRow>,
    rulepacks: &[crate::waf_rulepack::RulepackRow],
) -> WafConfigOut {
    let managed_rulesets = crate::waf_rulesets::parse_csv(&settings.managed_rulesets);
    let active = rulepacks.iter().find(|p| p.slot == "active");
    let previous = rulepacks.iter().find(|p| p.slot == "previous");
    let pinned = if settings.waf_rulepack_version.trim().is_empty() {
        None
    } else {
        rulepacks
            .iter()
            .find(|p| p.version == settings.waf_rulepack_version.trim())
    };
    let selected = pinned.or_else(|| {
        if settings.waf_gray_percent > 0 {
            match (active, previous) {
                (Some(a), Some(p)) => {
                    if crate::waf_rulepack::gray_bucket(domain, &a.version)
                        < settings.waf_gray_percent as u32
                    {
                        Some(a)
                    } else {
                        Some(p)
                    }
                }
                _ => active,
            }
        } else {
            active
        }
    });
    let ruleset_categories = selected
        .map(|p| p.categories_for(&managed_rulesets))
        .unwrap_or_else(|| {
            crate::waf_rulesets::Categories::from_csv(&settings.managed_rulesets)
        });
    let rulepack_out = selected.map(|p| RulepackOut {
        version: p.version.clone(),
        payload: p.payload.clone(),
        signature: p.signature.clone(),
        checksum: p.checksum.clone(),
    });
    let rulepack_version = selected.map(|p| p.version.clone()).unwrap_or_default();
    // De-duplicate on the way out. The unique index prevents new duplicates, but
    // rows written before it existed may still contain them, and the edge matches
    // these lists linearly on every request.
    let mut ip_allow = Vec::new();
    let mut ip_deny = Vec::new();
    let mut seen_allow = std::collections::HashSet::new();
    let mut seen_deny = std::collections::HashSet::new();
    for ip in ips {
        if !ip.enabled {
            continue;
        }
        if ip.kind == "allow" {
            if seen_allow.insert(ip.ip.clone()) {
                ip_allow.push(ip.ip);
            }
        } else if seen_deny.insert(ip.ip.clone()) {
            ip_deny.push(ip.ip);
        }
    }
    let mut country_allow = Vec::new();
    let mut country_deny = Vec::new();
    let mut asn_allow = Vec::new();
    let mut asn_deny = Vec::new();
    for row in geo {
        if !row.enabled {
            continue;
        }
        match row.kind.as_str() {
            "country_allow" => country_allow.push(row.value),
            "country_deny" => country_deny.push(row.value),
            "asn_allow" => {
                if let Ok(asn) = row.value.parse::<u32>() {
                    asn_allow.push(asn);
                }
            }
            "asn_deny" => {
                if let Ok(asn) = row.value.parse::<u32>() {
                    asn_deny.push(asn);
                }
            }
            _ => {}
        }
    }
    WafConfigOut {
        enabled: settings.enabled,
        mode: settings.mode,
        managed: WafManagedOut {
            sqli: settings.sqli || ruleset_categories.sqli,
            xss: settings.xss || ruleset_categories.xss,
            traversal: settings.traversal || ruleset_categories.traversal,
            scanners: settings.scanners || ruleset_categories.scanners,
            rce: settings.rce || ruleset_categories.rce,
            ssrf: settings.ssrf || ruleset_categories.ssrf,
            xxe: settings.xxe || ruleset_categories.xxe,
            log4shell: settings.log4shell || ruleset_categories.log4shell,
            crlf: settings.crlf || ruleset_categories.crlf,
            ssti: settings.ssti || ruleset_categories.ssti,
            nosql: settings.nosql || ruleset_categories.nosql,
            ldap: settings.ldap || ruleset_categories.ldap,
            java: settings.java || ruleset_categories.java,
            webshell: settings.webshell || ruleset_categories.webshell,
            protocol: settings.protocol || ruleset_categories.protocol,
        },
        managed_rulesets,
        rulepack_version,
        rulepack: rulepack_out,
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
                expr: r.expr,
            })
            .collect(),
        ip_allow,
        ip_deny,
        country_allow,
        country_deny,
        asn_allow,
        asn_deny,
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

    // The version hash covers the entire document, not a hand-maintained list of
    // fields. The previous per-field hashing silently omitted
    // `waf.managed_rulesets`, so changing only the managed ruleset selection
    // left both the HTTP ETag and the Edge's version guard unchanged: edges
    // answered `304 Not Modified` and the new ruleset never took effect.
    //
    // The document is built first and hashed with `version` empty, so adding a
    // field to `DomainConfigResponse` can never again escape the hash.
    let mut out = DomainConfigResponse {
        domain: row.name.clone(),
        origin,
        rules,
        status: row.status.clone(),
        ssl_enabled: row.ssl_enabled,
        rate_limit_rps: rps,
        rate_limit_burst: burst,
        ignore_query_string: row.ignore_query_string,
        cache_key_ignore_headers: row.cache_key_ignore_headers.clone(),
        cors_origins: row.cors_origins.clone(),
        hotlink_allow_referers: row.hotlink_allow_referers.clone(),
        origin_timeout_ms: timeout,
        custom_headers: row.custom_headers.clone(),
        shield_url: row.shield_url.clone(),
        signed_url_enabled: row.signed_url_enabled,
        signed_url_mode: if row.signed_url_mode.is_empty() {
            if row.signed_url_enabled { "all".into() } else { "off".into() }
        } else {
            row.signed_url_mode.clone()
        },
        signed_url_paths: row.signed_url_paths.clone(),
        signed_url_secret: row.signed_url_secret.clone(),
        signed_url_previous_secret: row.signed_url_previous_secret.clone(),
        signed_url_ttl_secs: row.signed_url_ttl_secs.max(0) as u32,
        origin_auth_header: row.origin_auth_header.clone(),
        origin_auth_value: row.origin_auth_value.clone(),
        hotlink_signature_enabled: row.hotlink_signature_enabled,
        backup_origin: backup,
        origins,
        waf,
        cc,
        version: String::new(),
    };
    out.version = String::new();
    let digest = config_digest(&out);
    out.version = format!("{}-{:x}", row.id, digest);
    out
}

/// FNV-1a over the serialized configuration document.
///
/// A stable hash is required here: the version string is persisted in config
/// snapshots and compared across control-plane restarts and replicas, so
/// `std::collections::hash_map::DefaultHasher` (whose algorithm is explicitly
/// unspecified and has changed between releases) must not be used.
fn config_digest(config: &DomainConfigResponse) -> u64 {
    let bytes = serde_json::to_vec(config).unwrap_or_default();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Build one domain's edge config snapshot. Used by version history/releases.
pub async fn snapshot_domain(
    pool: &PgPool,
    name: &str,
) -> sqlx::Result<Option<DomainConfigResponse>> {
    let Some(row) = repository::get_domain_full_by_name(pool, name).await? else {
        return Ok(None);
    };
    // Every query on the config path must propagate its error. Coercing a
    // failure into an empty collection turns "the database blipped" into "this
    // domain has no WAF rules and no Geo allow-list", which silently disables
    // protection (or, for a Geo allow-list, blocks all traffic). A 5xx makes the
    // edge keep its current config instead.
    let rules = repository::list_rules_for_domain(pool, row.id).await?;
    let rulepacks = crate::waf_rulepack::list(pool).await?;
    let waf = match repository::get_waf_settings(pool, row.id).await? {
        Some(settings) => {
            let waf_rules = repository::list_waf_rules(pool, row.id).await?;
            let waf_ips = repository::list_waf_ips(pool, row.id).await?;
            let waf_geo = repository::list_waf_geo(pool, row.id).await?;
            Some(waf_config_from(
                &row.name,
                settings,
                waf_rules,
                waf_ips,
                waf_geo,
                &rulepacks,
            ))
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
    // Same rule as `snapshot_domain`: a failed query must not degrade into an
    // empty rule set, or the edge would serve this domain with protection off.
    let rules = repository::list_rules_for_domain(&state.pool, row.id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, domain = %row.name, "load cache rules for config");
            db_error()
        })?;
    let rulepacks = crate::waf_rulepack::list(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "load rulepacks for config");
            db_error()
        })?;
    let waf = match repository::get_waf_settings(&state.pool, row.id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, domain = %row.name, "load waf settings for config");
            db_error()
        })?
    {
        Some(settings) => {
            let waf_rules = repository::list_waf_rules(&state.pool, row.id)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, domain = %row.name, "load waf rules for config");
                    db_error()
                })?;
            let waf_ips = repository::list_waf_ips(&state.pool, row.id)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, domain = %row.name, "load waf ips for config");
                    db_error()
                })?;
            let waf_geo = repository::list_waf_geo(&state.pool, row.id)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, domain = %row.name, "load waf geo for config");
                    db_error()
                })?;
            Some(waf_config_from(
                &row.name,
                settings,
                waf_rules,
                waf_ips,
                waf_geo,
                &rulepacks,
            ))
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
        return Ok(cached_response(&headers, &cached.etag, cached.body));
    }
    let redis_key = format!("lagran:cfg:{cache_key}");
    if let Some(redis) = state.redis.as_deref() {
        if let Some(shared) = redis
            .get_json::<crate::service::config_cache::SharedConfig>(&redis_key)
            .await
        {
            let body = Bytes::from(shared.body.into_bytes());
            state
                .config_cache
                .put(cache_key.clone(), shared.etag.clone(), body.clone());
            return Ok(cached_response(&headers, &shared.etag, body));
        }
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
    let waf_geo = repository::list_waf_geo_all(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "list waf geo rules for config");
            db_error()
        })?;

    let rulepacks = crate::waf_rulepack::list(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "list rulepacks for config");
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
    let mut waf_geo_by: HashMap<Uuid, Vec<repository::WafGeoRow>> = HashMap::new();
    for rule in waf_geo {
        waf_geo_by.entry(rule.domain_id).or_default().push(rule);
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
                &row.name,
                settings,
                waf_rules_by.remove(&row.id).unwrap_or_default(),
                waf_ips_by.remove(&row.id).unwrap_or_default(),
                waf_geo_by.remove(&row.id).unwrap_or_default(),
                &rulepacks,
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
    if let Some(redis) = state.redis.as_deref() {
        if let Ok(text) = std::str::from_utf8(&body) {
            let shared = crate::service::config_cache::SharedConfig {
                etag: etag.clone(),
                body: text.to_string(),
            };
            let _ = redis
                .set_json(
                    &format!("lagran:cfg:{cache_key}"),
                    &shared,
                    state.config.config_cache_ttl_secs,
                )
                .await;
        }
    }
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

fn cached_response(headers: &HeaderMap, etag: &str, body: Bytes) -> Response {
    if if_none_match(headers, etag) {
        return not_modified(etag);
    }
    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Ok(value) = HeaderValue::from_str(etag) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    response
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

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> repository::WafSettingsRow {
        repository::WafSettingsRow {
            domain_id: uuid::Uuid::nil(),
            enabled: true,
            mode: "block".into(),
            sqli: true,
            xss: true,
            traversal: true,
            scanners: true,
            rce: true,
            ssrf: true,
            xxe: true,
            log4shell: true,
            crlf: true,
            ssti: true,
            nosql: true,
            ldap: true,
            java: true,
            webshell: true,
            protocol: true,
            challenge_difficulty: 4,
            challenge_ttl_secs: 1800,
            security_level: "off".into(),
            managed_rulesets: String::new(),
            waf_rulepack_version: String::new(),
            waf_gray_percent: 0,
        }
    }

    fn geo(kind: &str, value: &str) -> repository::WafGeoRow {
        repository::WafGeoRow {
            id: uuid::Uuid::nil(),
            domain_id: uuid::Uuid::nil(),
            kind: kind.into(),
            value: value.into(),
            note: String::new(),
            enabled: true,
            created_at: chrono::Utc::now(),
        }
    }

    fn disabled_geo(kind: &str, value: &str) -> repository::WafGeoRow {
        let mut row = geo(kind, value);
        row.enabled = false;
        row
    }

    fn ip(kind: &str, value: &str, enabled: bool) -> repository::WafIpRow {
        repository::WafIpRow {
            id: uuid::Uuid::nil(),
            domain_id: uuid::Uuid::nil(),
            kind: kind.into(),
            ip: value.into(),
            note: String::new(),
            enabled,
            created_at: chrono::Utc::now(),
        }
    }

    fn domain() -> repository::DomainFullRow {
        repository::DomainFullRow {
            id: Uuid::nil(),
            name: "example.com".into(),
            origin_host: "127.0.0.1".into(),
            origin_port: 80,
            origin_proto: "http".into(),
            ssl_enabled: false,
            status: "active".into(),
            rate_limit_rps: 0,
            rate_limit_burst: 0,
            ignore_query_string: false,
            cache_key_ignore_headers: String::new(),
            cors_origins: String::new(),
            hotlink_allow_referers: String::new(),
            origin_timeout_ms: 10_000,
            custom_headers: String::new(),
            origins: sqlx::types::Json(Vec::new()),
            backup_origin_host: String::new(),
            backup_origin_port: 80,
            backup_origin_proto: "http".into(),
            cc_enabled: false,
            cc_rps: 0,
            cc_burst: 0,
            cc_ban_after: 0,
            cc_ban_seconds: 0,
            cc_mode: "block".into(),
            cc_allow_ips: String::new(),
            shield_url: String::new(),
            signed_url_enabled: false,
            signed_url_mode: "off".into(),
            signed_url_paths: String::new(),
            signed_url_secret: String::new(),
            signed_url_previous_secret: String::new(),
            signed_url_ttl_secs: 3600,
            origin_auth_header: String::new(),
            origin_auth_value: String::new(),
            hotlink_signature_enabled: false,
            published_version_id: None,
        }
    }

    fn config_with_geo(entries: Vec<repository::WafGeoRow>) -> DomainConfigResponse {
        let waf = waf_config_from(
            "example.com",
            settings(),
            Vec::new(),
            Vec::new(),
            entries,
            &[],
        );
        build(&domain(), Vec::new(), Some(waf))
    }

    #[test]
    fn geo_mutations_change_versions_and_invalidate_conditional_requests() {
        let empty = config_with_geo(Vec::new());
        for (kind, value) in [
            ("country_allow", "CN"),
            ("country_deny", "CN"),
            ("asn_allow", "13335"),
            ("asn_deny", "13335"),
        ] {
            let added = config_with_geo(vec![geo(kind, value)]);
            assert_ne!(empty.version, added.version, "adding {kind}");
            let removed = config_with_geo(Vec::new());
            assert_ne!(added.version, removed.version, "deleting {kind}");
            assert_eq!(empty.version, removed.version);
            assert_eq!(
                added.version,
                config_with_geo(vec![geo(kind, value)]).version
            );

            // The aggregate ETag is derived from domain versions, as in
            // get_all_config. Exercise the conditional response path as well.
            let etag = |cfg: &DomainConfigResponse| {
                let parts = [format!("{}:{:?}", cfg.version, None::<Uuid>)];
                let mut h = DefaultHasher::new();
                parts.join("|").hash(&mut h);
                None::<String>.hash(&mut h);
                format!("\"{:x}\"", h.finish())
            };
            for (before, after) in [(&empty, &added), (&added, &removed)] {
                let mut headers = HeaderMap::new();
                headers.insert(header::IF_NONE_MATCH, etag(before).parse().unwrap());
                let current_etag = etag(after);
                let response = cached_response(&headers, &current_etag, Bytes::new());
                assert_eq!(response.status(), StatusCode::OK, "changed {kind}");
                headers.insert(header::IF_NONE_MATCH, current_etag.parse().unwrap());
                assert_eq!(
                    cached_response(&headers, &current_etag, Bytes::new()).status(),
                    StatusCode::NOT_MODIFIED
                );
            }
        }
    }

    #[test]
    fn moving_geo_entries_between_allow_and_deny_changes_version() {
        for (allow, deny, value) in [
            ("country_allow", "country_deny", "CN"),
            ("asn_allow", "asn_deny", "13335"),
        ] {
            assert_ne!(
                config_with_geo(vec![geo(allow, value)]).version,
                config_with_geo(vec![geo(deny, value)]).version,
            );
        }
    }

    #[test]
    fn geo_rules_are_split_into_config_arrays() {
        let out = waf_config_from(
            "example.com",
            settings(),
            Vec::new(),
            Vec::new(),
            vec![
                geo("country_allow", "CN"),
                geo("country_deny", "KP"),
                geo("asn_allow", "13335"),
                geo("asn_deny", "4134"),
                // Malformed rows must be dropped instead of reaching the Edge.
                geo("asn_deny", "not-a-number"),
                geo("bogus_kind", "US"),
            ],
            &[],
        );

        assert_eq!(out.country_allow, vec!["CN".to_string()]);
        assert_eq!(out.country_deny, vec!["KP".to_string()]);
        assert_eq!(out.asn_allow, vec![13335]);
        assert_eq!(out.asn_deny, vec![4134]);
        assert!(out.ip_allow.is_empty() && out.ip_deny.is_empty());

        // The Edge agent deserializes this payload, so the wire names matter.
        let json = serde_json::to_value(&out).expect("serialize waf config");
        assert_eq!(json["country_allow"][0], "CN");
        assert_eq!(json["country_deny"][0], "KP");
        assert_eq!(json["asn_allow"][0], 13335);
        assert_eq!(json["asn_deny"][0], 4134);
        assert!(json["ip_allow"].as_array().is_some_and(|a| a.is_empty()));
    }

    #[test]
    fn disabled_geo_entries_are_kept_out_of_edge_config() {
        let out = config_with_geo(vec![
            geo("country_allow", "CN"),
            disabled_geo("country_deny", "KP"),
            disabled_geo("asn_deny", "4134"),
        ]);

        let waf = out.waf.expect("waf config");
        assert_eq!(waf.country_allow, vec!["CN".to_string()]);
        assert!(waf.country_deny.is_empty());
        assert!(waf.asn_deny.is_empty());
    }

    /// Historical duplicate rows must not be shipped to the edge even after the
    /// unique index is in place, because the index does not retroactively prove
    /// the config generator is duplicate-safe.
    #[test]
    fn duplicate_ip_entries_are_collapsed_in_config() {
        use uuid::Uuid;
        let row = |ip: &str| repository::WafIpRow {
            id: Uuid::new_v4(),
            domain_id: Uuid::nil(),
            kind: "deny".into(),
            ip: ip.into(),
            note: String::new(),
            enabled: true,
            created_at: chrono::Utc::now(),
        };
        let out = waf_config_from(
            "example.com",
            settings(),
            Vec::new(),
            vec![
                row("198.51.100.10"),
                row("198.51.100.10"),
                row("198.51.100.11"),
                row("198.51.100.10"),
            ],
            Vec::new(),
            &[],
        );
        assert_eq!(
            out.ip_deny,
            vec!["198.51.100.10".to_string(), "198.51.100.11".to_string()]
        );
    }

    #[test]
    fn disabled_ip_entries_are_kept_out_of_edge_config() {
        let out = waf_config_from(
            "example.com",
            settings(),
            Vec::new(),
            vec![ip("allow", "203.0.113.10", true), ip("deny", "198.51.100.10", false)],
            Vec::new(),
            &[],
        );

        assert_eq!(out.ip_allow, vec!["203.0.113.10".to_string()]);
        assert!(out.ip_deny.is_empty());
    }

    /// Every field of the WAF document must participate in the version, or an
    /// Edge holding the old ETag answers 304 and the change never lands.
    ///
    /// This used to fail for `managed_rulesets`: the hash listed fields by hand
    /// and that one was missing.
    #[test]
    fn version_changes_when_managed_rulesets_change() {
        let base = waf_config_from(
            "example.com",
            settings(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            &[],
        );
        let mut selected = settings();
        // Use catalog ids that actually exist: `parse_csv` drops unknown ones,
        // which would make this test pass for the wrong reason.
        selected.managed_rulesets = "owasp-core, injection-extended".into();
        let with_rulesets = waf_config_from(
            "example.com",
            selected,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            &[],
        );

        assert_eq!(base.managed_rulesets, Vec::<String>::new());
        assert_eq!(
            with_rulesets.managed_rulesets,
            vec!["owasp-core".to_string(), "injection-extended".to_string()]
        );

        let a = build(&domain(), Vec::new(), Some(base));
        let b = build(&domain(), Vec::new(), Some(with_rulesets));
        assert_ne!(
            a.version, b.version,
            "changing managed_rulesets must change the config version"
        );
    }

    /// Guards the property rather than a specific field: mutate the serialized
    /// document in a few different places and require a different digest each
    /// time. A hand-maintained field list cannot satisfy this.
    #[test]
    fn digest_reflects_the_whole_document() {
        let base = build(
            &domain(),
            Vec::new(),
            Some(waf_config_from(
                "example.com",
                settings(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                &[],
            )),
        );
        let baseline = config_digest(&base);

        let mut changed = base.clone();
        changed.hotlink_signature_enabled = !changed.hotlink_signature_enabled;
        assert_ne!(config_digest(&changed), baseline, "top-level field");

        let mut changed = base.clone();
        if let Some(waf) = changed.waf.as_mut() {
            waf.security_level = "high".into();
        }
        assert_ne!(config_digest(&changed), baseline, "nested waf field");

        let mut changed = base.clone();
        if let Some(waf) = changed.waf.as_mut() {
            waf.managed.webshell = !waf.managed.webshell;
        }
        assert_ne!(config_digest(&changed), baseline, "nested managed flag");

        // `version` is part of the document, so it participates in the digest.
        // The builder always resets it before hashing, which is what keeps the
        // digest stable across rebuilds.
        let mut same = base.clone();
        same.version = "different".into();
        assert_ne!(config_digest(&same), baseline);
    }

    #[test]
    fn version_is_stable_across_rebuilds() {
        let make = || {
            build(
                &domain(),
                Vec::new(),
                Some(waf_config_from(
                    "example.com",
                    settings(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    &[],
                )),
            )
        };
        assert_eq!(make().version, make().version);
    }

    #[test]
    fn empty_geo_config_keeps_backward_compatible_defaults() {
        let out = waf_config_from(
            "example.com",
            settings(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            &[],
        );
        assert!(out.country_allow.is_empty());
        assert!(out.country_deny.is_empty());
        assert!(out.asn_allow.is_empty());
        assert!(out.asn_deny.is_empty());

        // A payload written by an older Control (no geo keys) must still
        // deserialize, because Edge agents and release snapshots are rolled
        // forward independently.
        let mut legacy = serde_json::to_value(&out).expect("serialize");
        for key in ["country_allow", "country_deny", "asn_allow", "asn_deny"] {
            legacy.as_object_mut().expect("object").remove(key);
        }
        let parsed: WafConfigOut = serde_json::from_value(legacy).expect("legacy payload");
        assert!(parsed.country_allow.is_empty());
        assert!(parsed.country_deny.is_empty());
        assert!(parsed.asn_allow.is_empty());
        assert!(parsed.asn_deny.is_empty());
    }
}
