//! Cross-node CC bans.
//!
//! Edges POST newly created local bans here and poll GET /cc/bans with their
//! node token. The control plane is the only shared state, so no Redis is
//! required. Rows expire by `expires_at`; polling edges also drop them.

use crate::middleware::agent_auth::AgentAuth;
use crate::middleware::authz::Actor;
use crate::repository;
use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Serialize)]
pub struct BanDto {
    pub domain: String,
    pub ip: String,
    pub reason: String,
    pub source: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
    pub revoked_by: String,
    pub remaining_secs: i64,
}

impl From<repository::CcBanRow> for BanDto {
    fn from(r: repository::CcBanRow) -> Self {
        let now = chrono::Utc::now();
        let status = if r.revoked_at.is_some() {
            "revoked"
        } else if r.expires_at > now {
            "active"
        } else {
            "expired"
        };
        let remaining = if status == "active" {
            (r.expires_at - now).num_seconds().max(1)
        } else {
            0
        };
        Self {
            domain: r.domain,
            ip: r.ip,
            reason: r.reason,
            source: r.source,
            status: status.to_string(),
            created_at: r.created_at.to_rfc3339(),
            updated_at: r.updated_at.to_rfc3339(),
            expires_at: r.expires_at.to_rfc3339(),
            revoked_at: r.revoked_at.map(|t| t.to_rfc3339()),
            revoked_by: r.revoked_by,
            remaining_secs: remaining,
        }
    }
}

#[derive(Serialize)]
pub struct BanListDto {
    pub bans: Vec<BanDto>,
}

#[derive(Deserialize)]
pub struct BansQuery {
    pub domain: Option<String>,
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    pub domain: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Deserialize)]
pub struct ReportBanRequest {
    pub domain: String,
    pub ip: String,
    /// Ban duration in seconds.
    pub seconds: u64,
    #[serde(default)]
    pub reason: String,
}

fn bad_request(msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": msg })),
    )
}

fn normalize_domain(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// GET /api/v1/cc/bans — edge poll (node token).
pub async fn list(
    State(state): State<AppState>,
    _agent: AgentAuth,
    Query(q): Query<BansQuery>,
) -> Result<Json<BanListDto>, (StatusCode, Json<serde_json::Value>)> {
    let domain = q.domain.as_deref().map(normalize_domain);
    let rows = repository::list_active_cc_bans(&state.pool, domain.as_deref())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "list cc bans");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "database error" })),
            )
        })?;
    Ok(Json(BanListDto {
        bans: rows.into_iter().map(BanDto::from).collect(),
    }))
}

/// POST /api/v1/cc/bans — edge reports a newly auto-banned IP.
pub async fn report(
    State(state): State<AppState>,
    agent: AgentAuth,
    Json(req): Json<ReportBanRequest>,
) -> Result<(StatusCode, Json<BanDto>), (StatusCode, Json<serde_json::Value>)> {
    let domain = normalize_domain(&req.domain);
    if domain.is_empty() {
        return Err(bad_request("domain is required"));
    }
    if repository::get_domain_by_name(&state.pool, &domain)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "database error" })),
            )
        })?
        .is_none()
    {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "domain not found" })),
        ));
    }
    let ip: IpAddr = req
        .ip
        .trim()
        .parse()
        .map_err(|_| bad_request("invalid ip"))?;
    let seconds = req.seconds.clamp(1, 86_400) as i64;
    let reason = if req.reason.trim().is_empty() {
        "cc-auto-ban".to_string()
    } else {
        req.reason.trim().chars().take(200).collect()
    };
    let row = repository::upsert_cc_ban(
        &state.pool,
        &domain,
        &ip.to_string(),
        seconds,
        &reason,
        &agent.node_name,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "upsert cc ban");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "database error" })),
        )
    })?;
    tracing::info!(
        %domain, %ip, source = %agent.node_name, seconds,
        "shared CC ban upserted"
    );
    Ok((StatusCode::CREATED, Json(BanDto::from(row))))
}

/// GET /api/v1/cc/bans/all — console/admin list.
pub async fn list_admin(
    State(state): State<AppState>,
    actor: Actor,
    Query(q): Query<BansQuery>,
) -> Result<Json<BanListDto>, (StatusCode, Json<serde_json::Value>)> {
    if !actor.is_admin {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "forbidden" })),
        ));
    }
    let domain = q.domain.as_deref().map(normalize_domain);
    let rows = repository::list_active_cc_bans(&state.pool, domain.as_deref())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "list cc bans");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "database error" })),
            )
        })?;
    Ok(Json(BanListDto {
        bans: rows.into_iter().map(BanDto::from).collect(),
    }))
}

/// GET /api/v1/cc/bans/history — admin history including expired/revoked rows.
pub async fn list_history(
    State(state): State<AppState>,
    actor: Actor,
    Query(q): Query<HistoryQuery>,
) -> Result<Json<BanListDto>, (StatusCode, Json<serde_json::Value>)> {
    let domain = q.domain.as_deref().map(normalize_domain);
    // Admins see the full history. Regular users see only domains they can read.
    let visible_domains = if actor.is_admin {
        None
    } else {
        let visible = actor.visible_domain_ids(&state).await.unwrap_or_default();
        let visible: std::collections::HashSet<_> = visible.into_iter().collect();
        Some(
            repository::domain_names_by_ids(
                &state.pool,
                &visible.iter().copied().collect::<Vec<_>>(),
            )
            .await
            .unwrap_or_default()
            .into_values()
            .collect::<Vec<_>>(),
        )
    };
    let rows = repository::list_cc_ban_history(
        &state.pool,
        domain.as_deref(),
        visible_domains,
        q.limit.unwrap_or(500),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "list cc ban history");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "database error" })),
        )
    })?;
    Ok(Json(BanListDto {
        bans: rows.into_iter().map(BanDto::from).collect(),
    }))
}

/// DELETE /api/v1/cc/bans/:domain/:ip — manual unban (kept in history).
pub async fn remove(
    State(state): State<AppState>,
    actor: Actor,
    Path((domain, ip)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let domain = normalize_domain(&domain);
    if !actor.can_write_domain_name(&state, &domain).await {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "forbidden" })),
        ));
    }
    let ip: IpAddr = ip.trim().parse().map_err(|_| bad_request("invalid ip"))?;
    let n = repository::revoke_cc_ban(&state.pool, &domain, &ip.to_string(), &actor.email)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "delete cc ban");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "database error" })),
            )
        })?;
    Ok(Json(serde_json::json!({
        "deleted": n,
        "domain": domain,
        "ip": ip.to_string()
    })))
}

#[derive(Deserialize)]
pub struct ManualBanRequest {
    pub domain: String,
    pub ip: String,
    pub seconds: u64,
    #[serde(default)]
    pub reason: String,
}

#[derive(Deserialize)]
pub struct ManualUnbanRequest {
    pub domain: String,
    pub ip: String,
}

fn normalize_target(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Some(ip.to_string());
    }
    let (addr, prefix) = raw.split_once('/')?;
    let ip: IpAddr = addr.trim().parse().ok()?;
    let prefix: u8 = prefix.trim().parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    (prefix <= max).then(|| format!("{ip}/{prefix}"))
}

/// POST /api/v1/cc/bans/manual — create an IP/CIDR ban for a writable domain.
pub async fn create_manual(
    State(state): State<AppState>,
    actor: Actor,
    Json(req): Json<ManualBanRequest>,
) -> Result<(StatusCode, Json<BanDto>), (StatusCode, Json<serde_json::Value>)> {
    let domain = normalize_domain(&req.domain);
    if domain.is_empty() {
        return Err(bad_request("domain is required"));
    }
    if !actor.can_write_domain_name(&state, &domain).await {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "forbidden" })),
        ));
    }
    let target = normalize_target(&req.ip).ok_or_else(|| bad_request("invalid ip or cidr"))?;
    if repository::get_domain_by_name(&state.pool, &domain)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "database error" })),
            )
        })?
        .is_none()
    {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "domain not found" })),
        ));
    }
    let seconds = req.seconds.clamp(1, 86_400) as i64;
    let reason = if req.reason.trim().is_empty() {
        "manual-cc-ban".to_string()
    } else {
        req.reason.trim().chars().take(200).collect()
    };
    let row = repository::upsert_cc_ban(
        &state.pool,
        &domain,
        &target,
        seconds,
        &reason,
        &actor.email,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "manual cc ban");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "database error" })),
        )
    })?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "cc.ban.create",
        &format!("{domain}|{target}"),
        &reason,
    )
    .await;
    Ok((StatusCode::CREATED, Json(BanDto::from(row))))
}

/// POST /api/v1/cc/bans/unban — unban an IP/CIDR for a writable domain.
pub async fn unban_manual(
    State(state): State<AppState>,
    actor: Actor,
    Json(req): Json<ManualUnbanRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let domain = normalize_domain(&req.domain);
    if domain.is_empty() {
        return Err(bad_request("domain is required"));
    }
    if !actor.can_write_domain_name(&state, &domain).await {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "forbidden" })),
        ));
    }
    let target = normalize_target(&req.ip).ok_or_else(|| bad_request("invalid ip or cidr"))?;
    let n = repository::revoke_cc_ban(&state.pool, &domain, &target, &actor.email)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "manual cc unban");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "database error" })),
            )
        })?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "cc.ban.delete",
        &format!("{domain}|{target}"),
        "",
    )
    .await;
    Ok(Json(serde_json::json!({
        "deleted": n,
        "domain": domain,
        "ip": target
    })))
}
#[derive(Serialize)]
pub struct CcStatsDto {
    pub active_bans: i64,
    pub limited_24h: i64,
    pub challenged_24h: i64,
    pub banned_24h: i64,
    pub monitor_24h: i64,
    pub top_ips: Vec<(String, i64)>,
}

/// GET /api/v1/cc/stats — CC activity summary for the console.
pub async fn stats(
    State(state): State<AppState>,
    actor: Actor,
    Query(q): Query<BansQuery>,
) -> Result<Json<CcStatsDto>, (StatusCode, Json<serde_json::Value>)> {
    if !actor.is_admin {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "forbidden" })),
        ));
    }
    let domain = q.domain.as_deref().map(normalize_domain);
    let actions: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT action, COUNT(*)::bigint
        FROM waf_events
        WHERE category = 'cc'
          AND ts >= NOW() - INTERVAL '24 hours'
          AND ($1::text IS NULL OR domain = $1)
        GROUP BY action
        "#,
    )
    .bind(domain.as_deref())
    .fetch_all(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "cc stats");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "database error" })),
        )
    })?;
    let mut limited = 0i64;
    let mut challenged = 0i64;
    let mut banned = 0i64;
    let mut monitor = 0i64;
    for (action, count) in actions {
        match action.as_str() {
            "cc-limit" => limited = count,
            "challenge" | "cc-challenge" => challenged = count,
            "cc-ban" => banned = count,
            "log" => monitor = count,
            _ => {}
        }
    }
    let top_ips: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT client_ip, COUNT(*)::bigint
        FROM waf_events
        WHERE category = 'cc'
          AND ts >= NOW() - INTERVAL '24 hours'
          AND ($1::text IS NULL OR domain = $1)
        GROUP BY client_ip
        ORDER BY 2 DESC
        LIMIT 10
        "#,
    )
    .bind(domain.as_deref())
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let active_bans = repository::list_active_cc_bans(&state.pool, domain.as_deref())
        .await
        .map(|rows| rows.len() as i64)
        .unwrap_or(0);
    Ok(Json(CcStatsDto {
        active_bans,
        limited_24h: limited,
        challenged_24h: challenged,
        banned_24h: banned,
        monitor_24h: monitor,
        top_ips,
    }))
}
