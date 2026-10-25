//! Domain management — RESTful handlers with project-scoped authorization.

use crate::middleware::authz::Actor;
use crate::repository;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize)]
pub struct DomainDto {
    pub id: String,
    pub name: String,
    pub origin_host: String,
    pub origin_port: u16,
    pub origin_proto: String,
    pub ssl_enabled: bool,
    pub status: String,
    pub project_id: Option<String>,
    pub rate_limit_rps: u32,
    pub rate_limit_burst: u32,
}

#[derive(Deserialize)]
pub struct CreateDomainRequest {
    pub name: String,
    pub origin_host: String,
    pub origin_port: Option<u16>,
    pub origin_proto: Option<String>,
    pub ssl_enabled: Option<bool>,
    pub project_id: Option<String>,
    pub rate_limit_rps: Option<u32>,
    pub rate_limit_burst: Option<u32>,
    pub backup_origin_host: Option<String>,
    pub backup_origin_port: Option<u16>,
    pub backup_origin_proto: Option<String>,
}

#[derive(Serialize)]
pub struct ErrorBody {
    pub error: String,
}

#[derive(Serialize)]
pub struct DeleteResponse {
    pub success: bool,
    pub id: String,
}

pub(crate) fn to_dto(r: repository::DomainRow) -> DomainDto {
    DomainDto {
        id: r.id.to_string(),
        name: r.name,
        origin_host: r.origin_host,
        origin_port: r.origin_port as u16,
        origin_proto: r.origin_proto,
        ssl_enabled: r.ssl_enabled,
        status: r.status,
        project_id: r.project_id.map(|u| u.to_string()),
        rate_limit_rps: r.rate_limit_rps.max(0) as u32,
        rate_limit_burst: r.rate_limit_burst.max(0) as u32,
    }
}

fn parse_uuid(id: &str) -> Result<Uuid, (StatusCode, Json<ErrorBody>)> {
    Uuid::parse_str(id.trim()).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: format!("invalid uuid: {id}"),
            }),
        )
    })
}

fn db_error() -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorBody {
            error: "database error".into(),
        }),
    )
}

fn forbidden() -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorBody {
            error: "forbidden".into(),
        }),
    )
}

fn not_found(id: &str) -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorBody {
            error: format!("domain not found: {id}"),
        }),
    )
}

pub async fn list(
    State(state): State<AppState>,
    actor: Actor,
) -> Result<Json<Vec<DomainDto>>, (StatusCode, Json<ErrorBody>)> {
    let rows = repository::list_domains(&state.pool).await.map_err(|e| {
        tracing::error!(error = %e, "list domains");
        db_error()
    })?;
    let visible = actor.visible_domain_ids(&state).await;
    Ok(Json(
        rows.into_iter()
            .filter(|d| match &visible {
                None => true,
                Some(ids) => ids.contains(&d.id),
            })
            .map(to_dto)
            .collect(),
    ))
}

pub async fn create(
    State(state): State<AppState>,
    actor: Actor,
    Json(req): Json<CreateDomainRequest>,
) -> Result<(StatusCode, Json<DomainDto>), (StatusCode, Json<ErrorBody>)> {
    if req.name.trim().is_empty() || req.origin_host.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "name and origin_host required".into(),
            }),
        ));
    }
    let port = req.origin_port.unwrap_or(80) as i32;
    let proto = req.origin_proto.unwrap_or_else(|| {
        if req.ssl_enabled.unwrap_or(false) {
            "https".into()
        } else {
            "http".into()
        }
    });
    let ssl = req.ssl_enabled.unwrap_or(proto == "https");

    // Tenancy: admins may leave a domain unassigned (global); everyone else's
    // domains always live in a project they can write. When no project is
    // chosen we lazily create the user's personal project.
    let project_id = match req.project_id.as_deref().filter(|s| !s.is_empty()) {
        Some(s) => {
            let pid = Uuid::parse_str(s).map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorBody {
                        error: "invalid project_id".into(),
                    }),
                )
            })?;
            if !actor.can_write_project(&state, pid).await {
                return Err(forbidden());
            }
            Some(pid)
        }
        None => {
            if actor.admin() {
                None
            } else {
                Some(
                    repository::ensure_personal_project(&state.pool, actor.id)
                        .await
                        .map_err(|_| db_error())?,
                )
            }
        }
    };

    let row = repository::create_domain_with_project(
        &state.pool,
        req.name.trim(),
        req.origin_host.trim(),
        port,
        &proto,
        ssl,
        project_id,
    )
    .await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("duplicate") || msg.contains("unique") {
            tracing::warn!(name = %req.name, "domain already exists");
        } else {
            tracing::error!(error = %msg, "create domain");
        }
        let error = if msg.contains("duplicate") || msg.contains("unique") {
            "domain already exists"
        } else {
            "database error"
        };
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: error.into(),
            }),
        )
    })?;

    if let Some(rps) = req.rate_limit_rps {
        let burst = req.rate_limit_burst.unwrap_or(rps * 2);
        let _ =
            repository::set_domain_rate_limit(&state.pool, row.id, rps as i32, burst as i32).await;
    }
    if let Some(ref host) = req.backup_origin_host {
        if !host.is_empty() {
            let port = req.backup_origin_port.unwrap_or(80) as i32;
            let proto = req.backup_origin_proto.as_deref().unwrap_or("http");
            let _ = repository::set_backup_origin(&state.pool, row.id, host, port, proto).await;
        }
    }
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "domain.create",
        &row.name,
        &format!("{proto}://{}:{port}", row.origin_host),
    )
    .await;

    // Re-read so the response carries rate limits just written.
    let row = repository::get_domain(&state.pool, row.id)
        .await
        .ok()
        .flatten()
        .unwrap_or(row);
    Ok((StatusCode::CREATED, Json(to_dto(row))))
}

pub async fn get(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<DomainDto>, (StatusCode, Json<ErrorBody>)> {
    let uid = parse_uuid(&id)?;
    if !actor.can_read_domain(&state, uid).await {
        return Err(not_found(&id));
    }
    let row = repository::get_domain(&state.pool, uid)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "get domain");
            db_error()
        })?
        .ok_or_else(|| not_found(&id))?;
    Ok(Json(to_dto(row)))
}

pub async fn delete(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<DeleteResponse>, (StatusCode, Json<ErrorBody>)> {
    let uid = parse_uuid(&id)?;
    let row = repository::get_domain(&state.pool, uid)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found(&id))?;
    if !actor.can_write_domain(&state, uid).await {
        return Err(forbidden());
    }

    repository::delete_domain(&state.pool, uid)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, %id, "delete domain");
            db_error()
        })?;
    let _ =
        repository::insert_audit(&state.pool, &actor.email, "domain.delete", &row.name, "").await;
    tracing::info!(%id, "domain deleted ok");
    Ok(Json(DeleteResponse { success: true, id }))
}

#[derive(Deserialize)]
pub struct UpdateDomainRequest {
    pub origin_host: Option<String>,
    pub origin_port: Option<u16>,
    pub origin_proto: Option<String>,
    pub ssl_enabled: Option<bool>,
    pub status: Option<String>,
    pub project_id: Option<String>,
    pub rate_limit_rps: Option<u32>,
    pub rate_limit_burst: Option<u32>,
    pub backup_origin_host: Option<String>,
    pub backup_origin_port: Option<u16>,
    pub backup_origin_proto: Option<String>,
}

/// PUT /api/v1/domains/{id}
pub async fn update(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(req): Json<UpdateDomainRequest>,
) -> Result<Json<DomainDto>, (StatusCode, Json<ErrorBody>)> {
    let uid = parse_uuid(&id)?;
    if !actor.can_write_domain(&state, uid).await {
        return Err(forbidden());
    }
    if let Some(ref status) = req.status {
        let s = status.trim().to_lowercase();
        if s != "active" && s != "disabled" {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: "status must be active or disabled".into(),
                }),
            ));
        }
    }

    let row = repository::update_domain(
        &state.pool,
        uid,
        req.origin_host.as_deref(),
        req.origin_port.map(|p| p as i32),
        req.origin_proto.as_deref(),
        req.ssl_enabled,
        req.status.as_deref(),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "update domain");
        db_error()
    })?
    .ok_or_else(|| not_found(&id))?;

    if req.backup_origin_host.is_some() || req.backup_origin_port.is_some() {
        let host = req.backup_origin_host.as_deref().unwrap_or("");
        let port = req.backup_origin_port.unwrap_or(0) as i32;
        let proto = req.backup_origin_proto.as_deref().unwrap_or("http");
        let _ = repository::set_backup_origin(&state.pool, uid, host, port, proto).await;
    }
    if let Some(rps) = req.rate_limit_rps {
        let burst = req.rate_limit_burst.unwrap_or(rps * 2);
        let _ = repository::set_domain_rate_limit(&state.pool, uid, rps as i32, burst as i32).await;
    }

    // project_id: Some("") clears (admin only), Some(uuid) moves the domain.
    if let Some(ref pid) = req.project_id {
        let target = if pid.is_empty() {
            if !actor.admin() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorBody {
                        error: "only an admin can unassign a domain".into(),
                    }),
                ));
            }
            None
        } else {
            let parsed = Uuid::parse_str(pid).map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorBody {
                        error: "invalid project_id".into(),
                    }),
                )
            })?;
            if !actor.can_write_project(&state, parsed).await {
                return Err(forbidden());
            }
            Some(parsed)
        };
        let _ = repository::assign_domain_project(&state.pool, uid, target).await;
    }

    let row = repository::get_domain(&state.pool, uid)
        .await
        .ok()
        .flatten()
        .unwrap_or(row);
    let _ =
        repository::insert_audit(&state.pool, &actor.email, "domain.update", &row.name, "").await;
    Ok(Json(to_dto(row)))
}

#[derive(Deserialize)]
pub struct StatusRequest {
    pub status: String,
}

/// POST /api/v1/domains/{id}/status
pub async fn set_status(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(req): Json<StatusRequest>,
) -> Result<Json<DomainDto>, (StatusCode, Json<ErrorBody>)> {
    let status = req.status.trim().to_lowercase();
    if status != "active" && status != "disabled" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "status must be active or disabled".into(),
            }),
        ));
    }
    let uid = parse_uuid(&id)?;
    if !actor.can_write_domain(&state, uid).await {
        return Err(forbidden());
    }
    let row = repository::set_domain_status(&state.pool, uid, &status)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "set domain status");
            db_error()
        })?
        .ok_or_else(|| not_found(&id))?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "domain.status",
        &row.name,
        &status,
    )
    .await;
    Ok(Json(to_dto(row)))
}

#[derive(Deserialize)]
pub struct SettingsRequest {
    pub ignore_query_string: Option<bool>,
    pub cors_origins: Option<String>,
    pub hotlink_allow_referers: Option<String>,
    pub origin_timeout_ms: Option<u32>,
    pub custom_headers: Option<String>,
    pub rate_limit_rps: Option<u32>,
    pub rate_limit_burst: Option<u32>,
}

#[derive(Serialize)]
pub struct SettingsDto {
    pub ignore_query_string: bool,
    pub cors_origins: String,
    pub hotlink_allow_referers: String,
    pub origin_timeout_ms: u32,
    pub custom_headers: String,
    pub rate_limit_rps: u32,
    pub rate_limit_burst: u32,
}

fn settings_dto(s: repository::DomainSettingsRow) -> SettingsDto {
    SettingsDto {
        ignore_query_string: s.ignore_query_string,
        cors_origins: s.cors_origins,
        hotlink_allow_referers: s.hotlink_allow_referers,
        origin_timeout_ms: s.origin_timeout_ms.max(0) as u32,
        custom_headers: s.custom_headers,
        rate_limit_rps: s.rate_limit_rps.max(0) as u32,
        rate_limit_burst: s.rate_limit_burst.max(0) as u32,
    }
}

async fn resolve_domain(
    state: &AppState,
    id: &str,
) -> Result<repository::DomainRow, (StatusCode, Json<ErrorBody>)> {
    let row = if let Ok(uid) = Uuid::parse_str(id) {
        repository::get_domain(&state.pool, uid).await
    } else {
        repository::get_domain_by_name(&state.pool, id).await
    };
    row.map_err(|_| db_error())?.ok_or_else(|| not_found(id))
}

/// GET /api/v1/domains/{id}/settings — id can be uuid or domain name
pub async fn get_settings(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<SettingsDto>, (StatusCode, Json<ErrorBody>)> {
    let domain = resolve_domain(&state, &id).await?;
    if !actor.can_read_domain(&state, domain.id).await {
        return Err(forbidden());
    }
    let s = repository::get_domain_settings(&state.pool, &domain.name)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found(&id))?;
    Ok(Json(settings_dto(s)))
}

/// PUT /api/v1/domains/{id}/settings
pub async fn put_settings(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(req): Json<SettingsRequest>,
) -> Result<Json<SettingsDto>, (StatusCode, Json<ErrorBody>)> {
    let uid = parse_uuid(&id)?;
    if !actor.can_write_domain(&state, uid).await {
        return Err(forbidden());
    }
    let n = repository::update_domain_settings(
        &state.pool,
        uid,
        req.ignore_query_string,
        req.cors_origins.as_deref(),
        req.hotlink_allow_referers.as_deref(),
        req.origin_timeout_ms.map(|v| v as i32),
        req.custom_headers.as_deref(),
        req.rate_limit_rps.map(|v| v as i32),
        req.rate_limit_burst.map(|v| v as i32),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "update domain settings");
        db_error()
    })?;
    if n == 0 {
        return Err(not_found(&id));
    }
    let row = repository::get_domain(&state.pool, uid)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| not_found(&id))?;
    let s = repository::get_domain_settings(&state.pool, &row.name)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| not_found(&id))?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "domain.settings",
        &row.name,
        "updated",
    )
    .await;
    Ok(Json(settings_dto(s)))
}
