//! Domain management — RESTful handlers

use crate::middleware::AuthUser;
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

fn to_dto(r: repository::DomainRow) -> DomainDto {
    DomainDto {
        id: r.id.to_string(),
        name: r.name,
        origin_host: r.origin_host,
        origin_port: r.origin_port as u16,
        origin_proto: r.origin_proto,
        ssl_enabled: r.ssl_enabled,
        status: r.status,
        project_id: r.project_id.map(|u| u.to_string()),
        rate_limit_rps: 0,
        rate_limit_burst: 0,
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

pub async fn list(
    State(state): State<AppState>,
    _user: AuthUser,
) -> Result<Json<Vec<DomainDto>>, (StatusCode, Json<ErrorBody>)> {
    let rows = repository::list_domains(&state.pool).await.map_err(|e| {
        tracing::error!(error = %e, "list domains");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: "database error".into(),
            }),
        )
    })?;
    Ok(Json(rows.into_iter().map(to_dto).collect()))
}

pub async fn create(
    State(state): State<AppState>,
    _user: AuthUser,
    Json(req): Json<CreateDomainRequest>,
) -> Result<(StatusCode, Json<DomainDto>), (StatusCode, Json<ErrorBody>)> {
    let port = req.origin_port.unwrap_or(80) as i32;
    let proto = req.origin_proto.unwrap_or_else(|| {
        if req.ssl_enabled.unwrap_or(false) {
            "https".into()
        } else {
            "http".into()
        }
    });
    let ssl = req.ssl_enabled.unwrap_or(proto == "https");

    let project_id = match req.project_id.as_deref() {
        Some(s) if !s.is_empty() => Some(uuid::Uuid::parse_str(s).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: "invalid project_id".into(),
                }),
            )
        })?),
        _ => None,
    };
    let row = repository::create_domain_with_project(
        &state.pool,
        &req.name,
        &req.origin_host,
        port,
        &proto,
        ssl,
        project_id,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "create domain");
        let msg = if e.to_string().contains("duplicate") || e.to_string().contains("unique") {
            "domain already exists"
        } else {
            "database error"
        };
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: msg.into(),
            }),
        )
    })?;

    if let (Some(rps), Some(burst)) = (req.rate_limit_rps, req.rate_limit_burst) {
        let _ = repository::set_domain_rate_limit(&state.pool, row.id, rps as i32, burst as i32).await;
    } else if let Some(rps) = req.rate_limit_rps {
        let _ = repository::set_domain_rate_limit(&state.pool, row.id, rps as i32, rps as i32 * 2).await;
    }
    if let Some(ref host) = req.backup_origin_host {
        if !host.is_empty() {
            let port = req.backup_origin_port.unwrap_or(80) as i32;
            let proto = req.backup_origin_proto.as_deref().unwrap_or("http");
            let _ = repository::set_backup_origin(&state.pool, row.id, host, port, proto).await;
        }
    }
    Ok((StatusCode::CREATED, Json(to_dto(row))))
}

/// GET /api/v1/domains/{id}
pub async fn get(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<DomainDto>, (StatusCode, Json<ErrorBody>)> {
    let uid = parse_uuid(&id)?;
    let row = repository::get_domain(&state.pool, uid)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "get domain");
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
                    error: format!("domain not found: {id}"),
                }),
            )
        })?;
    Ok(Json(to_dto(row)))
}

/// DELETE /api/v1/domains/{id}
pub async fn delete(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<DeleteResponse>, (StatusCode, Json<ErrorBody>)> {
    tracing::info!(%id, "DELETE /api/v1/domains/{{id}}");
    let uid = parse_uuid(&id)?;

    if repository::get_domain(&state.pool, uid)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: format!("database error: {e}"),
                }),
            )
        })?
        .is_none()
    {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: format!("domain not found: {id}"),
            }),
        ));
    }

    repository::delete_domain(&state.pool, uid)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, %id, "delete domain");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: format!("database error: {e}"),
                }),
            )
        })?;

    tracing::info!(%id, "domain deleted ok");
    Ok(Json(DeleteResponse {
        success: true,
        id,
    }))
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
    _user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateDomainRequest>,
) -> Result<Json<DomainDto>, (StatusCode, Json<ErrorBody>)> {
    let uid = parse_uuid(&id)?;
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
                error: format!("domain not found: {id}"),
            }),
        )
    })?;
    if req.backup_origin_host.is_some() || req.backup_origin_port.is_some() {
        let host = req.backup_origin_host.as_deref().unwrap_or("");
        let port = req.backup_origin_port.unwrap_or(0) as i32;
        let proto = req.backup_origin_proto.as_deref().unwrap_or("http");
        let _ = repository::set_backup_origin(&state.pool, uid, host, port, proto).await;
    }
    Ok(Json(to_dto(row)))
}

#[derive(Deserialize)]
pub struct StatusRequest {
    pub status: String,
}

/// POST /api/v1/domains/{id}/status
pub async fn set_status(
    State(state): State<AppState>,
    user: AuthUser,
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
    let row = repository::set_domain_status(&state.pool, uid, &status)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: format!("database error: {e}"),
                }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorBody {
                    error: format!("domain not found: {id}"),
                }),
            )
        })?;
    let _ = repository::insert_audit(
        &state.pool,
        &user.0.email,
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

/// GET /api/v1/domains/{id}/settings  — id can be uuid or domain name
pub async fn get_settings(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<SettingsDto>, (StatusCode, Json<ErrorBody>)> {
    let name = if let Ok(uid) = Uuid::parse_str(&id) {
        repository::get_domain(&state.pool, uid)
            .await
            .ok()
            .flatten()
            .map(|d| d.name)
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    Json(ErrorBody {
                        error: "not found".into(),
                    }),
                )
            })?
    } else {
        id.clone()
    };
    let s = repository::get_domain_settings(&state.pool, &name)
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
                    error: "not found".into(),
                }),
            )
        })?;
    Ok(Json(SettingsDto {
        ignore_query_string: s.ignore_query_string,
        cors_origins: s.cors_origins,
        hotlink_allow_referers: s.hotlink_allow_referers,
        origin_timeout_ms: s.origin_timeout_ms.max(0) as u32,
        custom_headers: s.custom_headers,
        rate_limit_rps: s.rate_limit_rps.max(0) as u32,
        rate_limit_burst: s.rate_limit_burst.max(0) as u32,
    }))
}

/// PUT /api/v1/domains/{id}/settings
pub async fn put_settings(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<SettingsRequest>,
) -> Result<Json<SettingsDto>, (StatusCode, Json<ErrorBody>)> {
    let uid = parse_uuid(&id)?;
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
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: format!("database error: {e}"),
            }),
        )
    })?;
    if n == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: "not found".into(),
            }),
        ));
    }
    let _ = repository::insert_audit(
        &state.pool,
        &user.0.email,
        "domain.settings",
        &id,
        "updated",
    )
    .await;
    // re-read settings
    let row = repository::get_domain(&state.pool, uid)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorBody {
                    error: "not found".into(),
                }),
            )
        })?;
    let s = repository::get_domain_settings(&state.pool, &row.name)
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
                    error: "not found".into(),
                }),
            )
        })?;
    Ok(Json(SettingsDto {
        ignore_query_string: s.ignore_query_string,
        cors_origins: s.cors_origins,
        hotlink_allow_referers: s.hotlink_allow_referers,
        origin_timeout_ms: s.origin_timeout_ms.max(0) as u32,
        custom_headers: s.custom_headers,
        rate_limit_rps: s.rate_limit_rps.max(0) as u32,
        rate_limit_burst: s.rate_limit_burst.max(0) as u32,
    }))
}
