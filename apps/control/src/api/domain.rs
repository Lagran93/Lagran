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
}

#[derive(Deserialize)]
pub struct CreateDomainRequest {
    pub name: String,
    pub origin_host: String,
    pub origin_port: Option<u16>,
    pub origin_proto: Option<String>,
    pub ssl_enabled: Option<bool>,
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

    let row = repository::create_domain(
        &state.pool,
        &req.name,
        &req.origin_host,
        port,
        &proto,
        ssl,
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
    Ok(Json(to_dto(row)))
}
