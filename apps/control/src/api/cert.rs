//! Certificate management (project-scoped) + edge-facing delivery (agent token).

use crate::middleware::agent_auth::AgentAuth;
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
pub struct CertDto {
    pub id: String,
    pub domain_id: Option<String>,
    pub domain_name: String,
    pub issuer: String,
    pub status: String,
    pub auto_renew: bool,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub has_cert: bool,
    pub has_key: bool,
    pub created_at: String,
}

#[derive(Deserialize)]
pub struct CreateCertRequest {
    pub domain_name: String,
    pub domain_id: Option<String>,
    pub cert_pem: Option<String>,
    pub key_pem: Option<String>,
    pub issuer: Option<String>,
    pub auto_renew: Option<bool>,
}

#[derive(Serialize)]
pub struct ErrorBody {
    pub error: String,
}

fn to_dto(r: repository::CertRow) -> CertDto {
    CertDto {
        id: r.id.to_string(),
        domain_id: r.domain_id.map(|u| u.to_string()),
        domain_name: r.domain_name,
        issuer: r.issuer,
        status: r.status,
        auto_renew: r.auto_renew,
        not_before: r.not_before.map(|t| t.to_rfc3339()),
        not_after: r.not_after.map(|t| t.to_rfc3339()),
        has_cert: !r.cert_pem.is_empty(),
        has_key: !r.key_pem.is_empty(),
        created_at: r.created_at.to_rfc3339(),
    }
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

/// Read access to a certificate follows its domain.
async fn can_read(state: &AppState, actor: &Actor, cert: &repository::CertRow) -> bool {
    if actor.admin() {
        return true;
    }
    match cert.domain_id {
        Some(id) => actor.can_read_domain(state, id).await,
        None => actor.can_read_domain_name(state, &cert.domain_name).await,
    }
}

async fn can_write(state: &AppState, actor: &Actor, cert: &repository::CertRow) -> bool {
    if actor.admin() {
        return true;
    }
    match cert.domain_id {
        Some(id) => actor.can_write_domain(state, id).await,
        None => actor.can_write_domain_name(state, &cert.domain_name).await,
    }
}

pub async fn list(
    State(state): State<AppState>,
    actor: Actor,
) -> Result<Json<Vec<CertDto>>, (StatusCode, Json<ErrorBody>)> {
    let rows = repository::list_certs(&state.pool).await.map_err(|e| {
        tracing::error!(error = %e, "list certs");
        db_error()
    })?;
    if actor.admin() {
        return Ok(Json(rows.into_iter().map(to_dto).collect()));
    }
    let visible = actor.visible_domain_ids(&state).await;
    let mut out = Vec::new();
    for row in rows {
        let allowed = match row.domain_id {
            Some(id) => visible.as_ref().map(|v| v.contains(&id)).unwrap_or(true),
            None => false,
        };
        if allowed {
            out.push(to_dto(row));
        }
    }
    Ok(Json(out))
}

pub async fn create(
    State(state): State<AppState>,
    actor: Actor,
    Json(req): Json<CreateCertRequest>,
) -> Result<(StatusCode, Json<CertDto>), (StatusCode, Json<ErrorBody>)> {
    if req.domain_name.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "domain_name required".into(),
            }),
        ));
    }
    let domain_id = match req.domain_id.as_deref().filter(|s| !s.is_empty()) {
        Some(s) => Some(Uuid::parse_str(s).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: "invalid domain_id".into(),
                }),
            )
        })?),
        None => repository::get_domain_by_name(&state.pool, &req.domain_name)
            .await
            .ok()
            .flatten()
            .map(|d| d.id),
    };

    let allowed = match domain_id {
        Some(did) => actor.can_write_domain(&state, did).await,
        None => actor.can_write_domain_name(&state, &req.domain_name).await,
    };
    if !allowed {
        return Err(forbidden());
    }

    let row = repository::create_cert(
        &state.pool,
        domain_id,
        req.domain_name.trim(),
        req.cert_pem.as_deref().unwrap_or(""),
        req.key_pem.as_deref().unwrap_or(""),
        req.issuer.as_deref().unwrap_or("manual"),
        req.auto_renew.unwrap_or(false),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "create cert");
        db_error()
    })?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "cert.create",
        &row.domain_name,
        &row.issuer,
    )
    .await;
    Ok((StatusCode::CREATED, Json(to_dto(row))))
}

pub async fn get(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<CertDto>, (StatusCode, Json<ErrorBody>)> {
    let uid = parse_uuid(&id)?;
    let row = repository::get_cert(&state.pool, uid)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorBody {
                    error: "not found".into(),
                }),
            )
        })?;
    if !can_read(&state, &actor, &row).await {
        return Err(forbidden());
    }
    Ok(Json(to_dto(row)))
}

pub async fn delete(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorBody>)> {
    let uid = parse_uuid(&id)?;
    let row = repository::get_cert(&state.pool, uid)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorBody {
                    error: "not found".into(),
                }),
            )
        })?;
    if !can_write(&state, &actor, &row).await {
        return Err(forbidden());
    }
    repository::delete_cert(&state.pool, uid)
        .await
        .map_err(|_| db_error())?;
    let _ = repository::insert_audit(
        &state.pool,
        &actor.email,
        "cert.delete",
        &row.domain_name,
        "",
    )
    .await;
    Ok(Json(serde_json::json!({ "success": true, "id": id })))
}

fn parse_uuid(id: &str) -> Result<Uuid, (StatusCode, Json<ErrorBody>)> {
    Uuid::parse_str(id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "invalid id".into(),
            }),
        )
    })
}

/// Edge-facing: fetch the active cert (including private key) for a domain.
#[derive(Serialize)]
pub struct EdgeCertResponse {
    pub domain: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub status: String,
}

pub async fn edge_get(
    State(state): State<AppState>,
    _agent: AgentAuth,
    Path(domain): Path<String>,
) -> Result<Json<EdgeCertResponse>, (StatusCode, Json<ErrorBody>)> {
    let row = repository::get_cert_by_domain(&state.pool, &domain)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorBody {
                    error: "no active cert".into(),
                }),
            )
        })?;
    Ok(Json(EdgeCertResponse {
        domain: row.domain_name,
        cert_pem: row.cert_pem,
        key_pem: row.key_pem,
        status: row.status,
    }))
}

#[derive(Serialize)]
pub struct EdgeCertBundle {
    pub domain: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub status: String,
}

/// Edge: list all active certs with PEM (agent token required).
pub async fn edge_list_active(
    State(state): State<AppState>,
    _agent: AgentAuth,
) -> Result<Json<Vec<EdgeCertBundle>>, (StatusCode, Json<ErrorBody>)> {
    let rows = repository::list_certs(&state.pool).await.map_err(|e| {
        tracing::error!(error = %e, "list certs for edge");
        db_error()
    })?;
    let out: Vec<_> = rows
        .into_iter()
        .filter(|r| r.status == "active" && !r.cert_pem.is_empty() && !r.key_pem.is_empty())
        .map(|r| EdgeCertBundle {
            domain: r.domain_name,
            cert_pem: r.cert_pem,
            key_pem: r.key_pem,
            status: r.status,
        })
        .collect();
    Ok(Json(out))
}
