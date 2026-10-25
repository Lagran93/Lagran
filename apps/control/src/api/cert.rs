//! Certificate management

use crate::middleware::agent_auth::AgentAuth;
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

pub async fn list(
    State(state): State<AppState>,
    _user: AuthUser,
) -> Result<Json<Vec<CertDto>>, (StatusCode, Json<ErrorBody>)> {
    let rows = repository::list_certs(&state.pool).await.map_err(|e| {
        tracing::error!(error = %e, "list certs");
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
    let domain_id = match req.domain_id.as_deref() {
        Some(s) if !s.is_empty() => Some(Uuid::parse_str(s).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: "invalid domain_id".into(),
                }),
            )
        })?),
        _ => {
            // try resolve by name
            repository::get_domain_by_name(&state.pool, &req.domain_name)
                .await
                .ok()
                .flatten()
                .map(|d| d.id)
        }
    };

    let row = repository::create_cert(
        &state.pool,
        domain_id,
        &req.domain_name,
        req.cert_pem.as_deref().unwrap_or(""),
        req.key_pem.as_deref().unwrap_or(""),
        req.issuer.as_deref().unwrap_or("manual"),
        req.auto_renew.unwrap_or(false),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "create cert");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: "database error".into(),
            }),
        )
    })?;

    Ok((StatusCode::CREATED, Json(to_dto(row))))
}

pub async fn get(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<CertDto>, (StatusCode, Json<ErrorBody>)> {
    let uid = Uuid::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "invalid id".into(),
            }),
        )
    })?;
    let row = repository::get_cert(&state.pool, uid)
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
    Ok(Json(to_dto(row)))
}

pub async fn delete(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorBody>)> {
    let uid = Uuid::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "invalid id".into(),
            }),
        )
    })?;
    let n = repository::delete_cert(&state.pool, uid).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: "database error".into(),
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
    Ok(Json(serde_json::json!({ "success": true, "id": id })))
}

/// Edge-facing: fetch active cert PEM for a domain (no private key in list; key only for edge with secret later)
#[derive(Serialize)]
pub struct EdgeCertResponse {
    pub domain: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub status: String,
}

pub async fn edge_get(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Result<Json<EdgeCertResponse>, (StatusCode, Json<ErrorBody>)> {
    let row = repository::get_cert_by_domain(&state.pool, &domain)
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

/// Edge: list all active certs with PEM (agent token)
pub async fn edge_list_active(
    State(state): State<AppState>,
    _agent: AgentAuth,
) -> Result<Json<Vec<EdgeCertBundle>>, (StatusCode, Json<ErrorBody>)> {
    let rows = repository::list_certs(&state.pool).await.map_err(|e| {
        tracing::error!(error = %e, "list certs for edge");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: "database error".into(),
            }),
        )
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
