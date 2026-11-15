//! Administrator-managed Origin Shield allowlist.
//!
//! Domain owners may select one of these URLs, but may never submit an
//! arbitrary URL. This is the SSRF boundary for the Shield feature.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::middleware::authz::Actor;
use crate::state::AppState;

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct ShieldNodeDto {
    pub id: Uuid,
    pub name: String,
    pub url: String,
    pub enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: String,
}

type ApiError = (StatusCode, Json<ErrorBody>);

#[derive(Debug, Deserialize)]
pub struct CreateShieldNodeRequest {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateShieldNodeRequest {
    pub name: Option<String>,
    pub url: Option<String>,
    pub enabled: Option<bool>,
}

fn bad_request(error: impl Into<String>) -> ApiError {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorBody {
            error: error.into(),
        }),
    )
}

fn forbidden() -> ApiError {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorBody {
            error: "admin only".into(),
        }),
    )
}

fn not_found() -> ApiError {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorBody {
            error: "shield node not found".into(),
        }),
    )
}

fn conflict(error: impl Into<String>) -> ApiError {
    (
        StatusCode::CONFLICT,
        Json(ErrorBody {
            error: error.into(),
        }),
    )
}

fn db_error() -> ApiError {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorBody {
            error: "database error".into(),
        }),
    )
}

/// Canonical Shield base URL: http(s), authority only, no path/query/fragment.
pub fn normalize_shield_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("shield url is required".into());
    }
    if trimmed.len() > 2048 {
        return Err("shield url is too long".into());
    }
    let uri: axum::http::Uri = trimmed
        .parse()
        .map_err(|_| "invalid shield url".to_string())?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| "shield url must include http:// or https://".to_string())?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err("shield url must use http:// or https://".into());
    }
    let authority = uri
        .authority()
        .ok_or_else(|| "shield url must include a host".to_string())?;
    if authority.as_str().contains('@') {
        return Err("shield url must not contain credentials".into());
    }
    if uri.query().is_some() || trimmed.contains('#') {
        return Err("shield url must not contain query or fragment".into());
    }
    if !uri.path().is_empty() && uri.path() != "/" {
        return Err("shield url must be an origin without a path".into());
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

pub async fn enabled_url(pool: &PgPool, url: &str) -> Result<bool, sqlx::Error> {
    let row: Option<(bool,)> = sqlx::query_as("SELECT enabled FROM shield_nodes WHERE url = $1")
        .bind(url)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(enabled,)| enabled).unwrap_or(false))
}

async fn referenced_domains(pool: &PgPool, url: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT COUNT(*) FROM domains WHERE rtrim(shield_url, '/') = $1")
        .bind(url)
        .fetch_one(pool)
        .await
}

fn validate_name(raw: &str) -> Result<String, String> {
    let name = raw.trim();
    if name.is_empty() {
        return Err("name is required".into());
    }
    if name.chars().count() > 64 {
        return Err("name must be at most 64 characters".into());
    }
    Ok(name.to_string())
}

pub async fn list(
    State(state): State<AppState>,
    actor: Actor,
) -> Result<Json<Vec<ShieldNodeDto>>, ApiError> {
    let rows = if actor.is_admin {
        sqlx::query_as::<_, ShieldNodeDto>(
            "SELECT id, name, url, enabled FROM shield_nodes ORDER BY name, url",
        )
        .fetch_all(&state.pool)
        .await
    } else {
        sqlx::query_as::<_, ShieldNodeDto>(
            "SELECT id, name, url, enabled FROM shield_nodes WHERE enabled ORDER BY name, url",
        )
        .fetch_all(&state.pool)
        .await
    }
    .map_err(|e| {
        tracing::error!(error = %e, "list shield nodes");
        db_error()
    })?;
    Ok(Json(rows))
}

pub async fn create(
    State(state): State<AppState>,
    actor: Actor,
    Json(req): Json<CreateShieldNodeRequest>,
) -> Result<(StatusCode, Json<ShieldNodeDto>), ApiError> {
    if !actor.is_admin {
        return Err(forbidden());
    }
    let name = validate_name(&req.name).map_err(bad_request)?;
    let url = normalize_shield_url(&req.url).map_err(bad_request)?;
    let enabled = req.enabled.unwrap_or(true);
    let row = sqlx::query_as::<_, ShieldNodeDto>(
        "INSERT INTO shield_nodes (name, url, enabled)
         VALUES ($1, $2, $3)
         RETURNING id, name, url, enabled",
    )
    .bind(name)
    .bind(url)
    .bind(enabled)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| {
        if let Some(db) = e.as_database_error() {
            if db.is_unique_violation() {
                return conflict("shield url already exists");
            }
        }
        tracing::error!(error = %e, "create shield node");
        db_error()
    })?;
    Ok((StatusCode::CREATED, Json(row)))
}

pub async fn update(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(req): Json<UpdateShieldNodeRequest>,
) -> Result<Json<ShieldNodeDto>, ApiError> {
    if !actor.is_admin {
        return Err(forbidden());
    }
    let uid = Uuid::parse_str(&id).map_err(|_| bad_request("invalid shield node id"))?;
    let current = sqlx::query_as::<_, ShieldNodeDto>(
        "SELECT id, name, url, enabled FROM shield_nodes WHERE id = $1",
    )
    .bind(uid)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "get shield node");
        db_error()
    })?
    .ok_or_else(not_found)?;

    let name = match req.name.as_deref() {
        Some(value) => validate_name(value).map_err(bad_request)?,
        None => current.name.clone(),
    };
    let url = match req.url.as_deref() {
        Some(value) => normalize_shield_url(value).map_err(bad_request)?,
        None => current.url.clone(),
    };
    let enabled = req.enabled.unwrap_or(current.enabled);

    if url != current.url || (!enabled && current.enabled) {
        let refs = referenced_domains(&state.pool, &current.url)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "count shield node references");
                db_error()
            })?;
        if refs > 0 {
            return Err(conflict(format!(
                "shield node is used by {refs} domain(s); update those domains first"
            )));
        }
    }

    let row = sqlx::query_as::<_, ShieldNodeDto>(
        "UPDATE shield_nodes
         SET name = $1, url = $2, enabled = $3, updated_at = NOW()
         WHERE id = $4
         RETURNING id, name, url, enabled",
    )
    .bind(name)
    .bind(url)
    .bind(enabled)
    .bind(uid)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| {
        if let Some(db) = e.as_database_error() {
            if db.is_unique_violation() {
                return conflict("shield url already exists");
            }
        }
        tracing::error!(error = %e, "update shield node");
        db_error()
    })?;
    Ok(Json(row))
}

pub async fn delete(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    if !actor.is_admin {
        return Err(forbidden());
    }
    let uid = Uuid::parse_str(&id).map_err(|_| bad_request("invalid shield node id"))?;
    let current = sqlx::query_as::<_, ShieldNodeDto>(
        "SELECT id, name, url, enabled FROM shield_nodes WHERE id = $1",
    )
    .bind(uid)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "get shield node");
        db_error()
    })?
    .ok_or_else(not_found)?;
    let refs = referenced_domains(&state.pool, &current.url)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "count shield node references");
            db_error()
        })?;
    if refs > 0 {
        return Err(conflict(format!(
            "shield node is used by {refs} domain(s); update those domains first"
        )));
    }
    sqlx::query("DELETE FROM shield_nodes WHERE id = $1")
        .bind(uid)
        .execute(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "delete shield node");
            db_error()
        })?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::normalize_shield_url;

    #[test]
    fn normalizes_origin_only_urls() {
        assert_eq!(
            normalize_shield_url("https://shield-s1.example.com/"),
            Ok("https://shield-s1.example.com".into())
        );
        assert_eq!(
            normalize_shield_url("http://10.0.0.10:8080"),
            Ok("http://10.0.0.10:8080".into())
        );
    }

    #[test]
    fn rejects_paths_and_credential_urls() {
        assert!(normalize_shield_url("https://shield.example.com/path").is_err());
        assert!(normalize_shield_url("https://user:pass@shield.example.com").is_err());
        assert!(normalize_shield_url("https://shield.example.com?x=1").is_err());
        assert!(normalize_shield_url("https://shield.example.com#frag").is_err());
        assert!(normalize_shield_url("ftp://shield.example.com").is_err());
    }
}
