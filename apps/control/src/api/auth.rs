//! Auth endpoints backed by PostgreSQL + JWT

use crate::middleware::AuthUser;
use crate::repository;
use crate::state::AppState;
use crate::utils::{issue_token, verify_password};
use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub name: Option<String>,
}

#[derive(Serialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub name: String,
    pub role: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub user: UserInfo,
}

#[derive(Serialize)]
pub struct ErrorBody {
    pub error: String,
}

pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<ErrorBody>)> {
    let user = repository::find_user_by_email(&state.pool, &req.email)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: "database error".into(),
                }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorBody {
                    error: "invalid email or password".into(),
                }),
            )
        })?;

    let ok = verify_password(&req.password, &user.password_hash).unwrap_or(false);
    if !ok {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "invalid email or password".into(),
            }),
        ));
    }

    let token = issue_token(
        user.id,
        &user.email,
        &user.name,
        &state.config.jwt_secret,
        state.config.jwt_expire_hours,
    )
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: "token error".into(),
            }),
        )
    })?;

    Ok(Json(LoginResponse {
        token,
        user: UserInfo {
            id: user.id.to_string(),
            email: user.email,
            name: user.name,
            role: user.role,
        },
    }))
}

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<LoginResponse>), (StatusCode, Json<ErrorBody>)> {
    if req.password.len() < 6 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "password too short".into(),
            }),
        ));
    }
    if repository::find_user_by_email(&state.pool, &req.email)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: "database error".into(),
                }),
            )
        })?
        .is_some()
    {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorBody {
                error: "email already registered".into(),
            }),
        ));
    }

    let hash = crate::utils::hash_password(&req.password).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: "hash error".into(),
            }),
        )
    })?;

    let name = req.name.unwrap_or_else(|| req.email.clone());
    let user = repository::create_user(&state.pool, &req.email, &hash, &name)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "create user");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: "database error".into(),
                }),
            )
        })?;

    let token = issue_token(
        user.id,
        &user.email,
        &user.name,
        &state.config.jwt_secret,
        state.config.jwt_expire_hours,
    )
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: "token error".into(),
            }),
        )
    })?;

    Ok((
        StatusCode::CREATED,
        Json(LoginResponse {
            token,
            user: UserInfo {
                id: user.id.to_string(),
                email: user.email,
                name: user.name,
                role: user.role,
            },
        }),
    ))
}

pub async fn me(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
) -> Result<Json<UserInfo>, (StatusCode, Json<ErrorBody>)> {
    let id = Uuid::parse_str(&claims.sub).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "invalid token".into(),
            }),
        )
    })?;

    let user = repository::find_user_by_id(&state.pool, id)
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
                StatusCode::UNAUTHORIZED,
                Json(ErrorBody {
                    error: "user not found".into(),
                }),
            )
        })?;

    Ok(Json(UserInfo {
        id: user.id.to_string(),
        email: user.email,
        name: user.name,
        role: user.role,
    }))
}
