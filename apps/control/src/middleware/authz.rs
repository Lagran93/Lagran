//! Authorization: global admin role + project-scoped tenancy.
//!
//! `Actor` is a request extractor that resolves the caller from the JWT and
//! loads the current role from the database (so demotions take effect without
//! waiting for the token to expire). Access rules:
//!
//! * `admin` — full access to every project/domain.
//! * project `owner`/`admin` — read + write inside that project.
//! * project `member` — read-only inside that project.
//! * domains without a project are admin-only (they belong to no tenant).

use crate::middleware::AuthUser;
use crate::repository;
use crate::state::AppState;
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Actor {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub is_admin: bool,
}

#[derive(Debug)]
pub struct ActorError {
    status: StatusCode,
    message: &'static str,
}

impl ActorError {
    fn unauthorized(message: &'static str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message,
        }
    }

    fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "database error",
        }
    }
}

impl IntoResponse for ActorError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

#[async_trait]
impl FromRequestParts<AppState> for Actor {
    type Rejection = ActorError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let user = <AuthUser as FromRequestParts<AppState>>::from_request_parts(parts, state)
            .await
            .map_err(|_| ActorError::unauthorized("unauthorized"))?;
        let id = Uuid::parse_str(&user.0.sub)
            .map_err(|_| ActorError::unauthorized("invalid token subject"))?;
        let role = repository::get_user_role(&state.pool, id)
            .await
            .map_err(|_| ActorError::internal())?
            .ok_or_else(|| ActorError::unauthorized("user no longer exists"))?;
        Ok(Actor {
            id,
            email: user.0.email.clone(),
            name: user.0.name.clone(),
            is_admin: role == "admin",
        })
    }
}

impl Actor {
    pub fn admin(&self) -> bool {
        self.is_admin
    }

    /// True when the actor may read the project's resources.
    pub async fn can_read_project(&self, state: &AppState, project_id: Uuid) -> bool {
        if self.is_admin {
            return true;
        }
        repository::project_role(&state.pool, project_id, self.id)
            .await
            .ok()
            .flatten()
            .is_some()
    }

    /// True when the actor may mutate the project's resources.
    pub async fn can_write_project(&self, state: &AppState, project_id: Uuid) -> bool {
        if self.is_admin {
            return true;
        }
        matches!(
            repository::project_role(&state.pool, project_id, self.id)
                .await
                .ok()
                .flatten()
                .as_deref(),
            Some("owner") | Some("admin")
        )
    }

    pub async fn can_read_domain(&self, state: &AppState, domain_id: Uuid) -> bool {
        if self.is_admin {
            return true;
        }
        match repository::domain_project(&state.pool, domain_id).await {
            Ok(Some(Some(pid))) => self.can_read_project(state, pid).await,
            _ => false,
        }
    }

    pub async fn can_write_domain(&self, state: &AppState, domain_id: Uuid) -> bool {
        if self.is_admin {
            return true;
        }
        match repository::domain_project(&state.pool, domain_id).await {
            Ok(Some(Some(pid))) => self.can_write_project(state, pid).await,
            _ => false,
        }
    }

    /// Domain IDs the actor may read. `None` means "all" (admin).
    pub async fn visible_domain_ids(&self, state: &AppState) -> Option<Vec<Uuid>> {
        if self.is_admin {
            return None;
        }
        repository::domains_for_user(&state.pool, self.id)
            .await
            .ok()
            .map(Some)
            .unwrap_or(Some(Vec::new()))
    }

    pub async fn can_read_domain_name(&self, state: &AppState, name: &str) -> bool {
        if self.is_admin {
            return true;
        }
        match repository::get_domain_by_name(&state.pool, name).await {
            Ok(Some(d)) => self.can_read_domain(state, d.id).await,
            _ => false,
        }
    }

    pub async fn can_write_domain_name(&self, state: &AppState, name: &str) -> bool {
        if self.is_admin {
            return true;
        }
        match repository::get_domain_by_name(&state.pool, name).await {
            Ok(Some(d)) => self.can_write_domain(state, d.id).await,
            _ => false,
        }
    }
}

/// Standard JSON error body used by the authorization helpers.
pub fn forbidden() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::FORBIDDEN, Json(json!({ "error": "forbidden" })))
}

pub fn not_found() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" })))
}
