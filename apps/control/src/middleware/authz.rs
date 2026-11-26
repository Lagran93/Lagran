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
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;

/// `/metrics` counters for the actor load path.
///
/// `ACTOR_DB_LOADS` is the regression guard: with the permission middleware
/// publishing the actor into the request extensions, one authenticated request
/// must produce exactly one DB load — or one Redis hit when the session cache
/// is enabled — never two.
pub static ACTOR_DB_LOADS: AtomicU64 = AtomicU64::new(0);
pub static ACTOR_REDIS_HITS: AtomicU64 = AtomicU64::new(0);
pub static ACTOR_REUSES: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedSession {
    role: String,
    is_active: bool,
    token_version: i64,
    #[serde(default)]
    permissions: Vec<String>,
    /// Whether the user's module access is restricted. Old cache entries lack
    /// this field; default to `true` so a deploy does not silently grant an
    /// unrestricted session for the remaining TTL.
    #[serde(default = "default_restricted")]
    restricted: bool,
}

fn default_restricted() -> bool {
    true
}

#[derive(Debug, Clone)]
pub struct Actor {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub is_admin: bool,
    /// `None` = the user has no groups (legacy project-role behaviour, all
    /// modules allowed). `Some(list)` = restricted to exactly those grants;
    /// an empty list grants nothing.
    pub permissions: Option<Vec<String>>,
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
        // The permission middleware already resolved the actor for this
        // request; reuse it instead of paying for a second load.
        if let Some(actor) = parts.extensions.get::<Actor>() {
            ACTOR_REUSES.fetch_add(1, Ordering::Relaxed);
            return Ok(actor.clone());
        }
        let user = <AuthUser as FromRequestParts<AppState>>::from_request_parts(parts, state)
            .await
            .map_err(|_| ActorError::unauthorized("unauthorized"))?;
        let id = Uuid::parse_str(&user.0.sub)
            .map_err(|_| ActorError::unauthorized("invalid token subject"))?;
        let session_key = crate::service::redis::session_key(id);
        let redis = state.redis.as_deref();
        let cached = if let Some(redis) = redis {
            redis.get_json::<CachedSession>(&session_key).await
        } else {
            None
        };
        if cached.is_some() {
            ACTOR_REDIS_HITS.fetch_add(1, Ordering::Relaxed);
        }
        let (role, is_active, token_version, permissions, restricted) = if let Some(cached) = cached
        {
            (
                cached.role,
                cached.is_active,
                cached.token_version,
                cached.permissions,
                cached.restricted,
            )
        } else {
            let (role, is_active, token_version, restricted, permissions) =
                repository::get_actor_facts(&state.pool, id)
                    .await
                    .map_err(|_| ActorError::internal())?
                    .ok_or_else(|| ActorError::unauthorized("user no longer exists"))?;
            ACTOR_DB_LOADS.fetch_add(1, Ordering::Relaxed);
            if let Some(redis) = redis {
                let _ = redis
                    .set_json(
                        &session_key,
                        &CachedSession {
                            role: role.clone(),
                            is_active,
                            token_version,
                            permissions: permissions.clone(),
                            restricted,
                        },
                        state.config.redis_session_ttl_secs,
                    )
                    .await;
            }
            (role, is_active, token_version, permissions, restricted)
        };
        if !is_active {
            if let Some(redis) = redis {
                redis.del(&session_key).await;
            }
            return Err(ActorError::unauthorized("account is disabled"));
        }
        if user.0.ver != token_version {
            if let Some(redis) = redis {
                redis.del(&session_key).await;
            }
            return Err(ActorError::unauthorized("session expired"));
        }
        Ok(Actor {
            id,
            email: user.0.email.clone(),
            name: user.0.name.clone(),
            is_admin: role == "admin",
            permissions: if restricted {
                Some(permissions)
            } else {
                None
            },
        })
    }
}

impl Actor {
    pub fn admin(&self) -> bool {
        self.is_admin
    }

    /// Module permission from user groups.
    ///
    /// Only users who were never restricted by a group keep the legacy
    /// unrestricted behaviour. A restricted user with no grants is denied;
    /// previously removing the last group *granted* every module.
    pub fn allows(&self, permission: &str) -> bool {
        if self.is_admin {
            return true;
        }
        let Some(granted_list) = self.permissions.as_ref() else {
            return true;
        };
        granted_list.iter().any(|granted| {
            granted == permission
                || granted == "*"
                || granted
                    .strip_suffix(":*")
                    .is_some_and(|module| permission.starts_with(&format!("{module}:")))
        })
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

#[cfg(test)]
mod tests {
    use super::Actor;
    use uuid::Uuid;

    fn actor(permissions: Option<Vec<&str>>) -> Actor {
        Actor {
            id: Uuid::nil(),
            email: "user@example.test".into(),
            name: "user".into(),
            is_admin: false,
            permissions: permissions.map(|list| list.into_iter().map(str::to_string).collect()),
        }
    }

    #[test]
    fn no_group_membership_keeps_legacy_access() {
        assert!(actor(None).allows("domain:read"));
    }

    #[test]
    fn empty_group_permissions_grant_nothing() {
        assert!(!actor(Some(vec![])).allows("domain:read"));
    }

    #[test]
    fn explicit_permissions_and_wildcards_work() {
        let a = actor(Some(vec!["domain:read", "cache:*"]));
        assert!(a.allows("domain:read"));
        assert!(!a.allows("domain:write"));
        assert!(a.allows("cache:purge"));
        assert!(actor(Some(vec!["*"])).allows("anything:at:all"));
    }

    /// The extension path must not touch the database.
    ///
    /// The pool points at a closed port, so any accidental query fails the test
    /// instead of silently hitting a real database.
    #[tokio::test]
    async fn actor_is_reused_from_request_extensions() {
        use axum::body::Body;
        use axum::extract::FromRequestParts;
        use axum::http::Request;
        use sqlx::postgres::PgPoolOptions;

        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://nobody:nobody@127.0.0.1:1/none")
            .expect("lazy pool");
        let state = crate::state::AppState::new(pool, crate::config::AppConfig::load(), None);
        let actor = super::Actor {
            id: Uuid::new_v4(),
            email: "actor@example.test".into(),
            name: "actor".into(),
            is_admin: true,
            permissions: None,
        };
        let mut request = Request::builder().body(Body::empty()).unwrap();
        request.extensions_mut().insert(actor.clone());
        let (mut parts, _body) = request.into_parts();
        let resolved = super::Actor::from_request_parts(&mut parts, &state)
            .await
            .expect("the actor must come from the extension, not the DB");
        assert_eq!(resolved.id, actor.id);
        assert!(resolved.is_admin);
    }
}
