//! Route-level module permission enforcement.

use crate::middleware::authz::Actor;
use crate::permissions::required_for_path;
use crate::state::AppState;
use axum::{
    body::Body,
    extract::{FromRequestParts, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// Only these routes may bypass JWT module permissions using the edge agent
/// token. Do not trust the header on ordinary user routes: a logged-in user
/// could otherwise skip their group restrictions.
fn is_agent_endpoint(method: &str, path: &str) -> bool {
    match (method, path) {
        ("GET", "/api/v1/config") => true,
        ("GET", "/api/v1/schedule") => true,
        ("POST", "/api/v1/schedule/test") => true,
        ("POST", "/api/v1/nodes/heartbeat") => true,
        ("POST", "/api/v1/metrics/report") => true,
        ("POST", "/api/v1/metrics/report/batch") => true,
        ("GET", "/api/v1/certs/edge-sync") => true,
        ("POST", "/api/v1/access-logs/report") => true,
        ("POST", "/api/v1/config/apply-report") => true,
        ("GET", "/api/v1/cc/bans") | ("POST", "/api/v1/cc/bans") => true,
        ("POST", "/api/v1/waf/events") => true,
        ("GET", path) if path.starts_with("/api/v1/waf/rulepack/") => true,
        ("POST", "/api/v1/origin-health/report") => true,
        _ => {
            path.starts_with("/api/v1/certs/by-domain/")
                || (path.starts_with("/api/v1/nodes/") && path.ends_with("/heartbeat"))
        }
    }
}

pub async fn require_permission(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    let method = request.method().as_str().to_string();
    if method == "OPTIONS"
        || path.starts_with("/api/v1/auth/")
        || path == "/api/v1/system/donation"
        || (request.headers().contains_key("x-lagran-agent-token")
            && is_agent_endpoint(&method, &path))
    {
        return next.run(request).await;
    }
    let Some(permission) = required_for_path(&method, &path) else {
        return next.run(request).await;
    };

    let (mut parts, body) = request.into_parts();
    match Actor::from_request_parts(&mut parts, &state).await {
        Ok(actor) if actor.allows(permission) => {
            next.run(Request::from_parts(parts, body)).await
        }
        Ok(_) => (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": format!("permission denied: {permission}")
            })),
        )
            .into_response(),
        Err(error) => error.into_response(),
    }
}
