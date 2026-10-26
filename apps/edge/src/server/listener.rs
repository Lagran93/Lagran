//! HTTP listener setup

use crate::server::agent_auth::RequireAgentToken;
use crate::server::challenge;
use crate::server::handler::{proxy_handler, AppState};
use crate::server::purge::{self, EdgePurgeRequest};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post, put},
    Json, Router,
};
use serde::Deserialize;
use std::sync::Arc;
use tower_http::trace::TraceLayer;

fn data_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/__lagran/health", get(health))
        .route("/__lagran/challenge/verify", get(challenge::verify))
        .route("/.well-known/acme-challenge/:token", get(acme_challenge))
}

fn management_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/__lagran/purge", post(purge_authed))
        .route("/__lagran/acme/challenge", put(put_challenge_authed))
        .route("/__lagran/certs/load", post(load_cert_authed))
        .route("/__lagran/access-logs", get(list_access_logs))
}

/// Legacy combined listener: data plane + management on the same port.
pub fn create_router(state: Arc<AppState>) -> Router {
    data_routes()
        .merge(management_routes())
        .fallback(proxy_handler)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Data/HTTP listener: CDN traffic, WAF challenge verify and ACME HTTP-01 only.
pub fn create_data_router(state: Arc<AppState>) -> Router {
    data_routes()
        .fallback(proxy_handler)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Control-plane management listener: purge/cert/challenge/access-log endpoints.
/// This listener must not be exposed to CDN clients.
pub fn create_admin_router(state: Arc<AppState>) -> Router {
    management_routes()
        .route("/__lagran/health", get(health))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

async fn list_access_logs(
    _auth: RequireAgentToken,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let entries = state.access_log.snapshot(200).await;
    Json(serde_json::json!({ "entries": entries })).into_response()
}

async fn purge_authed(
    _auth: RequireAgentToken,
    State(state): State<Arc<AppState>>,
    Json(req): Json<EdgePurgeRequest>,
) -> impl IntoResponse {
    purge::purge_handler(State(state), Json(req)).await
}

async fn put_challenge_authed(
    _auth: RequireAgentToken,
    State(state): State<Arc<AppState>>,
    Json(body): Json<ChallengeBody>,
) -> StatusCode {
    state.challenges.put(&body.token, &body.key_authorization);
    tracing::info!(token = %body.token, "ACME challenge installed");
    StatusCode::NO_CONTENT
}

async fn acme_challenge(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> impl IntoResponse {
    match state.challenges.get(&token) {
        Some(key_auth) => (StatusCode::OK, key_auth).into_response(),
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

#[derive(Deserialize)]
struct ChallengeBody {
    token: String,
    key_authorization: String,
}

#[derive(Deserialize)]
struct LoadCertBody {
    names: Vec<String>,
    cert_pem: String,
    key_pem: String,
}

async fn load_cert_authed(
    _auth: RequireAgentToken,
    State(state): State<Arc<AppState>>,
    Json(body): Json<LoadCertBody>,
) -> impl IntoResponse {
    match state.certs.upsert(
        &body.names,
        body.cert_pem.as_bytes(),
        body.key_pem.as_bytes(),
    ) {
        Ok(()) => {
            tracing::info!(names = ?body.names, "cert hot-loaded");
            (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}
