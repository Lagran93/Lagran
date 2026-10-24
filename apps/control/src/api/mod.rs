//! HTTP API routes — nest("/api/v1", ...) + Axum 0.7

pub mod acme;
pub mod auth;
pub mod cert;
pub mod config;
pub mod domain;
pub mod health;
pub mod metrics;
pub mod node;
pub mod purge;
pub mod rule;
pub mod stats;

use crate::state::AppState;
use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/health", get(health::health))
        .route("/.well-known/acme-challenge/:token", get(acme::challenge))
        .route("/ready", get(health::ready))
        .nest(
            "/api/v1",
            Router::new()
                .route("/auth/login", post(auth::login))
                .route("/auth/register", post(auth::register))
                .route("/auth/me", get(auth::me))
                .route("/domains", get(domain::list).post(domain::create))
                .route(
                    "/domains/:id",
                    get(domain::get).put(domain::update).delete(domain::delete),
                )
                .route("/rules", get(rule::list).post(rule::create))
                .route("/rules/:id", axum::routing::delete(rule::delete))
                .route("/nodes", get(node::list))
                .route("/nodes/heartbeat", post(node::heartbeat))
                .route("/nodes/:id/heartbeat", post(node::heartbeat_by_path))
                .route("/metrics/report", post(metrics::report))
                .route("/certs", get(cert::list).post(cert::create))
                .route("/certs/issue", post(acme::issue))
                .route("/certs/:id", get(cert::get).delete(cert::delete))
                .route("/certs/by-domain/:domain", get(cert::edge_get))
                .route("/purge", post(purge::purge))
                .route("/stats/summary", get(stats::summary))
                .route("/config", get(config::list_all_configs))
                .route("/config/:domain", get(config::get_domain_config)),
        )
        .fallback(not_found)
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

async fn not_found(req: Request<Body>) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    tracing::warn!(%method, %uri, "no route matched");
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error": "not found",
            "method": method.as_str(),
            "path": uri.path(),
        })),
    )
        .into_response()
}
