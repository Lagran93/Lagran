//! HTTP API routes — nest("/api/v1", ...) + path params :name

pub mod access_log;
pub mod acme;
pub mod audit;
pub mod auth;
pub mod cc;
pub mod cert;
pub mod config;
pub mod dns_test;
pub mod domain;
pub mod health;
pub mod health_origin;
pub mod metrics;
pub mod node;
pub mod prefetch;
pub mod project;
pub mod purge;
pub mod rule;
pub mod stats;
pub mod waf;

use crate::state::AppState;
use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
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
                .route("/projects", get(project::list).post(project::create))
                .route("/projects/:id", get(project::get).delete(project::delete))
                .route("/projects/:id/domains", get(project::list_domains))
                .route(
                    "/projects/:id/members",
                    get(project::list_members).post(project::add_member),
                )
                .route(
                    "/projects/:id/members/:user_id",
                    delete(project::remove_member),
                )
                .route("/domains", get(domain::list).post(domain::create))
                .route("/origin-health", get(health_origin::list))
                .route("/origin-health/report", post(health_origin::report))
                .route(
                    "/domains/:id",
                    get(domain::get).put(domain::update).delete(domain::delete),
                )
                .route(
                    "/domains/:id/settings",
                    get(domain::get_settings).put(domain::put_settings),
                )
                .route("/domains/:id/status", post(domain::set_status))
                .route("/rules", get(rule::list).post(rule::create))
                .route("/rules/test", post(rule::test))
                .route("/rules/:id", put(rule::update).delete(rule::delete))
                .route(
                    "/domains/:id/waf",
                    get(waf::get_settings).put(waf::put_settings),
                )
                .route(
                    "/domains/:id/waf/rules",
                    get(waf::list_rules).post(waf::create_rule),
                )
                .route(
                    "/waf/rules/:id",
                    put(waf::update_rule).delete(waf::delete_rule),
                )
                .route(
                    "/domains/:id/waf/ips",
                    get(waf::list_ips).post(waf::create_ip),
                )
                .route("/waf/ips/:id", delete(waf::delete_ip))
                .route(
                    "/waf/events",
                    get(waf::list_events).post(waf::report_events),
                )
                .route("/waf/stats", get(waf::stats))
                .route("/schedule", get(crate::scheduler::resolve_agent))
                .route("/schedule/test", post(crate::scheduler::test))
                .route("/dns/test", post(dns_test::test))
                .route("/nodes", get(node::list).post(node::create))
                .route(
                    "/nodes/:id",
                    get(node::detail).put(node::update).delete(node::delete),
                )
                .route("/nodes/:id/status", post(node::set_status))
                .route("/nodes/heartbeat", post(node::heartbeat))
                .route("/nodes/:id/heartbeat", post(node::heartbeat_by_path))
                .route("/metrics/report", post(metrics::report))
                .route("/certs", get(cert::list).post(cert::create))
                .route("/certs/issue", post(acme::issue))
                .route("/certs/:id", get(cert::get).delete(cert::delete))
                .route("/certs/by-domain/:domain", get(cert::edge_get))
                .route("/certs/edge-sync", get(cert::edge_list_active))
                .route("/purge", post(purge::purge))
                .route("/prefetch", get(prefetch::list).post(prefetch::create))
                .route("/stats/by-domain", get(stats::by_domain))
                .route("/stats/summary", get(stats::summary))
                .route("/audit", get(audit::list))
                .route("/access-logs", get(access_log::list))
                .route("/access-logs/report", post(access_log::report))
                .route("/config", get(config::list_all_configs))
                .route("/config/:domain", get(config::get_domain_config))
                .route("/cc/bans", get(cc::list).post(cc::report))
                .route("/cc/bans/all", get(cc::list_admin))
                .route("/cc/bans/:domain/:ip", delete(cc::remove)),
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
