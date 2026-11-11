//! HTTP API routes — nest("/api/v1", ...) + path params :name

pub mod access_log;
pub mod acme;
pub mod alert;
pub mod audit;
pub mod auth;
pub mod cache_diag;
pub mod cc;
pub mod cert;
pub mod config;
pub mod config_release;
pub mod dns_test;
pub mod domain;
pub mod domain_diag;
pub mod edge_endpoints;
pub mod group;
pub mod health;
pub mod health_origin;
pub mod login_log;
pub mod metrics;
pub mod node;
pub mod prefetch;
pub mod project;
pub mod purge;
pub mod rule;
pub mod stats;
pub mod system;
pub mod user;
pub mod waf;

use crate::state::AppState;
use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use serde_json::json;
use tower_http::cors::{Any, CorsLayer};
use tower_http::decompression::RequestDecompressionLayer;
use tracing::Instrument;

pub fn create_router(state: AppState) -> Router {
    let cors = build_cors(&state.config.cors_allowed_origins);

    Router::new()
        .route("/health", get(health::health))
        .route("/metrics", get(health::metrics))
        .route("/.well-known/acme-challenge/:token", get(acme::challenge))
        .route("/ready", get(health::ready))
        .nest(
            "/api/v1",
            Router::new()
                .route("/auth/login", post(auth::login))
                .route("/auth/register", post(auth::register))
                .route("/auth/config", get(auth::public_config))
                .route("/auth/captcha", get(auth::captcha))
                .route("/auth/me", get(auth::me).put(auth::update_me))
                .route("/auth/me/password", put(auth::change_password))
                .route("/system/donation", get(system::donation))
                .route(
                    "/system/update",
                    get(system::check_update).post(system::apply_update),
                )
                .route("/system/update/status", get(system::update_status))
                .route("/users", get(user::list).post(user::create))
                .route(
                    "/users/:id",
                    get(user::get).put(user::update).delete(user::delete),
                )
                .route("/users/:id/password", put(user::reset_password))
                .route("/groups", get(group::list).post(group::create))
                .route(
                    "/groups/:id",
                    get(group::get).put(group::update).delete(group::delete),
                )
                .route(
                    "/groups/:id/members",
                    get(group::members).put(group::set_members),
                )
                .route("/projects", get(project::list).post(project::create))
                .route("/projects/:id", get(project::get).delete(project::delete))
                .route("/projects/:id/domains", get(project::list_domains))
                .route(
                    "/projects/:id/members",
                    get(project::list_members).post(project::add_member),
                )
                .route(
                    "/projects/:id/members/:user_id",
                    put(project::update_member).delete(project::remove_member),
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
                .route("/domains/:id/signed-url", post(domain::create_signed_url))
                .route("/domains/:id/signed-url/rotate", post(domain::rotate_signed_url))
                .route("/domains/:id/diagnose", post(domain_diag::diagnose))
                .route("/edge-endpoints", get(edge_endpoints::list))
                .route("/rules", get(rule::list).post(rule::create))
                .route("/rules/test", post(rule::test))
                .route("/cache/diagnose", post(cache_diag::diagnose))
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
                .route(
                    "/waf/ips/:id",
                    put(waf::update_ip).delete(waf::delete_ip),
                )
                .route(
                    "/domains/:id/waf/geo",
                    get(waf::list_geo).post(waf::create_geo),
                )
                .route(
                    "/waf/geo/:id",
                    put(waf::update_geo).delete(waf::delete_geo),
                )
                .route("/waf/rulesets", get(waf::list_rulesets))
                .route("/waf/rulepacks", get(waf::list_rulepacks))
                .route("/waf/rulepacks/publish", post(waf::publish_rulepack))
                .route(
                    "/waf/rulepacks/:version/rollback",
                    post(waf::rollback_rulepack),
                )
                .route(
                    "/waf/rulepacks/:version/retire",
                    post(waf::retire_rulepack),
                )
                .route("/waf/rulepacks/:version", delete(waf::delete_rulepack))
                .route("/waf/rulepack/:version", get(waf::download_rulepack))
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
                .route("/nodes/:id/upgrade", post(node::upgrade))
                .route("/nodes/heartbeat", post(node::heartbeat))
                .route("/nodes/:id/heartbeat", post(node::heartbeat_by_path))
                .route("/metrics/report", post(metrics::report))
                .route("/metrics/report/batch", post(metrics::report_batch))
                .route("/certs", get(cert::list).post(cert::create))
                .route("/certs/issue", post(acme::issue))
                .route("/certs/:id", get(cert::get).delete(cert::delete))
                .route("/certs/by-domain/:domain", get(cert::edge_get))
                .route("/certs/edge-sync", get(cert::edge_list_active))
                .route("/purge", post(purge::purge))
                .route("/prefetch", get(prefetch::list).post(prefetch::create))
                .route("/prefetch/tasks", get(prefetch::list_tasks))
                .route(
                    "/prefetch/schedules",
                    get(prefetch::list_schedules).post(prefetch::create_schedule),
                )
                .route(
                    "/prefetch/schedules/:id",
                    put(prefetch::update_schedule).delete(prefetch::delete_schedule),
                )
                .route("/stats/by-domain", get(stats::by_domain))
                .route("/stats/by-node", get(stats::by_node))
                .route("/stats/timeseries", get(stats::timeseries))
                .route("/stats/realtime", get(stats::realtime))
                .route("/stats/summary", get(stats::summary))
                .route("/audit", get(audit::list))
                .route("/login-logs", get(login_log::list))
                .route(
                    "/alert-channels",
                    get(alert::list_channels).post(alert::create_channel),
                )
                .route(
                    "/alert-channels/:id",
                    put(alert::update_channel).delete(alert::delete_channel),
                )
                .route("/alert-channels/:id/test", post(alert::test_channel))
                .route(
                    "/alert-rules",
                    get(alert::list_rules).post(alert::create_rule),
                )
                .route(
                    "/alert-rules/:id",
                    put(alert::update_rule).delete(alert::delete_rule),
                )
                .route("/alert-events", get(alert::list_events))
                .route("/alerts/summary", get(alert::summary))
                .route("/access-logs", get(access_log::list))
                .route("/access-logs/report", post(access_log::report))
                .route("/config", get(config::list_all_configs))
                .route("/config/versions", get(config_release::list_versions))
                .route("/config/versions/:id", get(config_release::get_version))
                .route(
                    "/config/versions/:id/rollback",
                    post(config_release::rollback_version),
                )
                .route(
                    "/config/domains/:domain/versions",
                    post(config_release::snapshot_now),
                )
                .route(
                    "/config/releases",
                    get(config_release::list_releases).post(config_release::create_release),
                )
                .route("/config/releases/:id", get(config_release::get_release))
                .route(
                    "/config/releases/:id/approve",
                    post(config_release::approve_release),
                )
                .route(
                    "/config/releases/:id/publish",
                    post(config_release::publish_release),
                )
                .route(
                    "/config/releases/:id/rollback",
                    post(config_release::rollback_release),
                )
                .route(
                    "/config/releases/:id/dry-run",
                    post(config_release::dry_run),
                )
                .route("/config/apply-report", post(config_release::apply_report))
                .route("/config/:domain", get(config::get_domain_config))
                .route("/cc/bans", get(cc::list).post(cc::report))
                .route("/cc/bans/all", get(cc::list_admin))
                .route("/cc/bans/history", get(cc::list_history))
                .route("/cc/bans/manual", post(cc::create_manual))
                .route("/cc/bans/unban", post(cc::unban_manual))
                .route("/cc/stats", get(cc::stats))
                .route("/cc/bans/:domain/:ip", delete(cc::remove)),
        )
        .fallback(not_found)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::permission::require_permission,
        ))
        .layer(axum::middleware::from_fn(trace_http_request))
        .layer(RequestDecompressionLayer::new())
        .layer(cors)
        .with_state(state)
}

/// Build the CORS layer.
///
/// The console authenticates with a bearer token rather than a cookie, so a
/// browser never attaches credentials implicitly and classic CSRF does not apply.
/// `Any` is therefore not an exploitable hole, but it does let any web page talk
/// to this API if it ever learns a token, and it hides the origin policy from
/// reviewers. Deployments that serve the console from the API origin do not use
/// CORS at all, so an empty list keeps working: it preserves the previous
/// behaviour and lets operators tighten it with `CORS_ALLOWED_ORIGINS`.
fn build_cors(allowed: &[String]) -> CorsLayer {
    let base = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any);
    if allowed.is_empty() {
        return base.allow_origin(Any);
    }
    let origins: Vec<axum::http::HeaderValue> = allowed
        .iter()
        // `HeaderValue::from_str` rejects CR/LF and other non-ASCII bytes, so a
        // malformed entry can never be used for header injection.
        .filter_map(|origin| match axum::http::HeaderValue::from_str(origin.trim()) {
            Ok(value) => Some(value),
            Err(_) => {
                tracing::warn!(origin = %origin, "ignoring invalid CORS_ALLOWED_ORIGINS entry");
                None
            }
        })
        .collect();
    if origins.is_empty() {
        // Every entry was invalid: fail closed rather than silently opening up.
        tracing::error!("CORS_ALLOWED_ORIGINS contains no valid origin; cross-origin requests are denied");
        return base.allow_origin(Vec::<axum::http::HeaderValue>::new());
    }
    base.allow_origin(origins)
}

async fn trace_http_request(request: Request<Body>, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let span = tracing::info_span!(
        "http.request",
        "otel.kind" = "server",
        http.method = %method,
        url.path = %path,
        http.status_code = tracing::field::Empty
    );
    let started = std::time::Instant::now();
    let response = next.run(request).instrument(span.clone()).await;
    span.record("http.status_code", response.status().as_u16());
    tracing::info!(
        parent: &span,
        latency_ms = started.elapsed().as_millis() as u64,
        "http request completed"
    );
    response
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{header, Request};
    use tower::util::ServiceExt;

    async fn cors_headers(allowed: Vec<String>, origin: &str) -> Option<String> {
        // A minimal router: the CORS layer is what is under test, not the API.
        let app = Router::new()
            .route("/ping", get(|| async { "pong" }))
            .layer(build_cors(&allowed));
        let request = Request::builder()
            .method("GET")
            .uri("/ping")
            .header(header::ORIGIN, origin)
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    }

    /// An empty list keeps the previous behaviour: the response echoes the
    /// request origin, so existing deployments are unaffected.
    #[tokio::test]
    async fn empty_allowlist_preserves_open_default() {
        let allow = cors_headers(vec![], "https://anything.test").await;
        assert_eq!(allow.as_deref(), Some("*"));
    }

    /// A configured allowlist echoes only the configured origin.
    #[tokio::test]
    async fn configured_origin_is_allowed() {
        let allow = cors_headers(
            vec!["https://console.example.com".to_string()],
            "https://console.example.com",
        )
        .await;
        assert_eq!(allow.as_deref(), Some("https://console.example.com"));
    }

    /// A non-configured origin must not be granted access.
    #[tokio::test]
    async fn unlisted_origin_is_not_allowed() {
        let allow = cors_headers(
            vec!["https://console.example.com".to_string()],
            "https://evil.test",
        )
        .await;
        assert!(
            allow.is_none() || allow.as_deref() != Some("https://evil.test"),
            "unlisted origin must not be echoed back"
        );
    }

    /// An entry that is not a valid header value is dropped rather than injected.
    #[tokio::test]
    async fn invalid_origin_entries_are_dropped() {
        let allow = cors_headers(
            vec![
                "https://ok.example.com".to_string(),
                "bad\r\nX-Injected: 1".to_string(),
            ],
            "https://ok.example.com",
        )
        .await;
        assert_eq!(allow.as_deref(), Some("https://ok.example.com"));
    }

    /// If every entry is invalid, fail closed instead of widening access.
    #[tokio::test]
    async fn all_invalid_entries_fail_closed() {
        let allow = cors_headers(vec!["not an origin".to_string()], "https://evil.test").await;
        assert!(allow.is_none(), "must not grant any origin: {allow:?}");
    }
}
