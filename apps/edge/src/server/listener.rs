//! HTTP listener setup

use crate::server::agent_auth::RequireAgentToken;
use crate::server::handler::AppState;
use crate::server::purge::{self, EdgePurgeRequest};use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post, put},
    Json, Router,
};
use serde::Deserialize;
use std::sync::Arc;
use tower_http::trace::TraceLayer;

fn management_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/__lagran/purge", post(purge_authed))
        .route("/__lagran/prefetch", post(prefetch_authed))
        .route("/__lagran/cache-diagnose", post(cache_diag_authed))
        .route("/__lagran/acme/challenge", put(put_challenge_authed))
        .route("/__lagran/certs/load", post(load_cert_authed))
        .route("/__lagran/access-logs", get(list_access_logs))
        .route("/__lagran/config/reload", post(config_reload_authed))
        .route("/__lagran/update", post(update_authed))
        .route("/__lagran/metrics", get(prometheus_metrics))
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

async fn prefetch_authed(
    _auth: RequireAgentToken,
    State(state): State<Arc<AppState>>,
    Json(req): Json<crate::server::prefetch::EdgePrefetchRequest>,
) -> impl IntoResponse {
    crate::server::prefetch::prefetch_handler(State(state), Json(req)).await
}

async fn cache_diag_authed(
    _auth: RequireAgentToken,
    State(state): State<Arc<AppState>>,
    Json(req): Json<crate::server::cache_diag::EdgeDiagRequest>,
) -> impl IntoResponse {
    crate::server::cache_diag::diag_handler(State(state), Json(req)).await
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

async fn config_reload_authed(_auth: RequireAgentToken) -> impl IntoResponse {
    crate::agent::config_sync::request_config_reload();
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "reloading": true })),
    )
        .into_response()
}

#[derive(Deserialize)]
struct EdgeUpdateBody {
    version: String,
}

async fn update_authed(
    _auth: RequireAgentToken,
    Json(body): Json<EdgeUpdateBody>,
) -> impl IntoResponse {
    if !crate::pingora_edge::valid_release_tag(&body.version) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid release version" })),
        )
            .into_response();
    }
    if !crate::pingora_edge::edge_update_helper_installed() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "edge updater is not installed; re-run install.sh edge"
            })),
        )
            .into_response();
    }
    if let Err(error) = crate::pingora_edge::queue_edge_update(&body.version) {
        tracing::error!(error = %error, "queue edge update failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("cannot queue update: {error}") })),
        )
            .into_response();
    }
    tracing::info!(version = %body.version, "edge update queued");
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "queued": true,
            "version": body.version,
            "message": "edge updater will download, verify and restart the service"
        })),
    )
        .into_response()
}

async fn prometheus_metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let snaps = state.metrics.take_snapshots_peek();
    let mut out = String::from(
        "# HELP lagran_edge_up Edge process up\n# TYPE lagran_edge_up gauge\nlagran_edge_up 1\n\
         # HELP lagran_edge_domains Domains with traffic counters\n# TYPE lagran_edge_domains gauge\n\
         # HELP lagran_edge_requests_total Requests handled\n# TYPE lagran_edge_requests_total counter\n",
    );
    let mut hits = String::from(
        "# HELP lagran_edge_cache_hits_total Cache hits\n# TYPE lagran_edge_cache_hits_total counter\n",
    );
    let mut misses = String::from(
        "# HELP lagran_edge_cache_misses_total Cache misses\n# TYPE lagran_edge_cache_misses_total counter\n",
    );
    let mut bytes = String::from(
        "# HELP lagran_edge_bytes_sent_total Bytes sent\n# TYPE lagran_edge_bytes_sent_total counter\n",
    );
    for s in &snaps {
        let d = s.domain.replace('\\', "\\\\").replace('"', "");
        out.push_str(&format!(
            "lagran_edge_requests_total{{domain=\"{d}\"}} {}\n",
            s.requests
        ));
        hits.push_str(&format!(
            "lagran_edge_cache_hits_total{{domain=\"{d}\"}} {}\n",
            s.cache_hits
        ));
        misses.push_str(&format!(
            "lagran_edge_cache_misses_total{{domain=\"{d}\"}} {}\n",
            s.cache_misses
        ));
        bytes.push_str(&format!(
            "lagran_edge_bytes_sent_total{{domain=\"{d}\"}} {}\n",
            s.bytes_sent
        ));
    }
    out.push_str(&hits);
    out.push_str(&misses);
    out.push_str(&bytes);
    let global = state.metrics.global_snapshot();
    out.push_str(&format!(
        "# HELP lagran_edge_origin_timeouts_total Origin connect/header timeouts\n\
         # TYPE lagran_edge_origin_timeouts_total counter\n\
         lagran_edge_origin_timeouts_total {}\n\
         # HELP lagran_edge_origin_errors_total Origin failures\n\
         # TYPE lagran_edge_origin_errors_total counter\n\
         lagran_edge_origin_errors_total {}\n\
         # HELP lagran_edge_origin_stream_requests_total Streaming origin responses\n\
         # TYPE lagran_edge_origin_stream_requests_total counter\n\
         lagran_edge_origin_stream_requests_total {}\n\
         # HELP lagran_edge_origin_stream_bytes_total Streaming bytes proxied\n\
         # TYPE lagran_edge_origin_stream_bytes_total counter\n\
         lagran_edge_origin_stream_bytes_total {}\n\
         # HELP lagran_edge_origin_stream_errors_total Streaming body errors\n\
         # TYPE lagran_edge_origin_stream_errors_total counter\n\
         lagran_edge_origin_stream_errors_total {}\n\
         # HELP lagran_edge_datapath_pingora_total Requests handled by Pingora\n\
         # TYPE lagran_edge_datapath_pingora_total counter\n\
         lagran_edge_datapath_pingora_total {}\n\
         # HELP lagran_edge_datapath_legacy_total Requests handled by legacy\n\
         # TYPE lagran_edge_datapath_legacy_total counter\n\
         lagran_edge_datapath_legacy_total {}\n",
        global.origin_timeouts,
        global.origin_errors,
        global.stream_requests,
        global.stream_bytes,
        global.stream_errors,
        global.datapath_pingora,
        global.datapath_legacy
    ));
    out.push_str(&format!("lagran_edge_domains {}\n", snaps.len()));
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        out,
    )
}
