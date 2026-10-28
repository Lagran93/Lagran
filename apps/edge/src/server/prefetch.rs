//! Internal cache warming endpoint used by the control-plane prefetch worker.

use crate::server::handler::{proxy_handler, AppState};
use axum::{body::Body, extract::State, http::Request, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Deserialize)]
pub struct EdgePrefetchRequest {
    pub domain: String,
    pub paths: Vec<String>,
}

#[derive(Serialize)]
pub struct EdgePrefetchResponse {
    pub success: bool,
    pub warmed: usize,
    pub failed: usize,
    pub message: String,
}

pub async fn prefetch_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EdgePrefetchRequest>,
) -> Json<EdgePrefetchResponse> {
    let domain = req.domain.trim().to_ascii_lowercase();
    if domain.is_empty() {
        return Json(EdgePrefetchResponse {
            success: false,
            warmed: 0,
            failed: req.paths.len(),
            message: "domain is required".into(),
        });
    }
    let mut warmed = 0;
    let mut failed = 0;
    for raw in req.paths {
        let mut path = raw.trim().to_string();
        if path.is_empty() {
            continue;
        }
        if !path.starts_with('/') {
            path.insert(0, '/');
        }
        let request = match Request::builder()
            .method("GET")
            .uri(&path)
            .header("host", &domain)
            .header("user-agent", "lagran-prefetch/1.0")
            .body(Body::empty())
        {
            Ok(request) => request,
            Err(_) => {
                failed += 1;
                continue;
            }
        };
        let response = proxy_handler(State(state.clone()), request).await;
        let status = response.status();
        if status.is_success() || status == axum::http::StatusCode::NOT_MODIFIED {
            warmed += 1;
        } else {
            failed += 1;
            tracing::warn!(%domain, %path, %status, "prefetch request failed");
        }
    }
    Json(EdgePrefetchResponse {
        success: failed == 0,
        warmed,
        failed,
        message: format!("warmed {warmed} path(s), failed {failed}"),
    })
}
