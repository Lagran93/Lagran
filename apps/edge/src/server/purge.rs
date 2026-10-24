//! Edge-local purge API (called by control plane)

use crate::server::handler::AppState;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Deserialize)]
pub struct EdgePurgeRequest {
    pub domain: String,
    pub urls: Option<Vec<String>>,
    pub prefixes: Option<Vec<String>>,
    pub purge_all: Option<bool>,
}

#[derive(Serialize)]
pub struct EdgePurgeResponse {
    pub success: bool,
    pub purged_count: u64,
    pub message: String,
}

pub async fn purge_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EdgePurgeRequest>,
) -> Json<EdgePurgeResponse> {
    if req.purge_all.unwrap_or(false) {
        let before = state.cache.len().await;
        state.cache.clear().await;
        tracing::info!(domain = %req.domain, purged = before, "purge_all");
        return Json(EdgePurgeResponse {
            success: true,
            purged_count: before as u64,
            message: "cleared entire cache".into(),
        });
    }

    let mut patterns: Vec<String> = Vec::new();
    if let Some(urls) = req.urls {
        for u in urls {
            // extract path from URL if absolute
            if let Ok(parsed) = u.parse::<http::Uri>() {
                if let Some(pq) = parsed.path_and_query() {
                    patterns.push(pq.as_str().to_string());
                } else {
                    patterns.push(u);
                }
            } else {
                patterns.push(u);
            }
        }
    }
    if let Some(prefixes) = req.prefixes {
        patterns.extend(prefixes);
    }

    // Also match domain host in cache keys (key format: METHOD:host:path)
    if !req.domain.is_empty() {
        patterns.push(req.domain.clone());
    }

    let n = state.cache.purge_matching(&patterns).await;
    tracing::info!(domain = %req.domain, purged = n, patterns = ?patterns, "purge applied");

    Json(EdgePurgeResponse {
        success: true,
        purged_count: n,
        message: format!("purged {n} entries"),
    })
}
