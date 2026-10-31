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
    pub tags: Option<Vec<String>>,
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
        let before = state.cache.len().await
            + state
                .large_cache
                .as_ref()
                .map(|cache| cache.len())
                .unwrap_or(0);
        state.cache.clear().await;
        if let Some(large) = state.large_cache.as_ref() {
            large.clear().await;
        }
        tracing::info!(domain = %req.domain, purged = before, "purge_all");
        return Json(EdgePurgeResponse {
            success: true,
            purged_count: before as u64,
            message: "cleared entire cache".into(),
        });
    }

    let mut patterns: Vec<String> = Vec::new();
    let mut had_pattern = false;
    if let Some(urls) = req.urls {
        for u in urls {
            if u.trim().is_empty() {
                continue;
            }
            had_pattern = true;
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
        for prefix in prefixes {
            if !prefix.trim().is_empty() {
                had_pattern = true;
                patterns.push(prefix);
            }
        }
    }
    let tags: Vec<String> = req
        .tags
        .unwrap_or_default()
        .into_iter()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();

    // Also match domain host in cache keys (key format: METHOD:host:path).
    // Do not turn a tag-only purge into a domain-wide purge.
    if had_pattern && !req.domain.is_empty() {
        patterns.push(req.domain.clone());
    }

    let mut n = 0u64;
    if !patterns.is_empty() {
        n += state.cache.purge_matching(&patterns).await;
        if let Some(large) = state.large_cache.as_ref() {
            n += large.purge_patterns(&patterns).await;
        }
    }
    if !tags.is_empty() {
        n += state.cache.purge_tags(&tags, &req.domain).await;
    }
    tracing::info!(domain = %req.domain, purged = n, patterns = ?patterns, tags = ?tags, "purge applied");

    Json(EdgePurgeResponse {
        success: true,
        purged_count: n,
        message: format!("purged {n} entries"),
    })
}
