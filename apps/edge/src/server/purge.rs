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

    let domain = req.domain.trim();
    if domain.is_empty() {
        return Json(EdgePurgeResponse {
            success: false,
            purged_count: 0,
            message: "domain is required unless purge_all is set".into(),
        });
    }

    // Targets are host-and-path scoped. Appending the domain (the old
    // behaviour) turned every URL purge into a domain-wide purge, and a
    // substring match also hit other tenants.
    let mut targets: Vec<lagran_cache::PurgeTarget> = Vec::new();
    if let Some(urls) = req.urls {
        for u in urls {
            let raw = u.trim();
            if raw.is_empty() {
                continue;
            }
            let path = match raw.parse::<http::Uri>() {
                Ok(parsed) => parsed
                    .path_and_query()
                    .map(|pq| pq.as_str().to_string())
                    .unwrap_or_else(|| raw.to_string()),
                Err(_) => raw.to_string(),
            };
            if let Some(target) = lagran_cache::PurgeTarget::new(domain, &path, false) {
                targets.push(target);
            }
        }
    }
    if let Some(prefixes) = req.prefixes {
        for prefix in prefixes {
            let raw = prefix.trim();
            if raw.is_empty() {
                continue;
            }
            if let Some(target) = lagran_cache::PurgeTarget::new(domain, raw, true) {
                targets.push(target);
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

    let mut n = 0u64;
    if !targets.is_empty() {
        n += state.cache.purge_matching(&targets).await;
        if let Some(large) = state.large_cache.as_ref() {
            n += large.purge_targets(&targets).await;
        }
    }
    if !tags.is_empty() {
        n += state.cache.purge_tags(&tags, &req.domain).await;
    }
    tracing::info!(domain = %domain, purged = n, targets = ?targets, tags = ?tags, "purge applied");

    Json(EdgePurgeResponse {
        success: true,
        purged_count: n,
        message: format!("purged {n} entries"),
    })
}
