//! Internal cache warming endpoint used by the control-plane prefetch worker.

use crate::server::handler::AppState;
use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, Method},
    Json,
};
use http_body_util::BodyExt;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Deserialize)]
pub struct EdgePrefetchRequest {
    pub domain: String,
    pub paths: Vec<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
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
    let scheme = match state.domains.get(&domain).await {
        Some(entry) if entry.ssl_enabled => "https",
        _ => "http",
    };
    for raw in req.paths {
        let mut path = raw.trim().to_string();
        if path.is_empty() {
            continue;
        }
        if !path.starts_with('/') {
            path.insert(0, '/');
        }
        let base = format!("http://{}", state.local_http_addr);
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            match HeaderValue::from_str(&domain) {
                Ok(value) => value,
                Err(_) => {
                    failed += 1;
                    continue;
                }
            },
        );
        headers.insert(
            "x-forwarded-proto",
            HeaderValue::from_static(if scheme == "https" { "https" } else { "http" }),
        );
        headers.insert(
            "user-agent",
            HeaderValue::from_static("lagran-prefetch/1.0"),
        );
        headers.insert("x-lagran-prefetch", HeaderValue::from_static("1"));
        headers.insert("accept-encoding", HeaderValue::from_static("identity"));
        for (name, value) in &req.headers {
            let name = name.trim().to_ascii_lowercase();
            if !matches!(name.as_str(), "accept-language" | "origin") {
                continue;
            }
            let (Ok(name), Ok(value)) = (
                axum::http::HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) else {
                continue;
            };
            headers.insert(name, value);
        }

        // Go through the public Pingora listener so the same native cache,
        // Range and large-cache path is used as a real client request. Calling
        // proxy_handler directly bypassed that path and hit the legacy body
        // limit for large objects.
        let origin = match state
            .origin
            .request_stream_with_sni(&base, &Method::GET, &path, &headers, None, true, None)
            .await
        {
            Ok(response) => response,
            Err(e) => {
                failed += 1;
                tracing::warn!(%domain, %path, error = %e, "prefetch request failed");
                continue;
            }
        };
        let status = origin.status;
        let content_length = origin
            .headers
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        let size_cacheable = content_length
            .map(|length| {
                length <= state.max_cacheable_body as u64
                    || state
                        .large_cache
                        .as_ref()
                        .is_some_and(|large| large.accepts(length))
            })
            .unwrap_or(true);
        if !(status.is_success() || status == axum::http::StatusCode::NOT_MODIFIED)
            || !size_cacheable
        {
            failed += 1;
            tracing::warn!(
                %domain,
                %path,
                %status,
                content_length,
                size_cacheable,
                "prefetch request failed"
            );
            // Dropping the body cancels the local stream, avoiding a
            // pointless multi-GB download for an object neither cache can
            // accept.
            continue;
        }
        warmed += 1;
        // Drain the body so the data plane completes and can commit cache
        // entries. Never buffer the full object in the prefetch worker.
        let mut body = origin.body;
        while let Some(frame) = body.frame().await {
            if frame.is_err() {
                break;
            }
        }
    }
    Json(EdgePrefetchResponse {
        success: failed == 0,
        warmed,
        failed,
        message: format!("warmed {warmed} path(s), failed {failed}"),
    })
}
