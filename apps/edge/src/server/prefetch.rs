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
        let first = match state
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
        let status = first.status;
        let content_length = first
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

        let range_limit = state.range_fill_max_bytes.max(1024 * 1024);
        let use_range = state.large_cache.is_some()
            && (content_length.is_none()
                || content_length.is_some_and(|length| length > range_limit))
            && (status.is_success() || status == axum::http::StatusCode::NOT_MODIFIED);

        let mut origin = first;
        if use_range {
            drop(origin);
            let end = content_length
                .map(|length| length.saturating_sub(1).min(range_limit.saturating_sub(1)))
                .unwrap_or_else(|| range_limit.saturating_sub(1));
            let mut range_headers = headers.clone();
            range_headers.insert(
                "range",
                match HeaderValue::from_str(&format!("bytes=0-{end}")) {
                    Ok(value) => value,
                    Err(_) => {
                        failed += 1;
                        continue;
                    }
                },
            );
            origin = match state
                .origin
                .request_stream_with_sni(
                    &base,
                    &Method::GET,
                    &path,
                    &range_headers,
                    None,
                    true,
                    None,
                )
                .await
            {
                Ok(response) => response,
                Err(e) => {
                    failed += 1;
                    tracing::warn!(%domain, %path, error = %e, "prefetch range request failed");
                    continue;
                }
            };
        }

        let status = origin.status;
        if !(status.is_success() || status == axum::http::StatusCode::NOT_MODIFIED)
            || (!use_range && !size_cacheable)
        {
            failed += 1;
            tracing::warn!(
                %domain,
                %path,
                %status,
                content_length,
                size_cacheable,
                use_range,
                "prefetch request failed"
            );
            continue;
        }
        warmed += 1;
        tracing::info!(
            %domain,
            %path,
            content_length,
            use_range,
            range_limit,
            status = %origin.status,
            "prefetch warmed"
        );
        let mut body = origin.body;
        let mut received = 0u64;
        while let Some(frame) = body.frame().await {
            let Ok(frame) = frame else {
                break;
            };
            if let Some(data) = frame.data_ref() {
                received += data.len() as u64;
                if use_range && received > range_limit.saturating_add(1024 * 1024) {
                    tracing::warn!(%domain, %path, received, "prefetch range body exceeded limit");
                    break;
                }
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
