//! Edge-local live cache diagnostic.
//!
//! The control plane asks an online edge to execute this request locally. That
//! avoids depending on public DNS / hairpin NAT / TLS for a control-plane
//! diagnostics call while still exercising the real edge cache path.

use crate::server::handler::{proxy_handler, AppState};
use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderName, HeaderValue, Request, StatusCode},
    Json,
};
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

#[derive(Deserialize)]
pub struct EdgeDiagRequest {
    pub domain: String,
    pub path: String,
    pub scheme: Option<String>,
    #[serde(default)]
    pub simulate_cookie: bool,
    #[serde(default)]
    pub simulate_authorization: bool,
    pub request_cache_control: Option<String>,
    #[serde(default)]
    pub probe_range: bool,
}

#[derive(Serialize)]
pub struct EdgeDiagResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body_preview: String,
}

pub async fn diag_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EdgeDiagRequest>,
) -> Json<EdgeDiagResponse> {
    let domain = req.domain.trim().to_ascii_lowercase();
    let mut path = req.path.trim().to_string();
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    if domain.is_empty()
        || path.contains('\r')
        || path.contains('\n')
        || path.starts_with("/__lagran/")
    {
        return Json(EdgeDiagResponse {
            status: StatusCode::BAD_REQUEST.as_u16(),
            headers: vec![],
            body_preview: "invalid diagnostic request".into(),
        });
    }

    let mut builder = Request::builder()
        .method("GET")
        .uri(&path)
        .header(header::HOST, &domain)
        .header(header::USER_AGENT, "lagran-cache-diagnose/1.0");
    if req.simulate_cookie {
        builder = builder.header(header::COOKIE, "lagran_debug=1");
    }
    if req.simulate_authorization {
        builder = builder.header(header::AUTHORIZATION, "Bearer lagran-diagnostic");
    }
    if let Some(cc) = req
        .request_cache_control
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        builder = builder.header(header::CACHE_CONTROL, cc);
    }
    if req.probe_range {
        // Large video/stream probes must not download the whole object. One
        // byte is enough to exercise the real cache/range path.
        builder = builder.header(header::RANGE, "bytes=0-0");
    }
    let mut request = match builder.body(Body::empty()) {
        Ok(request) => request,
        Err(_) => {
            return Json(EdgeDiagResponse {
                status: StatusCode::BAD_REQUEST.as_u16(),
                headers: vec![],
                body_preview: "invalid diagnostic request".into(),
            })
        }
    };
    let is_https = req
        .scheme
        .as_deref()
        .map(|v| v.eq_ignore_ascii_case("https"))
        .unwrap_or(true);
    if is_https {
        // The in-process data path normally receives this marker from the TLS
        // listener; without it a domain with HTTPS enforcement would answer
        // 301 before WAF/cache and look like an un-cacheable response.
        request
            .extensions_mut()
            .insert(crate::server::host_util::TlsSni(domain.clone()));
        request.headers_mut().insert(
            HeaderName::from_static("x-forwarded-proto"),
            HeaderValue::from_static("https"),
        );
    }

    let response = match tokio::time::timeout(
        Duration::from_secs(10),
        proxy_handler(State(state), request),
    )
    .await
    {
        Ok(response) => response,
        Err(_) => {
            return Json(EdgeDiagResponse {
                status: StatusCode::GATEWAY_TIMEOUT.as_u16(),
                headers: vec![],
                body_preview: "cache diagnostic timed out after 10s (large origin response?)"
                    .into(),
            })
        }
    };
    let status = response.status().as_u16();
    let selected = [
        "x-cache",
        "x-cache-status",
        "x-lagran-cache-reason",
        "age",
        "etag",
        "cache-control",
        "vary",
        "content-type",
        "server",
    ];
    let mut headers = Vec::new();
    for name in selected {
        if let Some(value) = response.headers().get(name).and_then(|v| v.to_str().ok()) {
            headers.push((name.to_string(), value.to_string()));
        }
    }

    let mut body = response.into_body();
    let mut preview = Vec::new();
    while preview.len() < 300 {
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    let take = data.len().min(300 - preview.len());
                    preview.extend_from_slice(&data[..take]);
                }
            }
            Some(Err(_)) | None => break,
        }
    }

    Json(EdgeDiagResponse {
        status,
        headers,
        body_preview: String::from_utf8_lossy(&preview).to_string(),
    })
}
