//! Edge-local live cache diagnostic.
//!
//! The control plane asks an online edge to execute this request locally. That
//! avoids depending on public DNS / hairpin NAT / TLS for a control-plane
//! diagnostics call while still exercising the real edge cache path.
//!
//! 阶段 5: the diagnostic used to call `proxy_handler` directly, which measured
//! the *legacy* in-process engine rather than the production Pingora data plane.
//! It now sends a real HTTP request to the loopback public listener (same trick
//! as `server/prefetch.rs`), so the reported status/headers reflect exactly what
//! a client would get: native cache, Range/large-cache, HTTPS redirect and the
//! preflight (WAF/CC/rate-limit).

use crate::server::handler::AppState;
use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
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

fn bad_request(message: &str) -> Json<EdgeDiagResponse> {
    Json(EdgeDiagResponse {
        status: StatusCode::BAD_REQUEST.as_u16(),
        headers: vec![],
        body_preview: message.into(),
    })
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
        return bad_request("invalid diagnostic request");
    }

    // Scheme decides the `X-Forwarded-Proto` the loopback listener sees: with
    // `https` an HTTPS-enforcing domain goes through the cache path, with `http`
    // it shows the 301 redirect a real plaintext client would receive.
    let is_https = req
        .scheme
        .as_deref()
        .map(|v| v.eq_ignore_ascii_case("https"))
        .unwrap_or(true);
    let proto = if is_https { "https" } else { "http" };

    let mut headers = HeaderMap::new();
    let Ok(host) = HeaderValue::from_str(&domain) else {
        return bad_request("invalid diagnostic request");
    };
    headers.insert(header::HOST, host);
    headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static(proto),
    );
    headers.insert(
        header::USER_AGENT,
        HeaderValue::from_static("lagran-cache-diagnose/1.0"),
    );
    // Prove to `prepare_proxy_headers` that this loopback request is the Edge's
    // own diagnostic, so the simulated scheme (`x-forwarded-proto`) is honoured
    // while the full preflight (WAF/CC/rate-limit) still runs.
    headers.insert(
        HeaderName::from_static("x-lagran-internal-request"),
        HeaderValue::from_static("1"),
    );
    if let Ok(token) = HeaderValue::from_str(&state.prefetch_token) {
        headers.insert(HeaderName::from_static("x-lagran-internal-token"), token);
    }
    // Ask for identity so the preview and `Content-Length` describe the stored
    // object, not a gzip variant.
    headers.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    if req.simulate_cookie {
        headers.insert(header::COOKIE, HeaderValue::from_static("lagran_debug=1"));
    }
    if req.simulate_authorization {
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer lagran-diagnostic"),
        );
    }
    if let Some(cc) = req
        .request_cache_control
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        if let Ok(value) = HeaderValue::from_str(cc) {
            headers.insert(header::CACHE_CONTROL, value);
        }
    }
    if req.probe_range {
        // Large video/stream probes must not download the whole object. One
        // byte is enough to exercise the real cache/range path.
        headers.insert(header::RANGE, HeaderValue::from_static("bytes=0-0"));
    }

    // Go through the loopback public listener so Pingora's real data plane runs.
    let base = format!("http://{}", state.local_http_addr);
    let origin = match tokio::time::timeout(
        Duration::from_secs(10),
        state
            .origin
            .request_stream_with_sni(&base, &Method::GET, &path, &headers, None, true, None),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(e)) => {
            tracing::warn!(%domain, %path, error = %e, "cache diagnostic loopback request failed");
            return Json(EdgeDiagResponse {
                status: StatusCode::BAD_GATEWAY.as_u16(),
                headers: vec![],
                body_preview: "cache diagnostic could not reach the edge data plane".into(),
            });
        }
        Err(_) => {
            return Json(EdgeDiagResponse {
                status: StatusCode::GATEWAY_TIMEOUT.as_u16(),
                headers: vec![],
                body_preview: "cache diagnostic timed out after 10s (large origin response?)"
                    .into(),
            })
        }
    };

    let status = origin.status.as_u16();
    let selected = [
        "x-cache",
        "x-cache-status",
        "x-lagran-cache-reason",
        "x-lagran-cache-ttl",
        "x-lagran-datapath",
        "age",
        "etag",
        "cache-control",
        "vary",
        "content-type",
        "server",
    ];
    let mut out_headers = Vec::new();
    for name in selected {
        if let Some(value) = origin.headers.get(name).and_then(|v| v.to_str().ok()) {
            out_headers.push((name.to_string(), value.to_string()));
        }
    }

    let mut body = origin.body;
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
        headers: out_headers,
        body_preview: String::from_utf8_lossy(&preview).to_string(),
    })
}
