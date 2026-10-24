//! Main request handler: cache lookup → origin → store

use crate::cache::policy::{cache_key, is_cacheable, RuleSet};
use crate::cache::{CacheEntry, SharedCache};
use crate::metrics::EdgeMetrics;
use crate::origin::OriginClient;
use crate::server::acme_challenge::ChallengeStore;
use crate::server::cert_store::CertStore;
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode},
    response::{IntoResponse, Response},
};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub cache: SharedCache,
    pub origin: OriginClient,
    pub default_ttl_secs: u64,
    pub rules: RuleSet,
    pub metrics: Arc<EdgeMetrics>,
    pub challenges: ChallengeStore,
    pub certs: Arc<CertStore>,
}

pub async fn proxy_handler(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    let method = req.method().clone();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let path_only = req.uri().path().to_string();

    if !is_cacheable(&req) {
        return match state.origin.fetch(&path_and_query, req.headers()).await {
            Ok((status, headers, body)) => {
                state.metrics.record_bypass(body.len() as u64);
                build_response(status, headers, body, "BYPASS")
            }
            Err(e) => {
                tracing::error!(error = %e, "origin fetch failed");
                (StatusCode::BAD_GATEWAY, "Bad Gateway").into_response()
            }
        };
    }

    let key = cache_key(&req);
    let ttl = state
        .rules
        .match_ttl(&path_only)
        .await
        .unwrap_or(state.default_ttl_secs);

    if let Some(entry) = state.cache.get(&key).await {
        tracing::debug!(%key, "cache HIT");
        state.metrics.record_hit(entry.body.len() as u64);
        return entry_to_response(entry, "HIT");
    }

    tracing::debug!(%key, ttl, "cache MISS");

    match state
        .origin
        .fetch_as_entry(&path_and_query, req.headers())
        .await
    {
        Ok(entry) => {
            let bytes = entry.body.len() as u64;
            if (200..300).contains(&entry.status) && ttl > 0 {
                state.cache.set(&key, entry.clone(), ttl).await;
            }
            state.metrics.record_miss(bytes);
            entry_to_response(entry, "MISS")
        }
        Err(e) => {
            tracing::error!(error = %e, method = %method, path = %path_and_query, "origin error");
            (StatusCode::BAD_GATEWAY, format!("Bad Gateway: {e}")).into_response()
        }
    }
}

fn entry_to_response(entry: CacheEntry, cache_status: &str) -> Response {
    let status = StatusCode::from_u16(entry.status).unwrap_or(StatusCode::OK);
    let mut headers = HeaderMap::new();
    for (k, v) in &entry.headers {
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            headers.insert(name, val);
        }
    }
    headers.insert(
        HeaderName::from_static("x-cache"),
        HeaderValue::from_str(cache_status).unwrap(),
    );
    headers.insert(
        HeaderName::from_static("x-powered-by"),
        HeaderValue::from_static("lagran-edge"),
    );
    let mut resp = Response::new(Body::from(entry.body));
    *resp.status_mut() = status;
    *resp.headers_mut() = headers;
    resp
}

fn build_response(
    status: StatusCode,
    mut headers: HeaderMap,
    body: bytes::Bytes,
    cache_status: &str,
) -> Response {
    headers.insert(
        HeaderName::from_static("x-cache"),
        HeaderValue::from_str(cache_status).unwrap(),
    );
    headers.insert(
        HeaderName::from_static("x-powered-by"),
        HeaderValue::from_static("lagran-edge"),
    );
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = status;
    *resp.headers_mut() = headers;
    resp
}
