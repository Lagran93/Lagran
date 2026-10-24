//! Main request handler: domain lookup → cache → origin

use crate::cache::policy::{cache_key, is_cacheable, RuleSet};
use crate::cache::{CacheEntry, SharedCache};
use crate::config::registry::DomainRegistry;
use crate::metrics::EdgeMetrics;
use crate::origin::OriginClient;
use crate::server::acme_challenge::ChallengeStore;
use crate::server::cert_store::CertStore;
use crate::server::default_page;
use crate::server::host_util;
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
    pub domains: DomainRegistry,
}

pub async fn proxy_handler(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    let method = req.method().clone();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let path_only = req.uri().path().to_string();

    let host = host_util::resolve_request_host(&req);
    let domain_entry = state.domains.get(&host).await;

    // Unknown domain → tip page when registry has domains and host is a real name
    let registry_len = state.domains.len().await;
    if domain_entry.is_none() && registry_len > 0 {
        // Empty host on HTTPS without SNI/Host: still show page
        let display = if host.is_empty() {
            "(empty Host/SNI)"
        } else {
            host.as_str()
        };
        tracing::info!(%host, registry_len, "domain not onboarded");
        return default_page::unknown_domain_page(display);
    }

    let (origin_url, domain_rules_ttl) = if let Some(ref e) = domain_entry {
        let ttl = match_rule_ttl(&e.rules, &path_only);
        (e.origin_url.clone(), ttl)
    } else {
        (state.origin.base_url().await, None)
    };

    if !is_cacheable(&req) {
        return match state
            .origin
            .fetch_from(&origin_url, &path_and_query, req.headers())
            .await
        {
            Ok((status, headers, body)) => {
                state.metrics.record_bypass(body.len() as u64);
                build_response(status, headers, body, "BYPASS")
            }
            Err(e) => {
                tracing::error!(error = %e, origin = %origin_url, "origin fetch failed");
                (StatusCode::BAD_GATEWAY, "Bad Gateway").into_response()
            }
        };
    }

    let key = cache_key(&req);
    let ttl = domain_rules_ttl
        .or(state.rules.match_ttl(&path_only).await)
        .unwrap_or(state.default_ttl_secs);

    if let Some(entry) = state.cache.get(&key).await {
        tracing::debug!(%key, %host, "cache HIT");
        state.metrics.record_hit(entry.body.len() as u64);
        return entry_to_response(entry, "HIT");
    }

    tracing::debug!(%key, %host, origin = %origin_url, ttl, "cache MISS");

    match state
        .origin
        .fetch_as_entry_from(&origin_url, &path_and_query, req.headers())
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
            tracing::error!(
                error = %e,
                method = %method,
                path = %path_and_query,
                origin = %origin_url,
                "origin error"
            );
            (StatusCode::BAD_GATEWAY, format!("Bad Gateway: {e}")).into_response()
        }
    }
}

fn match_rule_ttl(rules: &[crate::cache::policy::CacheRule], path: &str) -> Option<u64> {
    let mut sorted: Vec<_> = rules.iter().collect();
    sorted.sort_by(|a, b| b.priority.cmp(&a.priority));
    for r in sorted {
        if path_matches(&r.path_pattern, path) {
            return Some(r.ttl_seconds);
        }
    }
    None
}

fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern == "/*" || pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return path == prefix
            || path.starts_with(&format!("{prefix}/"))
            || path.starts_with(prefix);
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return path.starts_with(prefix);
    }
    path == pattern
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
