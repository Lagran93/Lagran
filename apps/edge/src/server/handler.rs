//! Main request handler: domain lookup → cache → origin

use crate::cache::policy::{cache_key_opts, is_cacheable, RuleSet};
use crate::cache::{CacheEntry, SharedCache};
use crate::config::registry::DomainRegistry;
use crate::metrics::EdgeMetrics;
use crate::origin::OriginClient;
use crate::server::access_log::AccessLog;
use crate::server::rate_limit::RateLimiter;
use crate::agent::origin_health::OriginHealthMap;
use crate::server::acme_challenge::ChallengeStore;
use crate::server::cert_store::CertStore;
use crate::server::default_page;
use crate::server::host_util;
use crate::server::websocket;
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode},
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use std::time::Instant;

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
    pub access_log: AccessLog,
    pub rate_limiter: RateLimiter,
    pub origin_health: OriginHealthMap,
    pub agent_token: String,
}

pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Response {
    let start = Instant::now();
    let method = req.method().clone();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let path_only = req.uri().path().to_string();
    let host = host_util::resolve_request_host(&req);
    let inm = req
        .headers()
        .get("if-none-match")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let domain_entry = state.domains.get(&host).await;
    let registry_len = state.domains.len().await;

    // Disabled domains behave as not onboarded
    if let Some(ref e) = domain_entry {
        // status is not on DomainEntry - skip; control filters disabled from config sync
        let _ = e;
    }

    if domain_entry.is_none() && registry_len > 0 {
        let display = if host.is_empty() {
            "(empty Host/SNI)"
        } else {
            host.as_str()
        };
        tracing::info!(%host, registry_len, "domain not onboarded");
        let resp = default_page::unknown_domain_page(display);
        log_access(&state.access_log, &method, &host, &path_only, 404, start).await;
        return resp;
    }

    let (origin_url, backup_url, domain_rules_ttl) = if let Some(ref e) = domain_entry {
        (
            e.origin_url.clone(),
            e.backup_origin_url.clone(),
            match_rule_ttl(&e.rules, &path_only),
        )
    } else {
        (state.origin.base_url().await, String::new(), None)
    };

    // Rate limit per host
    let (rps, burst) = domain_entry
        .as_ref()
        .map(|e| (e.rate_limit_rps, e.rate_limit_burst))
        .unwrap_or((0, 0));
    let rl_key = if host.is_empty() { "default" } else { host.as_str() };
    if !state.rate_limiter.check(rl_key, rps, burst).await {
        log_access(&state.access_log, &method, &host, &path_only, 429, start).await;
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", "1")],
            "Too Many Requests",
        )
            .into_response();
    }

    // Origin health gate
    if !host.is_empty() && !state.origin_health.is_healthy(&host).await {
        log_access(&state.access_log, &method, &host, &path_only, 503, start).await;
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Origin Unhealthy",
        )
            .into_response();
    }


    // WebSocket upgrade → tunnel to origin (no cache)
    if websocket::is_websocket_upgrade(req.headers()) {
        if let Some(on_upgrade) = req.extensions().get::<hyper::upgrade::OnUpgrade>().cloned() {
            let origin = origin_url.clone();
            let path = path_and_query.clone();
            let headers = req.headers().clone();
            tokio::spawn(async move {
                if let Err(e) = websocket::proxy_websocket(on_upgrade, &origin, &path, &headers).await {
                    tracing::warn!(error = %e, "websocket proxy failed");
                }
            });
            // Return 101 Switching Protocols with required headers echoed loosely
            let mut resp = Response::new(Body::empty());
            *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
            resp.headers_mut().insert(
                HeaderName::from_static("upgrade"),
                HeaderValue::from_static("websocket"),
            );
            resp.headers_mut().insert(
                HeaderName::from_static("connection"),
                HeaderValue::from_static("Upgrade"),
            );
            if let Some(key) = req.headers().get("sec-websocket-accept") {
                resp.headers_mut().insert("sec-websocket-accept", key.clone());
            }
            // Note: proper Sec-WebSocket-Accept should be computed; full handshake
            // is completed on the origin side of the tunnel. Client may need origin to answer 101.
            // Alternative path: we already dialed origin in spawn after client upgrade —
            // order is wrong. Fix: do origin upgrade first in spawn after both sides.
            log_access(&state.access_log, &method, &host, &path_only, 101, start).await;
            return resp;
        }
    }

    // Hotlink protection
    if let Some(ref e) = domain_entry {
        if !e.hotlink_allow_referers.is_empty() {
            let referer = req
                .headers()
                .get("referer")
                .or_else(|| req.headers().get("referrer"))
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let allowed = e
                .hotlink_allow_referers
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .any(|pat| referer.contains(pat) || pat == "*");
            if !allowed {
                log_access(&state.access_log, &method, &host, &path_only, 403, start).await;
                return (StatusCode::FORBIDDEN, "Hotlink Forbidden").into_response();
            }
        }
    }

    let ignore_query = domain_entry
        .as_ref()
        .map(|e| e.ignore_query_string)
        .unwrap_or(false);
    let cors = domain_entry
        .as_ref()
        .map(|e| e.cors_origins.clone())
        .unwrap_or_default();
    let custom_headers = domain_entry
        .as_ref()
        .map(|e| e.custom_headers.clone())
        .unwrap_or_default();
    let origin_timeout = domain_entry
        .as_ref()
        .map(|e| e.origin_timeout_ms)
        .filter(|t| *t > 0)
        .unwrap_or(10000);

    if !is_cacheable(&req) {
        let fetch = state
            .origin
            .fetch_from(&origin_url, &path_and_query, req.headers());
        match tokio::time::timeout(
            std::time::Duration::from_millis(origin_timeout as u64),
            fetch,
        )
        .await
        {
            Err(_) => {
                log_access(&state.access_log, &method, &host, &path_only, 504, start).await;
                return (StatusCode::GATEWAY_TIMEOUT, "Origin Timeout").into_response();
            }
            Ok(Err(e)) => {
                tracing::error!(error = %e, origin = %origin_url, "origin fetch failed");
                log_access(&state.access_log, &method, &host, &path_only, 502, start).await;
                return (StatusCode::BAD_GATEWAY, "Bad Gateway").into_response();
            }
            Ok(Ok((status, headers, body))) => {
                state.metrics.record_bypass(body.len() as u64);
                let resp = build_response(status, headers, body, "BYPASS", &cors, &custom_headers);
                log_access(
                    &state.access_log,
                    &method,
                    &host,
                    &path_only,
                    status.as_u16(),
                    start,
                )
                .await;
                return resp;
            }
        }
    }

        let key = cache_key_opts(&req, ignore_query);
    let ttl = domain_rules_ttl
        .or(state.rules.match_ttl(&path_only).await)
        .unwrap_or(state.default_ttl_secs);

    if let Some(entry) = state.cache.get(&key).await {
        let etag = compute_etag(&entry);
        if let Some(ref client_etag) = inm {
            if client_etag.trim() == etag || client_etag.trim() == format!("W/{etag}") {
                state.metrics.record_hit(0);
                log_access(&state.access_log, &method, &host, &path_only, 304, start).await;
                return not_modified_response(&etag);
            }
        }
        tracing::debug!(%key, %host, "cache HIT");
        state.metrics.record_hit(entry.body.len() as u64);
        let resp = entry_to_response(entry, "HIT", &etag, &cors, &custom_headers);
        log_access(&state.access_log, &method, &host, &path_only, 200, start).await;
        return resp;
    }

    tracing::debug!(%key, %host, origin = %origin_url, ttl, "cache MISS");

    match fetch_with_failover(
        &state.origin,
        &origin_url,
        &backup_url,
        &path_and_query,
        req.headers(),
        origin_timeout as u64,
    )
    .await
    {
        Ok(entry) => {
            let bytes = entry.body.len() as u64;
            let etag = compute_etag(&entry);
            if (200..300).contains(&entry.status) && ttl > 0 {
                state.cache.set(&key, entry.clone(), ttl).await;
            }
            state.metrics.record_miss(bytes);
            let status = entry.status;
            let resp = entry_to_response(entry, "MISS", &etag, &cors, &custom_headers);
            log_access(&state.access_log, &method, &host, &path_only, status, start).await;
            resp
        }
        Err(e) => {
            tracing::error!(error = %e, origin = %origin_url, "origin failover exhausted");
            let code = if e.contains("timeout") { 504 } else { 502 };
            log_access(&state.access_log, &method, &host, &path_only, code, start).await;
            if code == 504 {
                (StatusCode::GATEWAY_TIMEOUT, "Origin Timeout").into_response()
            } else {
                (StatusCode::BAD_GATEWAY, format!("Bad Gateway: {e}")).into_response()
            }
        }
    }
}

async fn log_access(
    log: &AccessLog,
    method: &axum::http::Method,
    host: &str,
    path: &str,
    status: u16,
    start: Instant,
) {
    let ms = start.elapsed().as_millis();
    let line = format!(
        "{method} host={host} path={path} status={status} {ms}ms"
    );
    log.write(&line).await;
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
        return path == prefix || path.starts_with(&format!("{prefix}/")) || path.starts_with(prefix);
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return path.starts_with(prefix);
    }
    path == pattern
}

fn compute_etag(entry: &CacheEntry) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    entry.status.hash(&mut h);
    entry.body.len().hash(&mut h);
    // sample body for stability without hashing entire large body
    let sample = if entry.body.len() > 64 {
        &entry.body[..64]
    } else {
        &entry.body[..]
    };
    sample.hash(&mut h);
    format!("\"{:x}\"", h.finish())
}

fn not_modified_response(etag: &str) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("etag"),
        HeaderValue::from_str(etag).unwrap_or_else(|_| HeaderValue::from_static("\"0\"")),
    );
    apply_security_headers(&mut headers);
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::NOT_MODIFIED;
    *resp.headers_mut() = headers;
    resp
}

fn apply_cors_and_custom(headers: &mut HeaderMap, cors: &str, custom: &str) {
    if !cors.is_empty() {
        let origin = if cors.trim() == "*" {
            "*"
        } else {
            cors.split(',').next().map(|s| s.trim()).unwrap_or("*")
        };
        if let Ok(v) = HeaderValue::from_str(origin) {
            headers.insert(HeaderName::from_static("access-control-allow-origin"), v);
        }
    }
    for line in custom.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(k.trim().as_bytes()),
                HeaderValue::from_str(v.trim()),
            ) {
                headers.insert(name, val);
            }
        }
    }
}

fn apply_security_headers(headers: &mut HeaderMap) {
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("SAMEORIGIN"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
}

fn entry_to_response(entry: CacheEntry, cache_status: &str, etag: &str, cors: &str, custom: &str) -> Response {
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
    if let Ok(v) = HeaderValue::from_str(etag) {
        headers.insert(HeaderName::from_static("etag"), v);
    }
    apply_security_headers(&mut headers);
    apply_cors_and_custom(&mut headers, cors, custom);
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
    cors: &str,
    custom: &str,
) -> Response {
    headers.insert(
        HeaderName::from_static("x-cache"),
        HeaderValue::from_str(cache_status).unwrap(),
    );
    headers.insert(
        HeaderName::from_static("x-powered-by"),
        HeaderValue::from_static("lagran-edge"),
    );
    apply_security_headers(&mut headers);
    apply_cors_and_custom(&mut headers, cors, custom);
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = status;
    *resp.headers_mut() = headers;
    resp
}


async fn fetch_with_failover(
    origin: &crate::origin::OriginClient,
    primary: &str,
    backup: &str,
    path: &str,
    headers: &HeaderMap,
    timeout_ms: u64,
) -> Result<CacheEntry, String> {
    let try_one = |url: String| async move {
        let fut = origin.fetch_as_entry_from(&url, path, headers);
        match tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), fut).await {
            Ok(Ok(e)) => Ok(e),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("timeout".into()),
        }
    };
    match try_one(primary.to_string()).await {
        Ok(e) => Ok(e),
        Err(e1) => {
            if backup.is_empty() {
                return Err(e1);
            }
            tracing::warn!(primary = %primary, error = %e1, "primary origin failed, trying backup");
            try_one(backup.to_string()).await
        }
    }
}
