//! Main request handler: domain lookup → policy → cache → origin.
//!
//! Cache correctness notes:
//! * rules are resolved per domain (never from a global rule set shared by all
//!   hosts) when the domain is in the registry;
//! * authenticated/personalised requests (Authorization/Cookie), Range probes
//!   and `Cache-Control: no-cache` bypass the shared cache;
//! * concurrent misses for the same key collapse into one origin fetch;
//! * storage TTL comes from the matched rule, then origin `Cache-Control` /
//!   `Expires`, then the domain/default TTL.

use crate::agent::origin_health::OriginHealthMap;
use crate::agent::{ControlClient, NodeControl};
use crate::cache::policy::{
    cache_key_for_request, compute_etag, decide_storage_reason, etag_matches,
    is_uncacheable_header, request_bypass_reason, request_method_cacheable, resolve_rule_policy,
    resolve_rule_policy_for_response, strip_response_headers, CacheRule, CacheStatus,
    ResolvedPolicy, RuleAction, RuleSet,
};
use crate::cache::{CacheEntry, CacheGetResult, SharedCache};
use crate::config::registry::{DomainEntry, DomainRegistry, OriginTarget};
use crate::metrics::EdgeMetrics;
use crate::origin::{OriginClient, OriginResponse};
use crate::server::access_log::AccessLog;
use crate::server::acme_challenge::ChallengeStore;
use crate::server::cc::{CcDecision, CcMode, CcProtector};
use crate::server::cert_store::CertStore;
use crate::server::challenge;
use crate::server::default_page::{self, OriginFailure};
use crate::server::host_util;
use crate::server::inflight::{self, Inflight, Slot};
use crate::server::rate_limit::RateLimiter;
use crate::server::waf_log::WafLog;
use crate::server::websocket;
use crate::waf::{evaluate as waf_evaluate, WafAction, WafMode, WafRequest};
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode},
    response::{IntoResponse, Response},
};
use http_body_util::{BodyExt, Limited};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Largest request body we are willing to buffer for pass-through traffic.
const MAX_PROXY_BODY: usize = 16 * 1024 * 1024;
/// Largest origin object we keep in the cache.
/// How long a follower waits for the in-flight fetch before fetching itself.
const FETCH_WAIT: Duration = Duration::from_secs(5);

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
    pub cc: CcProtector,
    pub control: ControlClient,
    pub origin_health: OriginHealthMap,
    pub agent_token: String,
    pub inflight: Inflight,
    pub waf_log: WafLog,
    /// Trust X-Forwarded-For when determining the client IP (WAF ACLs).
    pub trust_proxy_headers: bool,
    /// HMAC secret for challenge nonces and clearance cookies.
    pub challenge_secret: String,
    /// Set from the heartbeat reply; disabled nodes answer 503 and keep serving
    /// management/health endpoints.
    pub node_control: NodeControl,
    /// Port used when redirecting HTTP to HTTPS (None = 443).
    pub https_redirect_port: Option<u16>,
    /// Responses larger than this are proxied but not stored in cache.
    pub max_cacheable_body: usize,
}

/// Per-request view of the effective domain configuration.
struct Effective {
    origin_url: String,
    backup_url: String,
    origins: Vec<OriginTarget>,
    policy: ResolvedPolicy,
    rules: Vec<CacheRule>,
    path: String,
    method: Method,
    ignore_query: bool,
    cors: String,
    custom_headers: String,
    timeout_ms: u64,
}

static HANDLER_ORIGIN_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Weighted, health-aware origin order for the legacy handler path.
async fn origin_sequence(state: &AppState, host: &str, eff: &Effective) -> Vec<String> {
    let mut pool = if eff.origins.is_empty() {
        let mut list = vec![OriginTarget {
            url: eff.origin_url.clone(),
            weight: 100,
            priority: 0,
            enabled: true,
            host_header: None,
        }];
        if !eff.backup_url.is_empty() {
            list.push(OriginTarget {
                url: eff.backup_url.clone(),
                weight: 100,
                priority: 1,
                enabled: true,
                host_header: None,
            });
        }
        list
    } else {
        eff.origins.clone()
    };
    pool.retain(|o| o.enabled);
    if pool.is_empty() {
        return Vec::new();
    }

    let mut healthy = Vec::new();
    for origin in &pool {
        if state
            .origin_health
            .is_origin_healthy(host, &origin.url)
            .await
        {
            healthy.push(origin.clone());
        }
    }
    let mut candidates = if healthy.is_empty() { pool } else { healthy };
    let min_priority = candidates
        .iter()
        .map(|o| o.priority)
        .min()
        .unwrap_or_default();
    candidates.retain(|o| o.priority == min_priority);
    if candidates.is_empty() {
        return Vec::new();
    }

    let seed = HANDLER_ORIGIN_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    OriginTarget::weighted_order(candidates, seed)
        .into_iter()
        .map(|o| o.url)
        .collect()
}

enum Fetched {
    FromOrigin(OriginResponse),
    /// A follower reused the entry the leader just stored.
    FromCache(OriginResponse),
}

/// Why a fetch could not produce a usable origin response.
#[derive(Debug)]
enum FetchError {
    /// Health probes marked the origin down; fail fast without dialing.
    Unhealthy,
    Timeout,
    Failed(String),
}

impl FetchError {
    fn failure(&self) -> OriginFailure {
        match self {
            FetchError::Unhealthy => OriginFailure::Unhealthy,
            FetchError::Timeout => OriginFailure::Timeout,
            FetchError::Failed(_) => OriginFailure::Unreachable,
        }
    }
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Unhealthy => write!(f, "origin marked unhealthy"),
            FetchError::Timeout => write!(f, "origin timeout"),
            FetchError::Failed(e) => write!(f, "{e}"),
        }
    }
}

pub async fn proxy_handler(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    let start = Instant::now();
    let method = req.method().clone();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let path_only = req.uri().path().to_string();
    let host = host_util::resolve_request_host(&req);
    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip());
    let mut headers = req.headers().clone();
    let header_ip = header_ip_from_headers(&headers);
    let client_ip_addr = if state.trust_proxy_headers {
        header_ip.or(peer_ip)
    } else {
        peer_ip.or(header_ip)
    };
    let client_ip = client_ip_addr
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "-".to_string());
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let referer = headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let request_id = headers
        .get("x-request-id")
        .or_else(|| headers.get("x-correlation-id"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| uuid_like_request_id());
    let if_none_match = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    // A node disabled from the console stops serving traffic but keeps its
    // management endpoints (health, heartbeat, purge) reachable.
    if !state.node_control.is_serving() {
        log_access(
            &state.access_log,
            &method,
            &host,
            &path_only,
            503,
            start,
            &client_ip,
            &user_agent,
            &referer,
            0,
            "NODE_DISABLED",
            &request_id,
        )
        .await;
        return default_page::node_disabled_page(&host);
    }

    let domain_entry = state.domains.get(&host).await;

    // Domain-level HTTPS enforcement: redirect plain HTTP before WAF/cache so
    // the browser continues over TLS (and secure challenge cookies stick).
    let is_https = req.extensions().get::<host_util::TlsSni>().is_some()
        || (state.trust_proxy_headers
            && headers
                .get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.eq_ignore_ascii_case("https"))
                .unwrap_or(false));

    let registry_empty = state.domains.is_empty().await;

    if domain_entry.is_none() && !registry_empty {
        let display = if host.is_empty() {
            "(empty Host/SNI)"
        } else {
            host.as_str()
        };
        tracing::info!(%host, "domain not onboarded");
        log_access(
            &state.access_log,
            &method,
            &host,
            &path_only,
            404,
            start,
            &client_ip,
            &user_agent,
            &referer,
            0,
            CacheStatus::None.as_str(),
            &request_id,
        )
        .await;
        return default_page::unknown_domain_page(display);
    }

    // Resolve the effective config once; rules stay per-domain so two hosted
    // domains can never influence each other's TTL/action.
    let eff = match domain_entry {
        Some(ref e) => {
            let policy = resolve_rule_policy(
                &e.rules,
                &path_only,
                method.as_str(),
                req.uri().query().unwrap_or(""),
            );
            Effective {
                origin_url: e.origin_url.clone(),
                backup_url: e.backup_origin_url.clone(),
                origins: e.origins.clone(),
                policy,
                rules: e.rules.clone(),
                path: path_only.clone(),
                method: method.clone(),
                ignore_query: policy.ignore_query.unwrap_or(e.ignore_query_string),
                cors: e.cors_origins.clone(),
                custom_headers: e.custom_headers.clone(),
                timeout_ms: u64::from(if e.origin_timeout_ms == 0 {
                    10_000
                } else {
                    e.origin_timeout_ms
                }),
            }
        }
        None => {
            // Legacy single-origin mode: only reachable while the registry is
            // empty. Global rules are the best available approximation here.
            let policy = state
                .rules
                .resolve(&path_only, method.as_str(), req.uri().query().unwrap_or(""))
                .await
                .unwrap_or_default();
            let ignore_query = policy.ignore_query.unwrap_or(false);
            Effective {
                origin_url: state.origin.base_url().await,
                backup_url: String::new(),
                origins: Vec::new(),
                ignore_query,
                policy,
                rules: Vec::new(),
                path: path_only.clone(),
                method: method.clone(),
                cors: String::new(),
                custom_headers: String::new(),
                timeout_ms: 10_000,
            }
        }
    };

    // Single preflight implementation shared with the Pingora native path:
    // HTTPS redirect, CC, rate-limit, WAF and hotlink.
    if let Some(domain) = domain_entry.as_ref() {
        if let Some(resp) = preflight_cacheable(
            &state,
            domain,
            &method,
            &host,
            &path_only,
            &path_and_query,
            &headers,
            &client_ip,
            is_https,
            start,
        )
        .await
        {
            return resp;
        }
    }

    // NOTE: origin health is checked where an origin fetch is actually needed
    // (below), not here: a fresh cache hit must still be served while the
    // origin is down.

    // WebSocket upgrade → handshake with origin, then raw byte tunnel.
    if websocket::is_websocket_upgrade(&headers) {
        let ws_origin = origin_sequence(&state, &host, &eff)
            .await
            .first()
            .cloned()
            .unwrap_or_else(|| eff.origin_url.clone());
        let resp =
            websocket::handle_upgrade(req, &ws_origin, &path_and_query, &headers, eff.timeout_ms)
                .await;
        let code = resp.status().as_u16();
        log_access(
            &state.access_log,
            &method,
            &host,
            &path_only,
            code,
            start,
            &client_ip,
            &user_agent,
            &referer,
            0,
            "WS",
            &request_id,
        )
        .await;
        return resp;
    }

    let mut request_reason = if !request_method_cacheable(&method) {
        Some("method")
    } else {
        request_bypass_reason(&req, eff.policy.ignore_cookie).or_else(|| {
            if eff.policy.action != RuleAction::Cache {
                Some("rule-bypass")
            } else {
                None
            }
        })
    };
    let mut request_cacheable = request_reason.is_none();
    let mut range_spec = None;
    if request_cacheable {
        if let Some(raw) = headers
            .get(header::RANGE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
        {
            match parse_range_spec(&raw) {
                Some(spec) => {
                    range_spec = Some((spec, raw));
                    headers.remove(header::RANGE);
                }
                None => {
                    request_reason = Some("range");
                    request_cacheable = false;
                }
            }
        }
    }

    if !request_cacheable {
        let mut response = bypass_to_origin(
            &state,
            req,
            &eff,
            &method,
            &host,
            &path_and_query,
            &path_only,
            &headers,
            &client_ip,
            &user_agent,
            &referer,
            &request_id,
            start,
        )
        .await;
        set_cache_reason(&mut response, request_reason);
        return response;
    }

    let cache_lookup_path = if eff.ignore_query {
        path_only.clone()
    } else {
        path_and_query.clone()
    };
    let key_method = if method == Method::HEAD {
        Method::GET
    } else {
        method.clone()
    };
    let key = cache_key_for_request(&key_method, &host, &cache_lookup_path, &headers);

    if let Some((spec, raw_range)) = range_spec {
        let lookup = state.cache.get_result(&key).await;
        match lookup {
            CacheGetResult::Hit(entry) if !entry_response_bypass(&eff, &entry) => {
                return serve_range_entry(
                    &state,
                    entry,
                    CacheStatus::Hit,
                    spec,
                    &method,
                    &host,
                    &path_only,
                    &client_ip,
                    &user_agent,
                    &referer,
                    &request_id,
                    &eff,
                    start,
                )
                .await;
            }
            CacheGetResult::Stale(entry) if !entry_response_bypass(&eff, &entry) => {
                return serve_range_entry(
                    &state,
                    entry,
                    CacheStatus::Stale,
                    spec,
                    &method,
                    &host,
                    &path_only,
                    &client_ip,
                    &user_agent,
                    &referer,
                    &request_id,
                    &eff,
                    start,
                )
                .await;
            }
            CacheGetResult::Hit(_) | CacheGetResult::Stale(_) => {
                state.cache.delete(&key).await;
            }
            CacheGetResult::Expired | CacheGetResult::Miss => {}
        }

        // A cache miss must not turn a Range request into a full-object
        // download. Video/large-file endpoints rely on the origin's 206
        // streaming response; buffering the whole representation here would
        // blow the origin timeout. Pass the original Range through untouched.
        if let Ok(value) = HeaderValue::from_str(&raw_range) {
            headers.insert(header::RANGE, value);
        }
        let mut response = bypass_to_origin(
            &state,
            req,
            &eff,
            &method,
            &host,
            &path_and_query,
            &path_only,
            &headers,
            &client_ip,
            &user_agent,
            &referer,
            &request_id,
            start,
        )
        .await;
        set_cache_reason(&mut response, Some("range-bypass"));
        return response;
    }

    let mut lookup = state.cache.get_result(&key).await;
    let cached_bypass = match &lookup {
        CacheGetResult::Hit(entry) | CacheGetResult::Stale(entry) => {
            entry_response_bypass(&eff, entry)
        }
        _ => false,
    };
    if cached_bypass {
        state.cache.delete(&key).await;
        lookup = CacheGetResult::Miss;
    }
    let from_expired = matches!(lookup, CacheGetResult::Expired);
    match lookup {
        CacheGetResult::Hit(ref entry) => {
            serve_cached(
                &state,
                entry.clone(),
                CacheStatus::Hit,
                &method,
                &host,
                &path_only,
                &client_ip,
                &user_agent,
                &referer,
                &request_id,
                if_none_match.as_deref(),
                &eff,
                start,
            )
            .await
        }
        CacheGetResult::Stale(ref entry) => {
            // Serve stale immediately, revalidate once in the background.
            spawn_revalidation(
                state.clone(),
                key.clone(),
                host.clone(),
                eff.origin_url.clone(),
                eff.backup_url.clone(),
                eff.origins.clone(),
                path_and_query.clone(),
                headers.clone(),
                eff.timeout_ms,
                eff.policy,
                eff.rules.clone(),
                eff.path.clone(),
            );
            serve_cached(
                &state,
                entry.clone(),
                CacheStatus::Stale,
                &method,
                &host,
                &path_only,
                &client_ip,
                &user_agent,
                &referer,
                &request_id,
                if_none_match.as_deref(),
                &eff,
                start,
            )
            .await
        }
        CacheGetResult::Expired | CacheGetResult::Miss => {
            let fetched = fetch_with_single_flight(
                &state,
                &key,
                &eff,
                &path_and_query,
                &headers,
                &method,
                &host,
            )
            .await;

            match fetched {
                Ok((Fetched::FromCache(resp), _)) => {
                    let status = resp.status;
                    let body_len = resp.body.len() as u64;
                    let etag = entry_etag(&resp);
                    state.metrics.record_hit(&host, body_len).await;
                    log_access(
                        &state.access_log,
                        &method,
                        &host,
                        &path_only,
                        status.as_u16(),
                        start,
                        &client_ip,
                        &user_agent,
                        &referer,
                        body_len,
                        CacheStatus::Hit.as_str(),
                        &request_id,
                    )
                    .await;
                    origin_response(
                        resp,
                        CacheStatus::Hit.as_str(),
                        &etag,
                        &eff.cors,
                        &eff.custom_headers,
                        policy_browser_ttl(&eff.policy),
                    )
                }
                Ok((Fetched::FromOrigin(resp), _)) => {
                    let status = resp.status;
                    let body_len = resp.body.len() as u64;
                    let etag = entry_etag(&resp);
                    let content_type = resp
                        .headers
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    let response_policy = resolve_rule_policy_for_response(
                        &eff.rules,
                        &eff.path,
                        method.as_str(),
                        path_and_query.split_once('?').map(|(_, q)| q).unwrap_or(""),
                        content_type,
                    );
                    let response_bypass = response_policy.action != RuleAction::Cache;
                    if !response_bypass && (200..300).contains(&status.as_u16()) {
                        state.metrics.record_miss(&host, body_len).await;
                    } else {
                        state.metrics.record_bypass(&host, body_len).await;
                    }
                    let label = if response_bypass {
                        CacheStatus::Bypass
                    } else if from_expired {
                        CacheStatus::Expired
                    } else {
                        CacheStatus::Miss
                    };
                    let out = origin_response(
                        resp,
                        label.as_str(),
                        &etag,
                        &eff.cors,
                        &eff.custom_headers,
                        if response_bypass {
                            None
                        } else {
                            policy_browser_ttl(&response_policy)
                        },
                    );
                    log_access(
                        &state.access_log,
                        &method,
                        &host,
                        &path_only,
                        status.as_u16(),
                        start,
                        &client_ip,
                        &user_agent,
                        &referer,
                        body_len,
                        label.as_str(),
                        &request_id,
                    )
                    .await;
                    out
                }
                Err(e) => {
                    let failure = e.failure();
                    let code = failure.status().as_u16();
                    tracing::warn!(error = %e, origin = %eff.origin_url, "origin fetch failed");
                    log_access(
                        &state.access_log,
                        &method,
                        &host,
                        &path_only,
                        code,
                        start,
                        &client_ip,
                        &user_agent,
                        &referer,
                        0,
                        failure.log_label(),
                        &request_id,
                    )
                    .await;
                    default_page::origin_error_page(&host, &path_only, failure)
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn bypass_to_origin(
    state: &AppState,
    req: Request<Body>,
    eff: &Effective,
    method: &Method,
    host: &str,
    path_and_query: &str,
    path_only: &str,
    headers: &HeaderMap,
    client_ip: &str,
    user_agent: &str,
    referer: &str,
    request_id: &str,
    start: Instant,
) -> Response {
    let label = if request_method_cacheable(method) {
        CacheStatus::Bypass
    } else {
        CacheStatus::Dynamic
    };

    let body = match Limited::new(req.into_body(), MAX_PROXY_BODY)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            tracing::warn!(error = %e, "request body too large or unreadable");
            log_access(
                &state.access_log,
                method,
                host,
                path_only,
                413,
                start,
                client_ip,
                user_agent,
                referer,
                0,
                label.as_str(),
                &request_id,
            )
            .await;
            return (StatusCode::PAYLOAD_TOO_LARGE, "Payload Too Large").into_response();
        }
    };

    let attempt = |url: String| {
        let origin = state.origin.clone();
        let method = method.clone();
        let mut headers = headers.clone();
        if let Some(host) = origin_host_override(eff, &url) {
            if let Ok(value) = HeaderValue::from_str(host) {
                headers.insert(header::HOST, value);
            }
        }
        let path = path_and_query.to_string();
        let body = body.clone();
        async move {
            match tokio::time::timeout(
                Duration::from_millis(eff.timeout_ms),
                origin.request(&url, &method, &path, &headers, Some(body), true),
            )
            .await
            {
                Ok(Ok(r)) => Ok(r),
                Ok(Err(e)) => Err(FetchError::Failed(e.to_string())),
                Err(_) => Err(FetchError::Timeout),
            }
        }
    };

    let sequence = origin_sequence(state, host, eff).await;
    if sequence.is_empty() {
        log_access(
            &state.access_log,
            method,
            host,
            path_only,
            503,
            start,
            client_ip,
            user_agent,
            referer,
            0,
            OriginFailure::Unhealthy.log_label(),
            request_id,
        )
        .await;
        return default_page::origin_error_page(host, path_only, OriginFailure::Unhealthy);
    }
    let mut result = Err(FetchError::Unhealthy);
    for url in sequence {
        result = attempt(url.clone()).await;
        if result.is_ok() {
            break;
        }
        tracing::warn!(origin = %url, "origin failed, trying next origin");
    }

    match result {
        Ok(resp) => {
            let status = resp.status;
            let body_len = resp.body.len() as u64;
            let out = pass_through_response(resp, label.as_str(), &eff.cors, &eff.custom_headers);
            state.metrics.record_bypass(host, body_len).await;
            log_access(
                &state.access_log,
                method,
                host,
                path_only,
                status.as_u16(),
                start,
                client_ip,
                user_agent,
                referer,
                body_len,
                label.as_str(),
                &request_id,
            )
            .await;
            out
        }
        Err(e) => {
            let failure = e.failure();
            let code = failure.status().as_u16();
            tracing::warn!(error = %e, origin = %eff.origin_url, "origin fetch failed");
            log_access(
                &state.access_log,
                method,
                host,
                path_only,
                code,
                start,
                client_ip,
                user_agent,
                referer,
                0,
                failure.log_label(),
                &request_id,
            )
            .await;
            default_page::origin_error_page(host, path_only, failure)
        }
    }
}

/// Fetch with request coalescing: one leader per cache key; followers wait for
/// the leader and re-read the cache before falling back to their own fetch.
async fn fetch_with_single_flight(
    state: &Arc<AppState>,
    key: &str,
    eff: &Effective,
    path_and_query: &str,
    headers: &HeaderMap,
    method: &Method,
    host: &str,
) -> Result<(Fetched, bool), FetchError> {
    match state.inflight.begin(key).await {
        Slot::Leader(leader) => {
            // HEAD must fetch and cache the full GET representation; otherwise
            // the empty HEAD body is stored under the shared GET key and later
            // GETs are poisoned with an empty response.
            let origin_method = if method == Method::HEAD {
                Method::GET
            } else {
                method.clone()
            };
            let mut result =
                fetch_origin(state, eff, host, path_and_query, headers, &origin_method).await;
            if let Ok(resp) = &mut result {
                let content_type = resp
                    .headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let query = path_and_query.split_once('?').map(|(_, q)| q).unwrap_or("");
                let response_policy = resolve_rule_policy_for_response(
                    &eff.rules,
                    &eff.path,
                    method.as_str(),
                    query,
                    content_type,
                );
                let mut reason = None;
                if response_policy.action != RuleAction::Cache {
                    reason = Some("content-type-bypass");
                } else {
                    match decide_storage_reason(
                        resp.status.as_u16(),
                        &headers_vec(&resp.headers),
                        response_policy,
                        state.default_ttl_secs,
                    ) {
                        Ok(decision) => {
                            if resp.body.len() <= state.max_cacheable_body {
                                let entry = clone_as_entry(resp);
                                state
                                    .cache
                                    .set_with_swr(key, entry, decision.ttl_secs, decision.swr_secs)
                                    .await;
                            } else {
                                reason = Some("body-too-large");
                                tracing::debug!(len = resp.body.len(), %host, "object too large to cache");
                            }
                        }
                        Err(r) => reason = Some(r),
                    }
                }
                resp.cache_reason = reason;
            }
            leader.finish().await;
            result.map(|r| (Fetched::FromOrigin(r), true))
        }
        Slot::Follower(mut rx) => {
            let _ = inflight::wait_for(&mut rx, FETCH_WAIT).await;
            match state.cache.get_result(key).await {
                CacheGetResult::Hit(entry) | CacheGetResult::Stale(entry) => {
                    Ok((Fetched::FromCache(entry_into_origin(entry)), false))
                }
                _ => fetch_origin(state, eff, host, path_and_query, headers, method)
                    .await
                    .map(|r| (Fetched::FromOrigin(r), true)),
            }
        }
    }
}

fn origin_host_override<'a>(eff: &'a Effective, url: &str) -> Option<&'a str> {
    eff.origins
        .iter()
        .find(|origin| origin.url == url)
        .and_then(|origin| origin.host_header.as_deref())
}

async fn fetch_origin(
    state: &AppState,
    eff: &Effective,
    host: &str,
    path_and_query: &str,
    headers: &HeaderMap,
    method: &Method,
) -> Result<OriginResponse, FetchError> {
    let sequence = origin_sequence(state, host, eff).await;
    if sequence.is_empty() {
        return Err(FetchError::Unhealthy);
    }

    let timeout = Duration::from_millis(eff.timeout_ms);
    let attempt = |url: String| {
        let origin = state.origin.clone();
        let method = method.clone();
        let mut headers = headers.clone();
        if let Some(host) = origin_host_override(eff, &url) {
            if let Ok(value) = HeaderValue::from_str(host) {
                headers.insert(header::HOST, value);
            }
        }
        let path = path_and_query.to_string();
        async move {
            match tokio::time::timeout(
                timeout,
                origin.request(&url, &method, &path, &headers, None, false),
            )
            .await
            {
                Ok(Ok(r)) => Ok(r),
                Ok(Err(e)) => Err(FetchError::Failed(e.to_string())),
                Err(_) => Err(FetchError::Timeout),
            }
        }
    };

    let mut result = Err(FetchError::Unhealthy);
    for url in sequence {
        result = attempt(url.clone()).await;
        if result.is_ok() {
            break;
        }
        tracing::warn!(origin = %url, "origin failed, trying next origin");
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn spawn_revalidation(
    state: Arc<AppState>,
    key: String,
    host: String,
    origin_url: String,
    backup_url: String,
    origins: Vec<OriginTarget>,
    path_and_query: String,
    headers: HeaderMap,
    timeout_ms: u64,
    policy: ResolvedPolicy,
    rules: Vec<CacheRule>,
    path: String,
) {
    tokio::spawn(async move {
        let Slot::Leader(leader) = state.inflight.begin(&key).await else {
            return;
        };
        let eff = Effective {
            origin_url,
            backup_url,
            origins,
            policy,
            rules,
            path,
            method: Method::GET,
            ignore_query: false,
            cors: String::new(),
            custom_headers: String::new(),
            timeout_ms,
        };
        match fetch_origin(&state, &eff, &host, &path_and_query, &headers, &Method::GET).await {
            Ok(resp) => {
                let content_type = resp
                    .headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let query = path_and_query.split_once('?').map(|(_, q)| q).unwrap_or("");
                let response_policy = resolve_rule_policy_for_response(
                    &eff.rules,
                    &eff.path,
                    "GET",
                    query,
                    content_type,
                );
                if response_policy.action == RuleAction::Cache {
                    if let Ok(decision) = decide_storage_reason(
                        resp.status.as_u16(),
                        &headers_vec(&resp.headers),
                        response_policy,
                        state.default_ttl_secs,
                    ) {
                        if resp.body.len() <= state.max_cacheable_body {
                            let entry = resp.into_entry();
                            state
                                .cache
                                .set_with_swr(&key, entry, decision.ttl_secs, decision.swr_secs)
                                .await;
                            tracing::debug!(%key, "revalidated stale entry");
                        }
                    }
                }
            }
            Err(e) => tracing::warn!(%key, error = %e, "background revalidation failed"),
        }
        leader.finish().await;
    });
}

#[derive(Debug, Clone, Copy)]
enum RangeSpec {
    FromTo(u64, Option<u64>),
    Suffix(u64),
}

fn parse_range_spec(raw: &str) -> Option<RangeSpec> {
    let value = raw.trim().strip_prefix("bytes=")?;
    if value.contains(',') {
        return None;
    }
    let (start, end) = value.split_once('-')?;
    let start = start.trim();
    let end = end.trim();
    if start.is_empty() {
        let suffix = end.parse::<u64>().ok()?;
        return (suffix > 0).then_some(RangeSpec::Suffix(suffix));
    }
    let start = start.parse::<u64>().ok()?;
    let end = if end.is_empty() {
        None
    } else {
        Some(end.parse::<u64>().ok()?)
    };
    if end.is_some_and(|e| e < start) {
        return None;
    }
    Some(RangeSpec::FromTo(start, end))
}

fn resolve_range(spec: RangeSpec, len: usize) -> Option<(usize, usize)> {
    if len == 0 {
        return None;
    }
    let (start, end) = match spec {
        RangeSpec::FromTo(start, end) => {
            let start = start as usize;
            let end = end.unwrap_or(u64::MAX) as usize;
            (start, end.min(len - 1))
        }
        RangeSpec::Suffix(suffix) => {
            let suffix = suffix as usize;
            (len.saturating_sub(suffix), len - 1)
        }
    };
    (start < len && start <= end).then_some((start, end))
}

#[allow(clippy::too_many_arguments)]
async fn serve_range_entry(
    state: &AppState,
    mut entry: CacheEntry,
    label: CacheStatus,
    spec: RangeSpec,
    method: &Method,
    host: &str,
    path_only: &str,
    client_ip: &str,
    user_agent: &str,
    referer: &str,
    request_id: &str,
    eff: &Effective,
    start: Instant,
) -> Response {
    let etag = entry
        .header("etag")
        .map(str::to_string)
        .unwrap_or_else(|| compute_etag(&entry));
    let total = entry.body.len();
    let Some((slice_start, slice_end)) = resolve_range(spec, total) else {
        let mut resp = Response::new(Body::empty());
        *resp.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
        if let Ok(v) = HeaderValue::from_str(&format!("bytes */{total}")) {
            resp.headers_mut().insert(header::CONTENT_RANGE, v);
        }
        cache_status_headers(resp.headers_mut(), label.as_str());
        return resp;
    };
    let body = entry.body.slice(slice_start..=slice_end);
    let body_len = body.len() as u64;
    entry.body = body;
    entry.status = StatusCode::PARTIAL_CONTENT.as_u16();
    entry
        .headers
        .retain(|(k, _)| !k.eq_ignore_ascii_case("content-length"));
    entry.headers.push((
        "content-range".into(),
        format!("bytes {slice_start}-{slice_end}/{total}"),
    ));
    entry
        .headers
        .push(("accept-ranges".into(), "bytes".into()));

    state.metrics.record_hit(host, body_len).await;
    log_access(
        &state.access_log,
        method,
        host,
        path_only,
        206,
        start,
        client_ip,
        user_agent,
        referer,
        body_len,
        label.as_str(),
        request_id,
    )
    .await;
    entry_to_response(
        entry,
        label.as_str(),
        &etag,
        &eff.cors,
        &eff.custom_headers,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
async fn serve_cached(
    state: &AppState,
    entry: CacheEntry,
    label: CacheStatus,
    method: &Method,
    host: &str,
    path_only: &str,
    client_ip: &str,
    user_agent: &str,
    referer: &str,
    request_id: &str,
    if_none_match: Option<&str>,
    eff: &Effective,
    start: Instant,
) -> Response {
    let etag = entry
        .header("etag")
        .map(str::to_string)
        .unwrap_or_else(|| compute_etag(&entry));

    if let Some(inm) = if_none_match {
        if etag_matches(inm, &etag) {
            state.metrics.record_hit(host, 0).await;
            log_access(
                &state.access_log,
                method,
                host,
                path_only,
                304,
                start,
                client_ip,
                user_agent,
                referer,
                0,
                CacheStatus::Revalidated.as_str(),
                &request_id,
            )
            .await;
            return not_modified_response(&etag);
        }
    }

    let bytes = entry.body.len() as u64;
    state.metrics.record_hit(host, bytes).await;
    log_access(
        &state.access_log,
        method,
        host,
        path_only,
        entry.status,
        start,
        client_ip,
        user_agent,
        referer,
        bytes,
        label.as_str(),
        &request_id,
    )
    .await;
    entry_to_response(
        entry,
        label.as_str(),
        &etag,
        &eff.cors,
        &eff.custom_headers,
        policy_browser_ttl(&eff.policy),
    )
}

pub(crate) fn policy_browser_ttl(policy: &ResolvedPolicy) -> Option<u64> {
    if policy.action == RuleAction::Cache {
        policy.browser_ttl_secs
    } else {
        None
    }
}

pub(crate) fn apply_browser_ttl(headers: &mut HeaderMap, ttl: Option<u64>) {
    let Some(ttl) = ttl.filter(|t| *t > 0) else {
        return;
    };
    // Never override an explicit "do not cache" signal from the origin, and
    // never make a response with Set-Cookie client-cacheable.
    if headers.contains_key(header::SET_COOKIE) {
        return;
    }
    if let Some(cc) = headers
        .get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
    {
        let cc = cc.to_ascii_lowercase();
        if cc.contains("no-store") || cc.contains("private") {
            return;
        }
    }
    if let Ok(v) = HeaderValue::from_str(&format!("public, max-age={ttl}")) {
        headers.insert(header::CACHE_CONTROL, v);
    }
}

fn entry_etag(resp: &OriginResponse) -> String {
    if let Some(v) = resp.headers.get(header::ETAG).and_then(|v| v.to_str().ok()) {
        return v.to_string();
    }
    compute_etag(&clone_as_entry(resp))
}

fn entry_response_bypass(eff: &Effective, entry: &CacheEntry) -> bool {
    let content_type = entry
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    if content_type.is_empty() {
        return false;
    }
    resolve_rule_policy_for_response(&eff.rules, &eff.path, eff.method.as_str(), "", content_type)
        .action
        != RuleAction::Cache
}

fn clone_as_entry(resp: &OriginResponse) -> CacheEntry {
    CacheEntry::new(
        resp.status.as_u16(),
        headers_vec(&resp.headers),
        resp.body.clone(),
    )
}

fn entry_into_origin(entry: CacheEntry) -> OriginResponse {
    let mut headers = HeaderMap::new();
    for (k, v) in &entry.headers {
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            headers.insert(name, val);
        }
    }
    OriginResponse {
        status: StatusCode::from_u16(entry.status).unwrap_or(StatusCode::OK),
        headers,
        body: entry.body,
        cache_reason: None,
    }
}

fn headers_vec(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|s| (k.as_str().to_string(), s.to_string()))
        })
        .collect()
}

/// Preflight for the native Pingora cache path: HTTPS redirect, CC, rate-limit,
/// WAF and hotlink checks. Returns a response when the request must not reach
/// cache/origin. This mirrors the corresponding part of `proxy_handler`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn preflight_cacheable(
    state: &Arc<AppState>,
    domain: &DomainEntry,
    method: &Method,
    host: &str,
    path_only: &str,
    path_and_query: &str,
    headers: &HeaderMap,
    client_ip: &str,
    is_https: bool,
    start: Instant,
) -> Option<Response> {
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let referer = headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let request_id = headers
        .get("x-request-id")
        .or_else(|| headers.get("x-correlation-id"))
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .unwrap_or_else(uuid_like_request_id);
    let client_ip_addr: Option<IpAddr> = client_ip.parse().ok();

    if domain.ssl_enabled && !is_https {
        let status = if *method == Method::GET || *method == Method::HEAD {
            StatusCode::MOVED_PERMANENTLY
        } else {
            StatusCode::PERMANENT_REDIRECT
        };
        log_access(
            &state.access_log,
            method,
            host,
            path_only,
            status.as_u16(),
            start,
            client_ip,
            &user_agent,
            &referer,
            0,
            "HTTPS_REDIRECT",
            &request_id,
        )
        .await;
        return Some(https_redirect_response(
            host,
            path_and_query,
            status,
            state.https_redirect_port,
        ));
    }

    if let Some(ip) = client_ip_addr {
        let decision = state.cc.check(host, ip, &domain.cc).await;
        if decision != CcDecision::Allow {
            let banned = decision.is_banned();
            let action = if domain.cc.mode == CcMode::Monitor {
                "log"
            } else if banned {
                "cc-ban"
            } else {
                "cc-limit"
            };
            state
                .waf_log
                .push(
                    host,
                    client_ip,
                    method.as_str(),
                    path_and_query,
                    action,
                    "cc",
                    if banned {
                        "cc-auto-ban"
                    } else {
                        "cc-rate-limit"
                    },
                    if domain.cc.mode == CcMode::Block {
                        "block"
                    } else {
                        "monitor"
                    },
                )
                .await;
            if domain.cc.mode == CcMode::Block {
                if let CcDecision::Banned {
                    newly_banned: true, ..
                } = decision
                {
                    let control = state.control.clone();
                    let cc = state.cc.clone();
                    let report_host = host.to_string();
                    let report_ip = ip;
                    let seconds = domain.cc.ban_seconds;
                    tokio::spawn(async move {
                        let body = serde_json::json!({
                            "domain": report_host,
                            "ip": report_ip.to_string(),
                            "seconds": seconds,
                            "reason": "cc-auto-ban"
                        });
                        match control.post_json("/api/v1/cc/bans", &body).await {
                            Ok(()) => cc.mark_reported(&report_host, report_ip).await,
                            Err(e) => {
                                tracing::warn!(error = %e, "report shared CC ban failed")
                            }
                        }
                    });
                }
                log_access(
                    &state.access_log,
                    method,
                    host,
                    path_only,
                    429,
                    start,
                    client_ip,
                    &user_agent,
                    &referer,
                    0,
                    if banned { "CC-BAN" } else { "CC" },
                    &request_id,
                )
                .await;
                return Some(cc_too_many(host, path_only, decision.retry_after(), banned));
            }
        }
    }

    let rl_key = if host.is_empty() { "default" } else { host };
    if !state
        .rate_limiter
        .check(rl_key, domain.rate_limit_rps, domain.rate_limit_burst)
        .await
    {
        log_access(
            &state.access_log,
            method,
            host,
            path_only,
            429,
            start,
            client_ip,
            &user_agent,
            &referer,
            0,
            CacheStatus::None.as_str(),
            &request_id,
        )
        .await;
        return Some(default_page::rate_limited_page(
            host,
            path_only,
            1,
            false,
        ));
    }

    if domain.waf.enabled {
        let waf_request = WafRequest {
            method: method.as_str(),
            path: path_only,
            query: url_query(path_and_query),
            user_agent: &user_agent,
            referer: &referer,
            ip: client_ip_addr,
            headers,
        };
        if let Some(verdict) = waf_evaluate(&domain.waf, &waf_request) {
            if verdict.action != WafAction::Allow {
                let mode_is_block = domain.waf.mode == WafMode::Block;
                let challenge_capable = challenge_accepts_html(method, headers);
                let cleared = challenge::has_clearance(
                    headers,
                    host,
                    domain.waf.challenge_ttl_secs,
                    &state.challenge_secret,
                );
                let challenge_needed = verdict.action == WafAction::Challenge
                    && mode_is_block
                    && challenge_capable
                    && !cleared;
                let challenge_skipped =
                    verdict.action == WafAction::Challenge && mode_is_block && !challenge_capable;
                let blocked = mode_is_block && verdict.is_block();

                if challenge_needed
                    || blocked
                    || challenge_skipped
                    || verdict.action == WafAction::Log
                    || !mode_is_block
                {
                    let action = if blocked {
                        "block"
                    } else if challenge_needed {
                        "challenge"
                    } else if challenge_skipped {
                        "skip-challenge"
                    } else if verdict.action == WafAction::Log {
                        "log"
                    } else {
                        "monitor"
                    };
                    let mode = if mode_is_block { "block" } else { "monitor" };
                    state
                        .waf_log
                        .push(
                            host,
                            client_ip,
                            method.as_str(),
                            path_and_query,
                            action,
                            &verdict.category,
                            &verdict.rule_name,
                            mode,
                        )
                        .await;

                    if challenge_needed {
                        log_access(
                            &state.access_log,
                            method,
                            host,
                            path_only,
                            403,
                            start,
                            client_ip,
                            &user_agent,
                            &referer,
                            0,
                            "CHALLENGE",
                            &request_id,
                        )
                        .await;
                        let nonce = challenge::issue_nonce(host, &state.challenge_secret);
                        return Some(challenge::page(
                            host,
                            &nonce,
                            path_and_query,
                            domain.waf.challenge_difficulty,
                            is_https,
                        ));
                    }

                    if blocked {
                        log_access(
                            &state.access_log,
                            method,
                            host,
                            path_only,
                            403,
                            start,
                            client_ip,
                            &user_agent,
                            &referer,
                            0,
                            "WAF",
                            &request_id,
                        )
                        .await;
                        return Some(default_page::waf_blocked_page(
                            host,
                            path_only,
                            &verdict.rule_name,
                            &verdict.category,
                        ));
                    }
                }
            }
        }
    }

    if !domain.hotlink_allow_referers.is_empty()
        && !hotlink_allowed(&domain.hotlink_allow_referers, &referer)
    {
        log_access(
            &state.access_log,
            method,
            host,
            path_only,
            403,
            start,
            client_ip,
            &user_agent,
            &referer,
            0,
            CacheStatus::None.as_str(),
            &request_id,
        )
        .await;
        return Some((StatusCode::FORBIDDEN, "Hotlink Forbidden").into_response());
    }

    None
}

fn url_query(path_and_query: &str) -> &str {
    path_and_query.split_once('?').map(|(_, q)| q).unwrap_or("")
}

pub(crate) fn hotlink_allowed(allowed_list: &str, referer: &str) -> bool {
    allowed_list
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .any(|pat| pat == "*" || (!referer.is_empty() && referer.contains(pat)))
}

/// JS challenges require a top-level HTML document navigation. JSON/XHR
/// requests (login, fetch, API calls) cannot execute the challenge page.
pub(crate) fn challenge_accepts_html(method: &Method, headers: &HeaderMap) -> bool {
    if method != Method::GET && method != Method::HEAD {
        return false;
    }
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("text/html"))
        .unwrap_or(false)
}

fn header_ip_from_headers(headers: &HeaderMap) -> Option<IpAddr> {
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            if let Ok(ip) = first.trim().parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }
    if let Some(real) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        if let Ok(ip) = real.trim().parse::<IpAddr>() {
            return Some(ip);
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn log_access(
    log: &AccessLog,
    method: &Method,
    host: &str,
    path: &str,
    status: u16,
    start: Instant,
    client_ip: &str,
    user_agent: &str,
    referer: &str,
    bytes: u64,
    cache_status: &str,
    request_id: &str,
) {
    let ms = start.elapsed().as_millis() as u64;
    let rec = log.record(
        client_ip,
        method.as_str(),
        host,
        path,
        status,
        bytes,
        ms,
        cache_status,
        user_agent,
        referer,
        request_id,
    );
    log.write(rec).await;
}

fn uuid_like_request_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("lr-{:x}", nanos)
}

pub(crate) fn apply_security_headers(headers: &mut HeaderMap) {
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

pub(crate) fn apply_cors_and_custom(headers: &mut HeaderMap, cors: &str, custom: &str) {
    if !cors.is_empty() {
        let origin = if cors.trim() == "*" {
            "*"
        } else {
            cors.split(',').next().map(str::trim).unwrap_or("*")
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

fn cache_status_headers(headers: &mut HeaderMap, label: &str) {
    if let Ok(v) = HeaderValue::from_str(label) {
        headers.insert(HeaderName::from_static("x-cache"), v.clone());
        headers.insert(HeaderName::from_static("x-cache-status"), v);
    }
}

fn entry_to_response(
    entry: CacheEntry,
    cache_status: &str,
    etag: &str,
    cors: &str,
    custom: &str,
    browser_ttl: Option<u64>,
) -> Response {
    let status = StatusCode::from_u16(entry.status).unwrap_or(StatusCode::OK);
    let mut headers = HeaderMap::new();
    for (k, v) in &entry.headers {
        if is_uncacheable_header(k) || k.eq_ignore_ascii_case("x-lagran-pingora-meta") {
            continue;
        }
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            headers.insert(name, val);
        }
    }
    cache_status_headers(&mut headers, cache_status);
    headers.insert(
        HeaderName::from_static("age"),
        HeaderValue::from_str(&entry.age_secs().to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0")),
    );
    headers.insert(
        HeaderName::from_static("x-powered-by"),
        HeaderValue::from_static("lagran-edge"),
    );
    if let Ok(v) = HeaderValue::from_str(etag) {
        headers.insert(header::ETAG, v);
    }
    apply_browser_ttl(&mut headers, browser_ttl);
    apply_security_headers(&mut headers);
    apply_cors_and_custom(&mut headers, cors, custom);
    let mut resp = Response::new(Body::from(entry.body));
    *resp.status_mut() = status;
    *resp.headers_mut() = headers;
    resp
}

fn origin_response(
    resp: OriginResponse,
    cache_status: &str,
    etag: &str,
    cors: &str,
    custom: &str,
    browser_ttl: Option<u64>,
) -> Response {
    let reason = resp.cache_reason;
    let mut headers = resp.headers;
    strip_response_headers(&mut headers);
    headers.remove(HeaderName::from_static("x-lagran-pingora-meta"));
    cache_status_headers(&mut headers, cache_status);
    headers.insert(
        HeaderName::from_static("x-powered-by"),
        HeaderValue::from_static("lagran-edge"),
    );
    if !headers.contains_key(header::ETAG) {
        if let Ok(v) = HeaderValue::from_str(etag) {
            headers.insert(header::ETAG, v);
        }
    }
    apply_browser_ttl(&mut headers, browser_ttl);
    apply_security_headers(&mut headers);
    apply_cors_and_custom(&mut headers, cors, custom);
    let mut out = Response::new(Body::from(resp.body));
    *out.status_mut() = resp.status;
    *out.headers_mut() = headers;
    set_cache_reason(&mut out, reason);
    out
}

fn pass_through_response(
    resp: OriginResponse,
    cache_status: &str,
    cors: &str,
    custom: &str,
) -> Response {
    let reason = resp.cache_reason;
    let mut headers = resp.headers;
    strip_response_headers(&mut headers);
    headers.remove(HeaderName::from_static("x-lagran-pingora-meta"));
    cache_status_headers(&mut headers, cache_status);
    headers.insert(
        HeaderName::from_static("x-powered-by"),
        HeaderValue::from_static("lagran-edge"),
    );
    apply_security_headers(&mut headers);
    apply_cors_and_custom(&mut headers, cors, custom);
    let mut out = Response::new(Body::from(resp.body));
    *out.status_mut() = resp.status;
    *out.headers_mut() = headers;
    set_cache_reason(&mut out, reason);
    out
}

fn set_cache_reason(response: &mut Response, reason: Option<&'static str>) {
    if let Some(reason) = reason {
        if let Ok(value) = HeaderValue::from_str(reason) {
            response
                .headers_mut()
                .insert(HeaderName::from_static("x-lagran-cache-reason"), value);
        }
    }
}

pub(crate) fn cc_too_many(host: &str, path: &str, retry_after: u64, banned: bool) -> Response {
    default_page::rate_limited_page(host, path, retry_after, banned)
}

fn not_modified_response(etag: &str) -> Response {
    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(etag) {
        headers.insert(header::ETAG, v);
    }
    cache_status_headers(&mut headers, CacheStatus::Revalidated.as_str());
    apply_security_headers(&mut headers);
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::NOT_MODIFIED;
    *resp.headers_mut() = headers;
    resp
}

fn host_without_port(host: &str) -> String {
    let host = host.trim();
    if host.starts_with('[') {
        if let Some(end) = host.find(']') {
            return host[..=end].to_string();
        }
    }
    match host.rsplit_once(':') {
        Some((name, port)) if port.chars().all(|c| c.is_ascii_digit()) => name.to_string(),
        _ => host.to_string(),
    }
}

pub(crate) fn https_redirect_response(
    host: &str,
    path_and_query: &str,
    status: StatusCode,
    port: Option<u16>,
) -> Response {
    let mut authority = host_without_port(host);
    if let Some(p) = port.filter(|p| *p != 443) {
        authority = format!("{authority}:{p}");
    }
    let location = format!("https://{authority}{path_and_query}");
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    let headers = response.headers_mut();
    match HeaderValue::from_str(&location) {
        Ok(v) => {
            headers.insert(header::LOCATION, v);
        }
        Err(_) => {
            headers.insert(header::LOCATION, HeaderValue::from_static("/"));
        }
    }
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        HeaderName::from_static("x-lagran-redirect"),
        HeaderValue::from_static("https"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn challenge_only_for_html_document_navigation() {
        let html = Request::builder()
            .method("GET")
            .header("accept", "text/html,application/xhtml+xml")
            .body(())
            .unwrap();
        assert!(challenge_accepts_html(html.method(), html.headers()));

        let api = Request::builder()
            .method("POST")
            .header("accept", "application/json")
            .body(())
            .unwrap();
        assert!(!challenge_accepts_html(api.method(), api.headers()));

        let fetch = Request::builder()
            .method("GET")
            .header("accept", "*/*")
            .body(())
            .unwrap();
        assert!(!challenge_accepts_html(fetch.method(), fetch.headers()));
    }

    #[test]
    fn hotlink_rules() {
        assert!(hotlink_allowed("*", ""));
        assert!(hotlink_allowed(
            "example.com, foo.com",
            "https://example.com/a"
        ));
        assert!(!hotlink_allowed("example.com", "https://evil.test/a"));
        assert!(!hotlink_allowed("example.com", ""));
    }

    #[test]
    fn cache_status_headers_are_set() {
        let mut h = HeaderMap::new();
        cache_status_headers(&mut h, "HIT");
        assert_eq!(h.get("x-cache").unwrap(), "HIT");
        assert_eq!(h.get("x-cache-status").unwrap(), "HIT");
    }

    #[test]
    fn cached_entry_is_served_without_set_cookie_or_age() {
        let entry = CacheEntry::new(
            200,
            vec![
                ("content-type".into(), "text/plain".into()),
                ("set-cookie".into(), "sid=1".into()),
                ("age".into(), "999".into()),
            ],
            Bytes::from_static(b"hi"),
        );
        let resp = entry_to_response(entry, "HIT", "\"abc\"", "", "", None);
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get("set-cookie").is_none());
        assert_eq!(resp.headers().get("age").unwrap(), "0");
        assert_eq!(resp.headers().get("x-cache").unwrap(), "HIT");
    }
}
