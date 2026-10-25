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
use crate::agent::NodeControl;
use crate::cache::policy::{
    cache_key_for, compute_etag, decide_storage, etag_matches, is_uncacheable_header,
    request_bypasses_cache, request_method_cacheable, resolve_rule_policy, strip_response_headers,
    CacheStatus, ResolvedPolicy, RuleAction, RuleSet,
};
use crate::cache::{CacheEntry, CacheGetResult, SharedCache};
use crate::config::registry::DomainRegistry;
use crate::metrics::EdgeMetrics;
use crate::origin::{OriginClient, OriginResponse};
use crate::server::access_log::AccessLog;
use crate::server::acme_challenge::ChallengeStore;
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
const MAX_CACHE_OBJECT: usize = 8 * 1024 * 1024;
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
}

/// Per-request view of the effective domain configuration.
struct Effective<'a> {
    origin_url: String,
    backup_url: String,
    policy: ResolvedPolicy,
    ignore_query: bool,
    cors: String,
    custom_headers: String,
    timeout_ms: u64,
    hotlink: &'a str,
    rate_limit_rps: u32,
    rate_limit_burst: u32,
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
    let headers = req.headers().clone();
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
        )
        .await;
        return default_page::node_disabled_page(&host);
    }

    let domain_entry = state.domains.get(&host).await;
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
        )
        .await;
        return default_page::unknown_domain_page(display);
    }

    // Resolve the effective config once; rules stay per-domain so two hosted
    // domains can never influence each other's TTL/action.
    let eff = match domain_entry {
        Some(ref e) => Effective {
            origin_url: e.origin_url.clone(),
            backup_url: e.backup_origin_url.clone(),
            policy: resolve_rule_policy(&e.rules, &path_only),
            ignore_query: e.ignore_query_string,
            cors: e.cors_origins.clone(),
            custom_headers: e.custom_headers.clone(),
            timeout_ms: u64::from(if e.origin_timeout_ms == 0 {
                10_000
            } else {
                e.origin_timeout_ms
            }),
            hotlink: e.hotlink_allow_referers.as_str(),
            rate_limit_rps: e.rate_limit_rps,
            rate_limit_burst: e.rate_limit_burst,
        },
        None => {
            // Legacy single-origin mode: only reachable while the registry is
            // empty. Global rules are the best available approximation here.
            let policy = state.rules.resolve(&path_only).await.unwrap_or_default();
            Effective {
                origin_url: state.origin.base_url().await,
                backup_url: String::new(),
                policy,
                ignore_query: false,
                cors: String::new(),
                custom_headers: String::new(),
                timeout_ms: 10_000,
                hotlink: "",
                rate_limit_rps: 0,
                rate_limit_burst: 0,
            }
        }
    };

    // Rate limit per host.
    let rl_key = if host.is_empty() {
        "default"
    } else {
        host.as_str()
    };
    if !state
        .rate_limiter
        .check(rl_key, eff.rate_limit_rps, eff.rate_limit_burst)
        .await
    {
        log_access(
            &state.access_log,
            &method,
            &host,
            &path_only,
            429,
            start,
            &client_ip,
            &user_agent,
            &referer,
            0,
            CacheStatus::None.as_str(),
        )
        .await;
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", "1")],
            "Too Many Requests",
        )
            .into_response();
    }

    // WAF runs before cache/向源站: blocked requests never touch the origin.
    if let Some(ref entry) = domain_entry {
        if entry.waf.enabled {
            let waf_request = WafRequest {
                method: method.as_str(),
                path: &path_only,
                query: req.uri().query().unwrap_or(""),
                user_agent: &user_agent,
                referer: &referer,
                ip: client_ip_addr,
                headers: &headers,
            };
            if let Some(verdict) = waf_evaluate(&entry.waf, &waf_request) {
                if verdict.action != WafAction::Allow {
                    let mode_is_block = entry.waf.mode == WafMode::Block;
                    let challenge_method = method == Method::GET || method == Method::HEAD;
                    let cleared = challenge::has_clearance(
                        &headers,
                        &host,
                        entry.waf.challenge_ttl_secs,
                        &state.challenge_secret,
                    );
                    // A challenge only makes sense for a document navigation;
                    // non-GET requests in block mode are rejected outright.
                    let challenge_needed = verdict.action == WafAction::Challenge
                        && mode_is_block
                        && challenge_method
                        && !cleared;
                    let blocked = mode_is_block
                        && (verdict.is_block()
                            || (verdict.action == WafAction::Challenge && !challenge_method));

                    if challenge_needed
                        || blocked
                        || verdict.action == WafAction::Log
                        || !mode_is_block
                    {
                        let action = if blocked {
                            "block"
                        } else if challenge_needed {
                            "challenge"
                        } else if verdict.action == WafAction::Log {
                            "log"
                        } else {
                            "monitor"
                        };
                        let mode = if mode_is_block { "block" } else { "monitor" };
                        state
                            .waf_log
                            .push(
                                &host,
                                &client_ip,
                                method.as_str(),
                                &path_and_query,
                                action,
                                &verdict.category,
                                &verdict.rule_name,
                                mode,
                            )
                            .await;

                        if challenge_needed {
                            tracing::info!(
                                %host, %client_ip, rule = %verdict.rule_name,
                                "serving WAF challenge"
                            );
                            log_access(
                                &state.access_log,
                                &method,
                                &host,
                                &path_only,
                                403,
                                start,
                                &client_ip,
                                &user_agent,
                                &referer,
                                0,
                                "CHALLENGE",
                            )
                            .await;
                            let nonce = challenge::issue_nonce(&host, &state.challenge_secret);
                            let secure = req.extensions().get::<host_util::TlsSni>().is_some()
                                || headers
                                    .get("x-forwarded-proto")
                                    .and_then(|v| v.to_str().ok())
                                    .map(|v| v.eq_ignore_ascii_case("https"))
                                    .unwrap_or(false);
                            return challenge::page(
                                &host,
                                &nonce,
                                &path_and_query,
                                entry.waf.challenge_difficulty,
                                secure,
                            );
                        }

                        if blocked {
                            tracing::warn!(
                                %host, %client_ip, rule = %verdict.rule_name,
                                category = %verdict.category, "request blocked by WAF"
                            );
                            log_access(
                                &state.access_log,
                                &method,
                                &host,
                                &path_only,
                                403,
                                start,
                                &client_ip,
                                &user_agent,
                                &referer,
                                0,
                                "WAF",
                            )
                            .await;
                            return default_page::waf_blocked_page(
                                &host,
                                &path_only,
                                &verdict.rule_name,
                                &verdict.category,
                            );
                        }
                    }
                }
            }
        }
    }

    // NOTE: origin health is checked where an origin fetch is actually needed
    // (below), not here: a fresh cache hit must still be served while the
    // origin is down.

    // WebSocket upgrade → handshake with origin, then raw byte tunnel.
    if websocket::is_websocket_upgrade(&headers) {
        let resp = websocket::handle_upgrade(
            req,
            &eff.origin_url,
            &path_and_query,
            &headers,
            eff.timeout_ms,
        )
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
        )
        .await;
        return resp;
    }

    // Hotlink protection.
    if !eff.hotlink.is_empty() && !hotlink_allowed(eff.hotlink, &referer) {
        log_access(
            &state.access_log,
            &method,
            &host,
            &path_only,
            403,
            start,
            &client_ip,
            &user_agent,
            &referer,
            0,
            CacheStatus::None.as_str(),
        )
        .await;
        return (StatusCode::FORBIDDEN, "Hotlink Forbidden").into_response();
    }

    let request_cacheable = request_method_cacheable(&method)
        && !request_bypasses_cache(&req)
        && eff.policy.action == RuleAction::Cache;

    if !request_cacheable {
        return bypass_to_origin(
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
            start,
        )
        .await;
    }

    let cache_lookup_path = if eff.ignore_query {
        path_only.clone()
    } else {
        path_and_query.clone()
    };
    let key = cache_key_for(&method, &host, &cache_lookup_path);

    let lookup = state.cache.get_result(&key).await;
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
                path_and_query.clone(),
                headers.clone(),
                eff.timeout_ms,
                eff.policy,
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
                    )
                    .await;
                    origin_response(
                        resp,
                        CacheStatus::Hit.as_str(),
                        &etag,
                        &eff.cors,
                        &eff.custom_headers,
                    )
                }
                Ok((Fetched::FromOrigin(resp), _)) => {
                    let status = resp.status;
                    let body_len = resp.body.len() as u64;
                    let etag = entry_etag(&resp);
                    if (200..300).contains(&status.as_u16()) {
                        state.metrics.record_miss(&host, body_len).await;
                    } else {
                        state.metrics.record_bypass(&host, body_len).await;
                    }
                    let label = if from_expired {
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
    eff: &Effective<'_>,
    method: &Method,
    host: &str,
    path_and_query: &str,
    path_only: &str,
    headers: &HeaderMap,
    client_ip: &str,
    user_agent: &str,
    referer: &str,
    start: Instant,
) -> Response {
    let label = if request_method_cacheable(method) {
        CacheStatus::Bypass
    } else {
        CacheStatus::Dynamic
    };

    // Fail fast with the same page used by the cache path when the origin is
    // already known to be down.
    if !state.origin_health.is_healthy(host).await {
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
        )
        .await;
        return default_page::origin_error_page(host, path_only, OriginFailure::Unhealthy);
    }

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
            )
            .await;
            return (StatusCode::PAYLOAD_TOO_LARGE, "Payload Too Large").into_response();
        }
    };

    let result = tokio::time::timeout(
        Duration::from_millis(eff.timeout_ms),
        state.origin.request(
            &eff.origin_url,
            method,
            path_and_query,
            headers,
            Some(body),
            true,
        ),
    )
    .await;

    match result {
        Err(_) => {
            log_access(
                &state.access_log,
                method,
                host,
                path_only,
                504,
                start,
                client_ip,
                user_agent,
                referer,
                0,
                OriginFailure::Timeout.log_label(),
            )
            .await;
            default_page::origin_error_page(host, path_only, OriginFailure::Timeout)
        }
        Ok(Err(e)) => {
            tracing::warn!(error = %e, origin = %eff.origin_url, "origin fetch failed");
            log_access(
                &state.access_log,
                method,
                host,
                path_only,
                502,
                start,
                client_ip,
                user_agent,
                referer,
                0,
                OriginFailure::Unreachable.log_label(),
            )
            .await;
            default_page::origin_error_page(host, path_only, OriginFailure::Unreachable)
        }
        Ok(Ok(resp)) => {
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
            )
            .await;
            out
        }
    }
}

/// Fetch with request coalescing: one leader per cache key; followers wait for
/// the leader and re-read the cache before falling back to their own fetch.
async fn fetch_with_single_flight(
    state: &Arc<AppState>,
    key: &str,
    eff: &Effective<'_>,
    path_and_query: &str,
    headers: &HeaderMap,
    method: &Method,
    host: &str,
) -> Result<(Fetched, bool), FetchError> {
    match state.inflight.begin(key).await {
        Slot::Leader(leader) => {
            let result = fetch_origin(state, eff, host, path_and_query, headers, method).await;
            if let Ok(resp) = &result {
                if let Some(decision) = decide_storage(
                    resp.status.as_u16(),
                    &headers_vec(&resp.headers),
                    eff.policy,
                    state.default_ttl_secs,
                ) {
                    if resp.body.len() <= MAX_CACHE_OBJECT {
                        let entry = clone_as_entry(resp);
                        state
                            .cache
                            .set_with_swr(key, entry, decision.ttl_secs, decision.swr_secs)
                            .await;
                    } else {
                        tracing::debug!(len = resp.body.len(), %host, "object too large to cache");
                    }
                }
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

async fn fetch_origin(
    state: &AppState,
    eff: &Effective<'_>,
    host: &str,
    path_and_query: &str,
    headers: &HeaderMap,
    method: &Method,
) -> Result<OriginResponse, FetchError> {
    if !state.origin_health.is_healthy(host).await {
        return Err(FetchError::Unhealthy);
    }

    let timeout = Duration::from_millis(eff.timeout_ms);
    let attempt = |url: String| {
        let origin = state.origin.clone();
        let method = method.clone();
        let headers = headers.clone();
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

    match attempt(eff.origin_url.clone()).await {
        Ok(r) => Ok(r),
        Err(primary_err) => {
            if eff.backup_url.is_empty() {
                return Err(primary_err);
            }
            tracing::warn!(origin = %eff.origin_url, error = %primary_err, "primary origin failed, trying backup");
            attempt(eff.backup_url.clone()).await
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_revalidation(
    state: Arc<AppState>,
    key: String,
    host: String,
    origin_url: String,
    backup_url: String,
    path_and_query: String,
    headers: HeaderMap,
    timeout_ms: u64,
    policy: ResolvedPolicy,
) {
    tokio::spawn(async move {
        let Slot::Leader(leader) = state.inflight.begin(&key).await else {
            return;
        };
        let eff = Effective {
            origin_url,
            backup_url,
            policy,
            ignore_query: false,
            cors: String::new(),
            custom_headers: String::new(),
            timeout_ms,
            hotlink: "",
            rate_limit_rps: 0,
            rate_limit_burst: 0,
        };
        match fetch_origin(&state, &eff, &host, &path_and_query, &headers, &Method::GET).await {
            Ok(resp) => {
                if let Some(decision) = decide_storage(
                    resp.status.as_u16(),
                    &headers_vec(&resp.headers),
                    policy,
                    state.default_ttl_secs,
                ) {
                    if resp.body.len() <= MAX_CACHE_OBJECT {
                        let entry = resp.into_entry();
                        state
                            .cache
                            .set_with_swr(&key, entry, decision.ttl_secs, decision.swr_secs)
                            .await;
                        tracing::debug!(%key, "revalidated stale entry");
                    }
                }
            }
            Err(e) => tracing::warn!(%key, error = %e, "background revalidation failed"),
        }
        leader.finish().await;
    });
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
    if_none_match: Option<&str>,
    eff: &Effective<'_>,
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
    )
    .await;
    entry_to_response(entry, label.as_str(), &etag, &eff.cors, &eff.custom_headers)
}

fn entry_etag(resp: &OriginResponse) -> String {
    if let Some(v) = resp.headers.get(header::ETAG).and_then(|v| v.to_str().ok()) {
        return v.to_string();
    }
    compute_etag(&clone_as_entry(resp))
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

fn hotlink_allowed(allowed_list: &str, referer: &str) -> bool {
    allowed_list
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .any(|pat| pat == "*" || (!referer.is_empty() && referer.contains(pat)))
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
async fn log_access(
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
    );
    log.write(rec).await;
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

fn apply_cors_and_custom(headers: &mut HeaderMap, cors: &str, custom: &str) {
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
) -> Response {
    let status = StatusCode::from_u16(entry.status).unwrap_or(StatusCode::OK);
    let mut headers = HeaderMap::new();
    for (k, v) in &entry.headers {
        if is_uncacheable_header(k) {
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
) -> Response {
    let mut headers = resp.headers;
    strip_response_headers(&mut headers);
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
    apply_security_headers(&mut headers);
    apply_cors_and_custom(&mut headers, cors, custom);
    let mut out = Response::new(Body::from(resp.body));
    *out.status_mut() = resp.status;
    *out.headers_mut() = headers;
    out
}

fn pass_through_response(
    resp: OriginResponse,
    cache_status: &str,
    cors: &str,
    custom: &str,
) -> Response {
    let mut headers = resp.headers;
    strip_response_headers(&mut headers);
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
    out
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

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

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
        let resp = entry_to_response(entry, "HIT", "\"abc\"", "", "");
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get("set-cookie").is_none());
        assert_eq!(resp.headers().get("age").unwrap(), "0");
        assert_eq!(resp.headers().get("x-cache").unwrap(), "HIT");
    }
}
