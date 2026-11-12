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
use crate::cache::flight::RedisFlight;
use crate::cache::policy::{
    compute_etag, decide_storage_reason, etag_matches, is_uncacheable_header,
    request_method_cacheable, resolve_rule_policy, resolve_rule_policy_for_response_with_domain,
    strip_response_headers, CacheDecision, CacheRule, CacheStatus, ResolvedPolicy, RuleAction,
    RuleSet, VALIDATOR_SOURCE_HEADER,
};
use crate::cache::{CacheEntry, CacheGetResult, LargeCache, SharedCache};
use crate::config::registry::{DomainEntry, DomainRegistry, OriginTarget};
use crate::metrics::EdgeMetrics;
use crate::origin::{OriginClient, OriginResponse};
use crate::server::access_log::AccessLog;
use crate::server::acme_challenge::ChallengeStore;
use crate::server::bot_guard;
use crate::server::cc::{CcDecision, CcMode, CcProtector};
use crate::server::cert_store::CertStore;
use crate::server::challenge;
use crate::server::default_page::{self, OriginFailure};
use crate::server::host_util;
use crate::server::inflight::{self, Inflight, Slot};
use crate::server::pipeline::{facts_from_request, RequestPipeline};
use crate::server::rate_limit::RateLimiter;
use crate::server::response_headers::ResponseHeaderOverrides;
use crate::server::waf_log::WafLog;
use crate::server::websocket;
use crate::waf::{evaluate as waf_evaluate, WafAction, WafMode, WafRequest};
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use http_body_util::{BodyExt, Limited};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Largest request body we are willing to buffer for pass-through traffic.
const MAX_PROXY_BODY: usize = 16 * 1024 * 1024;
/// Largest origin object we keep in the cache.
/// How long a follower waits for the in-flight fetch before fetching itself.
const FETCH_WAIT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct AppState {
    pub cache: SharedCache,
    /// Cross-node cold-miss coalescing; None when Redis L2 is disabled.
    pub flight: Option<Arc<RedisFlight>>,
    /// Separate streaming disk cache for large objects; disabled when None.
    pub large_cache: Option<Arc<LargeCache>>,
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
    /// Networks whose `X-Forwarded-*` headers may be believed.
    pub trusted_proxies: crate::security::trusted_proxy::TrustedProxies,
    /// HMAC secret for challenge nonces and clearance cookies.
    pub challenge_secret: String,
    /// MaxMind-backed country/ASN lookup for the WAF Geo/ASN lists.
    pub geo: Arc<crate::waf::geo::GeoLookup>,
    /// Set from the heartbeat reply; disabled nodes answer 503 and keep serving
    /// management/health endpoints.
    pub node_control: NodeControl,
    /// Port used when redirecting HTTP to HTTPS (None = 443).
    pub https_redirect_port: Option<u16>,
    /// Responses larger than this are proxied but not stored in cache.
    pub max_cacheable_body: usize,
    /// Pre-compressed response variants, keyed by identity cache key + ETag.
    /// Keeps gzip out of the per-request path for repeat hits.
    pub compressed: Arc<lagran_cache::MemoryCache>,
    /// Header names intentionally excluded from the shared-cache key.
    pub cache_key_ignore_headers: Vec<String>,
    /// Idle origin read timeout; separate from per-domain connect timeout.
    pub origin_read_timeout_ms: u64,
    pub origin_stream_read_timeout_ms: u64,
    pub range_fill_max_bytes: u64,
    pub downstream_keepalive_secs: u64,
    pub downstream_h2_idle_secs: u64,
    pub downstream_keepalive_requests: u32,
    pub websocket_idle_secs: u64,
    /// Loopback address of the public Pingora HTTP listener, used by internal
    /// prefetch so it goes through the native cache/large-cache data plane.
    pub local_http_addr: SocketAddr,
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
    key_ignore: u8,
    key_ignore_headers: String,
    response_headers: Arc<ResponseHeaderOverrides>,
    origin_auth_header: String,
    origin_auth_value: String,
    timeout_ms: u64,
}

static HANDLER_ORIGIN_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Weighted, health-aware origin order for the legacy handler path.
async fn origin_sequence(state: &AppState, host: &str, eff: &Effective) -> Vec<OriginTarget> {
    let mut pool = if eff.origins.is_empty() {
        let mut list = vec![OriginTarget {
            url: eff.origin_url.clone(),
            weight: 100,
            priority: 0,
            enabled: true,
            host_header: None,
            sni: None,
        }];
        if !eff.backup_url.is_empty() {
            list.push(OriginTarget {
                url: eff.backup_url.clone(),
                weight: 100,
                priority: 1,
                enabled: true,
                host_header: None,
                sni: None,
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

/// Legacy-only entry point.
///
/// Normal GET/HEAD, Range, no-cache and cache revalidation are handled by the
/// Pingora data plane. This function is retained for WebSocket, management-
/// adjacent fallbacks, and requests where a native plan cannot be built.
pub async fn proxy_handler(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    state.metrics.record_legacy_datapath();
    let is_ws = websocket::is_websocket_upgrade(req.headers());
    let is_cache_method = req.method() == Method::GET || req.method() == Method::HEAD;
    // Expected fallbacks are observable in the access log. Log once per
    // process instead of once per request: a high-QPS HEAD or revalidation
    // workload made this line dominate the log by several orders of magnitude.
    if is_cache_method && !is_ws {
        static FALLBACK_LOGGED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        if FALLBACK_LOGGED.set(()).is_ok() {
            tracing::debug!(
                host = %host_util::resolve_request_host(&req),
                method = %req.method(),
                path = %req.uri().path(),
                "legacy GET/HEAD fallback reached; later requests are summarized in the access log"
            );
        }
    }
    let mut response = proxy_handler_inner(State(state), req).await;
    response.headers_mut().insert(
        HeaderName::from_static("x-lagran-datapath"),
        HeaderValue::from_static("legacy"),
    );
    response
}

async fn proxy_handler_inner(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    let start = Instant::now();
    let method = req.method().clone();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let path_only = req.uri().path().to_string();
    let host = host_util::resolve_request_host(&req);
    let peer_addr = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0);
    let mut headers = req.headers().clone();
    // Client identity comes from the shared trusted-proxy resolver so this data
    // plane and the Pingora one cannot disagree. Taking the leftmost
    // `X-Forwarded-For` entry let any client choose its own source IP, which
    // bypassed WAF IP deny lists and CC bans.
    let identity = crate::security::trusted_proxy::resolve(
        &state.trusted_proxies,
        peer_addr,
        headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()),
        headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok()),
        host_util::request_is_tls(&req),
    );
    let client_ip = identity
        .ip
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
        .unwrap_or_else(uuid_like_request_id);
    let if_none_match = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    if let Err(violation) =
        crate::security::header_guard::validate(&headers, req.uri(), &method, req.version())
    {
        log_access(
            &state.access_log,
            &method,
            &host,
            &path_only,
            400,
            start,
            &client_ip,
            &user_agent,
            &referer,
            0,
            CacheStatus::Bypass.as_str(),
            &request_id,
        )
        .await;
        tracing::warn!(reason = violation.reason, "request header rejected");
        return (StatusCode::BAD_REQUEST, "bad request headers").into_response();
    }

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

    let (registry_empty, domain_entry) = state.domains.lookup(&host).await;

    // Signed-URL enforcement for the in-process data plane.
    //
    // The Pingora request filter is not the only ingress: HEAD, Range,
    // `Cache-Control: no-cache`, WebSocket and every request without a native
    // plan fall back here. With the check only on the native path, adding a
    // single request header was enough to bypass `signed_url_mode=all`, so the
    // same verification has to run here. On success the signature parameters
    // are removed so they never reach the cache key or the origin.
    let req = match domain_entry.as_ref() {
        Some(domain) => match signed_url_gate(domain, req, &host).await {
            SignedUrlGate::Pass(req) | SignedUrlGate::Signed(req) => req,
            SignedUrlGate::Reject => {
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
                    CacheStatus::Bypass.as_str(),
                    &request_id,
                )
                .await;
                return (StatusCode::FORBIDDEN, "invalid or expired signed url").into_response();
            }
        },
        None => req,
    };

    // Domain-level HTTPS enforcement: redirect plain HTTP before WAF/cache so
    // the browser continues over TLS (and secure challenge cookies stick).
    // Scheme decided by the shared resolver: TLS we terminated ourselves, or an
    // `X-Forwarded-Proto` from a peer in TRUSTED_PROXIES. Reading the header
    // whenever `trust_proxy_headers` was on let a direct client assert HTTPS.
    let is_https = identity.is_https;

    if domain_entry.is_none() && !registry_empty {
        // A request without any host source cannot be attributed to a tenant.
        // Do not write an access-log row with an empty host: the console would
        // show it as an anonymous `—` row and it could not be filtered or
        // authorized per domain. Keep the rejection visible in the process log.
        if host.is_empty() {
            tracing::warn!(
                client_ip = %client_ip,
                method = %method,
                path = %path_only,
                "hostless request rejected; access-log row omitted"
            );
            return default_page::missing_host_page();
        }
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
        return default_page::unknown_domain_page(&host);
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
                key_ignore: policy.key_ignore,
                key_ignore_headers: e.cache_key_ignore_headers.clone(),
                response_headers: e.response_headers.clone(),
                origin_auth_header: e.origin_auth_header.clone(),
                origin_auth_value: e.origin_auth_value.clone(),
                // Budget for the whole legacy request (WebSocket handshake,
                // conditional revalidation, pass-through). The per-domain
                // `origin_timeout_ms` is a TCP connect override, not this.
                timeout_ms: state.origin_read_timeout_ms,
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
                key_ignore: policy.key_ignore,
                key_ignore_headers: String::new(),
                policy,
                rules: Vec::new(),
                path: path_only.clone(),
                method: method.clone(),
                response_headers: ResponseHeaderOverrides::empty_arc(),
                origin_auth_header: String::new(),
                origin_auth_value: String::new(),
                timeout_ms: state.origin_read_timeout_ms,
            }
        }
    };

    // Single preflight implementation shared with the Pingora native path:
    // HTTPS redirect, CC, rate-limit, WAF and hotlink.
    if let Some(domain) = domain_entry.as_ref() {
        let pipeline = RequestPipeline::new(&state);
        let facts = facts_from_request(
            &req,
            &host,
            &path_only,
            &path_and_query,
            &client_ip,
            is_https,
            start,
        );
        if let Some(resp) = pipeline.preflight(domain, &facts).await {
            return resp;
        }
        headers.remove(crate::security::signed_url::HOTLINK_OK_HEADER);
    }

    // NOTE: origin health is checked where an origin fetch is actually needed
    // (below), not here: a fresh cache hit must still be served while the
    // origin is down.

    // WebSocket upgrade → handshake with origin, then raw byte tunnel.
    if websocket::is_websocket_upgrade(&headers) {
        crate::security::origin_auth::apply(
            &mut headers,
            &eff.origin_auth_header,
            &eff.origin_auth_value,
        );
        let ws_origin = origin_sequence(&state, &host, &eff)
            .await
            .first()
            .map(|o| o.url.clone())
            .unwrap_or_else(|| eff.origin_url.clone());
        let resp = websocket::handle_upgrade(
            req,
            &ws_origin,
            &path_and_query,
            &headers,
            eff.timeout_ms,
            state.websocket_idle_secs,
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
            &request_id,
        )
        .await;
        return resp;
    }

    let pipeline = RequestPipeline::new(&state);
    let class = pipeline.classify_request(&method, &headers, &eff.policy);
    let mut request_reason = class.reason();
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

    let key = pipeline.cache_key_with_ignore_query(
        &method,
        &host,
        &path_only,
        &path_and_query,
        &headers,
        eff.ignore_query,
        eff.key_ignore,
    );

    // Strict client revalidation (`no-cache` / `max-age=0` / Pragma) must not
    // reuse a fresh body blindly. If we already have a validator, make one
    // conditional origin request and either refresh the entry on 304 or replace
    // it on 200. Without a validator, fall through to the normal full fetch.
    let strict_revalidation = matches!(
        request_reason,
        Some("request-max-age-0" | "request-no-cache" | "request-pragma-no-cache")
    );
    if strict_revalidation {
        if let Some(response) = revalidate_cached_entry(
            &state,
            &key,
            &eff,
            &headers,
            &method,
            &host,
            &path_and_query,
            &path_only,
            &client_ip,
            &user_agent,
            &referer,
            &request_id,
            if_none_match.as_deref(),
            start,
        )
        .await
        {
            return response;
        }
        // A strict revalidation request with no usable cached representation
        // still needs to populate the cache. An older entry without validator
        // cannot answer a 304 and must be replaced by a full origin response.
        if !headers.contains_key(header::RANGE) {
            if let Some(entry) = state.cache.get(&key).await {
                let source = entry.header(VALIDATOR_SOURCE_HEADER).unwrap_or("");
                let has_upstream_validator = match source {
                    "etag" | "last-modified" => true,
                    "computed" => false,
                    _ => entry.header("etag").is_some() || entry.header("last-modified").is_some(),
                };
                if !has_upstream_validator {
                    tracing::debug!(key, "dropping cache entry without upstream validator");
                    state.cache.delete(&key).await;
                }
            }
            if state.cache.get(&key).await.is_none() {
                tracing::debug!(key, "cold revalidation bootstraps normal fetch");
                request_cacheable = true;
                request_reason = None;
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
            if strict_revalidation {
                Some(&key)
            } else {
                None
            },
        )
        .await;
        set_cache_reason(&mut response, request_reason);
        return response;
    }

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
            None,
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
                    state.metrics.record_hit(&host, body_len);
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
                        &eff.response_headers,
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
                    let response_policy = resolve_rule_policy_for_response_with_domain(
                        &eff.rules,
                        &eff.path,
                        method.as_str(),
                        path_and_query.split_once('?').map(|(_, q)| q).unwrap_or(""),
                        content_type,
                        &eff.key_ignore_headers,
                    );
                    let response_bypass = response_policy.action != RuleAction::Cache;
                    if !response_bypass && (200..300).contains(&status.as_u16()) {
                        state.metrics.record_miss(&host, body_len);
                    } else {
                        state.metrics.record_bypass(&host, body_len);
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
                        &eff.response_headers,
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
    cache_key: Option<&str>,
) -> Response {
    let label = if request_method_cacheable(method) {
        CacheStatus::Bypass
    } else {
        CacheStatus::Dynamic
    };
    if cache_key.is_none() {
        return bypass_to_origin_streaming(
            state,
            req,
            eff,
            method,
            host,
            path_and_query,
            path_only,
            headers,
            client_ip,
            user_agent,
            referer,
            request_id,
            start,
            label,
        )
        .await;
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
                request_id,
            )
            .await;
            return (StatusCode::PAYLOAD_TOO_LARGE, "Payload Too Large").into_response();
        }
    };

    let attempt = |target: OriginTarget| {
        let origin = state.origin.clone();
        let method = method.clone();
        let mut headers = headers.clone();
        if let Some(host) = target.host_header.as_deref() {
            if let Ok(value) = HeaderValue::from_str(host) {
                headers.insert(header::HOST, value);
            }
        }
        crate::security::origin_auth::apply(
            &mut headers,
            &eff.origin_auth_header,
            &eff.origin_auth_value,
        );
        let path = path_and_query.to_string();
        let body = body.clone();
        let max_body = state.max_cacheable_body;
        async move {
            match tokio::time::timeout(
                Duration::from_millis(eff.timeout_ms),
                origin.request_with_sni_limit(
                    &target.url,
                    &method,
                    &path,
                    &headers,
                    Some(body),
                    true,
                    target.sni.as_deref(),
                    max_body,
                ),
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
    for target in sequence {
        result = attempt(target.clone()).await;
        if result.is_ok() {
            break;
        }
        tracing::warn!(origin = %target.url, "origin failed, trying next origin");
    }

    match result {
        Ok(resp) => {
            let status = resp.status;
            let body_len = resp.body.len() as u64;
            if let Some(key) = cache_key {
                if request_method_cacheable(method) && (200..300).contains(&status.as_u16()) {
                    let content_type = resp
                        .headers
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    let response_policy = resolve_rule_policy_for_response_with_domain(
                        &eff.rules,
                        &eff.path,
                        method.as_str(),
                        path_and_query.split_once('?').map(|(_, q)| q).unwrap_or(""),
                        content_type,
                        &eff.key_ignore_headers,
                    );
                    if response_policy.action == RuleAction::Cache {
                        if let Ok(decision) = decide_storage_reason(
                            status.as_u16(),
                            &headers_vec(&resp.headers),
                            response_policy,
                            state.default_ttl_secs,
                        ) {
                            if resp.body.len() <= state.max_cacheable_body {
                                state
                                    .cache
                                    .set_with_swr(
                                        key,
                                        clone_as_entry(&resp),
                                        decision.ttl_secs,
                                        decision.swr_secs,
                                    )
                                    .await;
                            } else {
                                store_large_response(state, key, &resp, decision).await;
                            }
                        }
                    }
                }
            }
            let out = pass_through_response(resp, label.as_str(), &eff.response_headers);
            state.metrics.record_bypass(host, body_len);
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
                request_id,
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
                request_id,
            )
            .await;
            default_page::origin_error_page(host, path_only, failure)
        }
    }
}

/// Streaming bypass path for legacy traffic (Range, cookie/auth, rules).
/// Status/headers are bounded by the domain origin timeout; the body uses an
/// idle timeout per chunk so a long media response is never aborted just for
/// exceeding the total timeout.
#[allow(clippy::too_many_arguments)]
async fn bypass_to_origin_streaming(
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
    label: CacheStatus,
) -> Response {
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
                request_id,
            )
            .await;
            return (StatusCode::PAYLOAD_TOO_LARGE, "Payload Too Large").into_response();
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

    let header_timeout = Duration::from_millis(state.origin_stream_read_timeout_ms.max(1_000));
    let idle_timeout = Duration::from_millis(state.origin_stream_read_timeout_ms.max(1_000));
    let mut result = Err(FetchError::Unhealthy);
    for target in sequence {
        let mut target_headers = headers.clone();
        if let Some(host) = target.host_header.as_deref() {
            if let Ok(value) = HeaderValue::from_str(host) {
                target_headers.insert(header::HOST, value);
            }
        }
        crate::security::origin_auth::apply(
            &mut target_headers,
            &eff.origin_auth_header,
            &eff.origin_auth_value,
        );
        let attempt = tokio::time::timeout(
            header_timeout,
            state.origin.request_stream_with_sni(
                &target.url,
                method,
                path_and_query,
                &target_headers,
                Some(body.clone()),
                true,
                target.sni.as_deref(),
            ),
        )
        .await;
        result = match attempt {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(e)) => Err(FetchError::Failed(e.to_string())),
            Err(_) => Err(FetchError::Timeout),
        };
        if result.is_ok() {
            break;
        }
        tracing::warn!(origin = %target.url, "stream origin failed, trying next origin");
    }

    match result {
        Ok(resp) => {
            state.metrics.record_stream_start();
            let status = resp.status;
            let mut out_headers = resp.headers;
            let content_length = out_headers
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            strip_response_headers(&mut out_headers);
            out_headers.remove(HeaderName::from_static("x-lagran-pingora-meta"));
            out_headers.remove(HeaderName::from_static(VALIDATOR_SOURCE_HEADER));
            out_headers.remove(HeaderName::from_static("x-lagran-cache-reason"));
            if content_length > 0 {
                if let Ok(value) = HeaderValue::from_str(&content_length.to_string()) {
                    out_headers.insert(header::CONTENT_LENGTH, value);
                }
            }
            cache_status_headers(&mut out_headers, label.as_str());
            out_headers.insert(
                HeaderName::from_static("x-powered-by"),
                HeaderValue::from_static("lagran-edge"),
            );
            apply_security_headers(&mut out_headers);
            apply_cors_and_custom(&mut out_headers, &eff.response_headers);

            let mut body = resp.body;
            let stream_metrics = state.metrics.clone();
            let stream = async_stream::stream! {
                loop {
                    let frame = match tokio::time::timeout(idle_timeout, body.frame()).await {
                        Ok(frame) => frame,
                        Err(_) => {
                            stream_metrics.record_stream_error();
                            yield Err::<Bytes, std::io::Error>(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "origin body idle timeout",
                            ));
                            break;
                        }
                    };
                    match frame {
                        Some(Ok(frame)) => {
                            if let Ok(data) = frame.into_data() {
                                if !data.is_empty() {
                                    stream_metrics.record_stream_bytes(data.len() as u64);
                                    yield Ok::<Bytes, std::io::Error>(data);
                                }
                            }
                        }
                        Some(Err(e)) => {
                            stream_metrics.record_stream_error();
                            yield Err::<Bytes, std::io::Error>(std::io::Error::other(
                                format!("origin body error: {e}"),
                            ));
                            break;
                        }
                        None => break,
                    }
                }
            };

            state.metrics.record_bypass(host, content_length);
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
                content_length,
                label.as_str(),
                request_id,
            )
            .await;

            let mut response = Response::new(Body::from_stream(stream));
            *response.status_mut() = status;
            *response.headers_mut() = out_headers;
            response
        }
        Err(e) => {
            if matches!(&e, FetchError::Timeout) {
                state.metrics.record_origin_timeout();
            } else {
                state.metrics.record_origin_error();
            }
            let failure = e.failure();
            let code = failure.status().as_u16();
            tracing::warn!(error = %e, origin = %eff.origin_url, "stream origin fetch failed");
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
                request_id,
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
            let flight_guard = if let Some(flight) = state.flight.as_ref() {
                crate::cache::flight::acquire(flight, key, state.cache.as_ref()).await
            } else {
                None
            };
            if flight_guard.is_none() && state.flight.is_some() {
                // Follower woke up after the leader wrote shared L2.
                if let CacheGetResult::Hit(entry) | CacheGetResult::Stale(entry) =
                    state.cache.get_result(key).await
                {
                    leader.finish().await;
                    return Ok((Fetched::FromCache(entry_into_origin(entry)), false));
                }
            }
            let _flight_guard = flight_guard;
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
                let response_policy = resolve_rule_policy_for_response_with_domain(
                    &eff.rules,
                    &eff.path,
                    method.as_str(),
                    query,
                    content_type,
                    &eff.key_ignore_headers,
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
                                tracing::debug!(
                                    key,
                                    ttl = decision.ttl_secs,
                                    swr = decision.swr_secs,
                                    body_len = resp.body.len(),
                                    "stored origin response"
                                );
                            } else if !store_large_response(state, key, resp, decision).await {
                                reason = Some("body-too-large");
                                tracing::debug!(len = resp.body.len(), %host, "object too large to cache");
                            }
                        }
                        Err(r) => {
                            tracing::debug!(key, reason = r, "origin response not stored");
                            reason = Some(r);
                        }
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
    let attempt = |target: OriginTarget| {
        let origin = state.origin.clone();
        let method = method.clone();
        let mut headers = headers.clone();
        if let Some(host) = target.host_header.as_deref() {
            if let Ok(value) = HeaderValue::from_str(host) {
                headers.insert(header::HOST, value);
            }
        }
        let path = path_and_query.to_string();
        let max_body = state.max_cacheable_body;
        async move {
            match tokio::time::timeout(
                timeout,
                origin.request_with_sni_limit(
                    &target.url,
                    &method,
                    &path,
                    &headers,
                    None,
                    false,
                    target.sni.as_deref(),
                    max_body,
                ),
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
    for target in sequence {
        result = attempt(target.clone()).await;
        if result.is_ok() {
            break;
        }
        if matches!(
            result,
            Err(FetchError::Timeout) | Err(FetchError::Failed(_))
        ) {
            // Fail over immediately: without this, a dead origin keeps being
            // selected until the scheduled prober flips it, and every fetch
            // waits out the full timeout.
            let reason = match &result {
                Err(e) => e.to_string(),
                Ok(_) => String::new(),
            };
            state
                .origin_health
                .record_origin_failure(host, &target.url, &reason)
                .await;
        }
        tracing::warn!(origin = %target.url, "origin failed, trying next origin");
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn revalidate_cached_entry(
    state: &Arc<AppState>,
    key: &str,
    eff: &Effective,
    headers: &HeaderMap,
    method: &Method,
    host: &str,
    path_and_query: &str,
    path_only: &str,
    client_ip: &str,
    user_agent: &str,
    referer: &str,
    request_id: &str,
    client_if_none_match: Option<&str>,
    start: Instant,
) -> Option<Response> {
    if headers.contains_key(header::RANGE) {
        return None;
    }
    let entry = match state.cache.get_result(key).await {
        CacheGetResult::Hit(entry) | CacheGetResult::Stale(entry) => entry,
        CacheGetResult::Expired | CacheGetResult::Miss => return None,
    };
    if entry_response_bypass(eff, &entry) {
        state.cache.delete(key).await;
        return None;
    }

    let etag = entry.header("etag").map(str::to_string);
    let last_modified = entry.header("last-modified").map(str::to_string);
    let validator_source = entry.header(VALIDATOR_SOURCE_HEADER).unwrap_or("");
    tracing::debug!(
        key,
        has_etag = etag.is_some(),
        has_last_modified = last_modified.is_some(),
        validator_source,
        "revalidation cache entry"
    );
    if validator_source == "computed" {
        tracing::debug!(key, "revalidation entry validator is edge-computed");
        return None;
    }
    let use_etag = match validator_source {
        "etag" => etag.is_some(),
        "last-modified" => false,
        _ => etag.is_some(),
    };
    let use_last_modified = !use_etag
        && match validator_source {
            "last-modified" => last_modified.is_some(),
            _ => last_modified.is_some(),
        };
    if !use_etag && !use_last_modified {
        tracing::debug!(key, "revalidation entry has no upstream validator");
        return None;
    }

    let mut conditional = headers.clone();
    conditional.remove(header::CACHE_CONTROL);
    conditional.remove(header::PRAGMA);
    conditional.remove(header::IF_NONE_MATCH);
    conditional.remove(header::IF_MODIFIED_SINCE);
    if use_etag {
        if let Some(ref etag) = etag {
            if let Ok(value) = HeaderValue::from_str(etag) {
                conditional.insert(header::IF_NONE_MATCH, value);
            }
        }
    } else if let Some(ref modified) = last_modified {
        if let Ok(value) = HeaderValue::from_str(modified) {
            conditional.insert(header::IF_MODIFIED_SINCE, value);
        }
    }

    let origin_result =
        fetch_origin(state, eff, host, path_and_query, &conditional, &Method::GET).await;
    match origin_result {
        Ok(resp) if resp.status == StatusCode::NOT_MODIFIED => {
            let mut refreshed = entry;
            merge_revalidation_headers(&mut refreshed, &resp.headers);
            // Let entry_to_response generate a fresh Date for the revalidated
            // representation instead of retaining the pre-304 Date.
            refreshed
                .headers
                .retain(|(name, _)| !name.eq_ignore_ascii_case("date"));
            refreshed.stored_at_epoch_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let content_type = refreshed.header("content-type").unwrap_or("");
            let response_policy = resolve_rule_policy_for_response_with_domain(
                &eff.rules,
                &eff.path,
                method.as_str(),
                path_and_query.split_once('?').map(|(_, q)| q).unwrap_or(""),
                content_type,
                &eff.key_ignore_headers,
            );
            if response_policy.action == RuleAction::Cache {
                match decide_storage_reason(
                    refreshed.status,
                    &refreshed.headers,
                    response_policy,
                    state.default_ttl_secs,
                ) {
                    Ok(decision) => {
                        if refreshed.body.len() <= state.max_cacheable_body {
                            state
                                .cache
                                .set_with_swr(
                                    key,
                                    refreshed.clone(),
                                    decision.ttl_secs,
                                    decision.swr_secs,
                                )
                                .await;
                        }
                    }
                    Err(_) => {
                        state.cache.delete(key).await;
                    }
                }
            } else {
                state.cache.delete(key).await;
            }

            let mut response = serve_cached(
                state,
                refreshed,
                CacheStatus::Revalidated,
                method,
                host,
                path_only,
                client_ip,
                user_agent,
                referer,
                request_id,
                client_if_none_match,
                eff,
                start,
            )
            .await;
            set_cache_reason(&mut response, Some("origin-304"));
            Some(response)
        }
        Ok(resp) => {
            let mut resp = resp;
            // Some origins/shields answer a conditional GET with an empty 200
            // even though the unconditional representation is non-empty. Do
            // not replace a usable cache body with that response: retry once
            // without validators, and if the retry also fails, serve the
            // cached body rather than a blank page.
            if resp.status.is_success() && resp.body.is_empty() && !entry.body.is_empty() {
                let mut retry_headers = headers.clone();
                retry_headers.remove(header::IF_NONE_MATCH);
                retry_headers.remove(header::IF_MODIFIED_SINCE);
                match fetch_origin(
                    state,
                    eff,
                    host,
                    path_and_query,
                    &retry_headers,
                    &Method::GET,
                )
                .await
                {
                    Ok(full) if !full.body.is_empty() => {
                        resp = full;
                    }
                    Ok(_) => {
                        tracing::warn!(
                            host,
                            "conditional revalidation returned empty 200 twice; serving cached body"
                        );
                        let mut response = serve_cached(
                            state,
                            entry,
                            CacheStatus::Revalidated,
                            method,
                            host,
                            path_only,
                            client_ip,
                            user_agent,
                            referer,
                            request_id,
                            client_if_none_match,
                            eff,
                            start,
                        )
                        .await;
                        set_cache_reason(&mut response, Some("origin-empty-fallback"));
                        return Some(response);
                    }
                    Err(error) => {
                        tracing::warn!(
                            error = %error,
                            host,
                            "conditional revalidation returned empty 200; serving cached body"
                        );
                        let mut response = serve_cached(
                            state,
                            entry,
                            CacheStatus::Revalidated,
                            method,
                            host,
                            path_only,
                            client_ip,
                            user_agent,
                            referer,
                            request_id,
                            client_if_none_match,
                            eff,
                            start,
                        )
                        .await;
                        set_cache_reason(&mut response, Some("origin-empty-fallback"));
                        return Some(response);
                    }
                }
            }
            let status = resp.status;
            let body_len = resp.body.len() as u64;
            let etag = entry_etag(&resp);
            let content_type = resp
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let response_policy = resolve_rule_policy_for_response_with_domain(
                &eff.rules,
                &eff.path,
                method.as_str(),
                path_and_query.split_once('?').map(|(_, q)| q).unwrap_or(""),
                content_type,
                &eff.key_ignore_headers,
            );
            if response_policy.action == RuleAction::Cache && (200..300).contains(&status.as_u16())
            {
                if let Ok(decision) = decide_storage_reason(
                    status.as_u16(),
                    &headers_vec(&resp.headers),
                    response_policy,
                    state.default_ttl_secs,
                ) {
                    if resp.body.len() <= state.max_cacheable_body {
                        let entry = clone_as_entry(&resp);
                        state
                            .cache
                            .set_with_swr(key, entry, decision.ttl_secs, decision.swr_secs)
                            .await;
                    } else {
                        store_large_response(state, key, &resp, decision).await;
                    }
                }
            }
            state.metrics.record_miss(host, body_len);
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
                CacheStatus::Revalidated.as_str(),
                request_id,
            )
            .await;
            let mut response = origin_response(
                resp,
                CacheStatus::Revalidated.as_str(),
                &etag,
                &eff.response_headers,
                policy_browser_ttl(&response_policy),
            );
            set_cache_reason(&mut response, Some("origin-200"));
            Some(response)
        }
        Err(error) => {
            let failure = error.failure();
            tracing::warn!(error = %error, origin = %eff.origin_url, "conditional revalidation failed");
            log_access(
                &state.access_log,
                method,
                host,
                path_only,
                failure.status().as_u16(),
                start,
                client_ip,
                user_agent,
                referer,
                0,
                failure.log_label(),
                request_id,
            )
            .await;
            Some(default_page::origin_error_page(host, path_only, failure))
        }
    }
}

fn merge_revalidation_headers(entry: &mut CacheEntry, headers: &HeaderMap) {
    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        if name_str.eq_ignore_ascii_case("connection")
            || name_str.eq_ignore_ascii_case("keep-alive")
            || name_str.eq_ignore_ascii_case("transfer-encoding")
            || name_str.eq_ignore_ascii_case("content-length")
            || name_str.eq_ignore_ascii_case("set-cookie")
            || name_str.eq_ignore_ascii_case("set-cookie2")
            || name_str.eq_ignore_ascii_case("age")
        {
            continue;
        }
        let Ok(value) = value.to_str() else {
            continue;
        };
        entry
            .headers
            .retain(|(existing, _)| !existing.eq_ignore_ascii_case(name_str));
        entry
            .headers
            .push((name_str.to_string(), value.to_string()));
    }
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
            key_ignore: 0,
            key_ignore_headers: String::new(),
            response_headers: ResponseHeaderOverrides::empty_arc(),
            origin_auth_header: String::new(),
            origin_auth_value: String::new(),
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
                let response_policy = resolve_rule_policy_for_response_with_domain(
                    &eff.rules,
                    &eff.path,
                    "GET",
                    query,
                    content_type,
                    &eff.key_ignore_headers,
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
                        } else {
                            store_large_response(&state, &key, &resp, decision).await;
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
    entry.headers.push(("accept-ranges".into(), "bytes".into()));

    state.metrics.record_hit(host, body_len);
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
    entry_to_response(entry, label.as_str(), &etag, &eff.response_headers, None)
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
            state.metrics.record_hit(host, 0);
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
                request_id,
            )
            .await;
            return not_modified_response(&etag, &entry);
        }
    }

    let bytes = entry.body.len() as u64;
    state.metrics.record_hit(host, bytes);
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
        request_id,
    )
    .await;
    entry_to_response(
        entry,
        label.as_str(),
        &etag,
        &eff.response_headers,
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
    resolve_rule_policy_for_response_with_domain(
        &eff.rules,
        &eff.path,
        eff.method.as_str(),
        "",
        content_type,
        &eff.key_ignore_headers,
    )
    .action
        != RuleAction::Cache
}

fn clone_as_entry(resp: &OriginResponse) -> CacheEntry {
    let mut entry = CacheEntry::new(
        resp.status.as_u16(),
        headers_vec(&resp.headers),
        resp.body.clone(),
    );
    let has_etag = entry.header("etag").is_some();
    let has_last_modified = entry.header("last-modified").is_some();
    entry
        .headers
        .retain(|(name, _)| !name.eq_ignore_ascii_case(VALIDATOR_SOURCE_HEADER));
    if has_etag {
        entry
            .headers
            .push((VALIDATOR_SOURCE_HEADER.to_string(), "etag".to_string()));
    } else if has_last_modified {
        entry.headers.push((
            VALIDATOR_SOURCE_HEADER.to_string(),
            "last-modified".to_string(),
        ));
    } else {
        entry
            .headers
            .push(("etag".to_string(), compute_etag(&entry)));
        entry
            .headers
            .push((VALIDATOR_SOURCE_HEADER.to_string(), "computed".to_string()));
    }
    entry
}

/// Store an already-buffered origin response in the streaming large-object
/// cache. The legacy handler (and therefore the prefetch endpoint) does not use
/// Pingora's `HandleMiss`, so it needs this bridge to warm large objects.
async fn store_large_response(
    state: &AppState,
    key: &str,
    resp: &OriginResponse,
    decision: CacheDecision,
) -> bool {
    let Some(large) = state.large_cache.as_ref() else {
        return false;
    };
    if resp.status != StatusCode::OK {
        return false;
    }
    let len = resp.body.len();
    if !large.accepts(len as u64) {
        return false;
    }
    // `large.begin` filters again, but this path also feeds the validator and
    // ETag computation below, which must not see a `Set-Cookie` either.
    let mut headers =
        crate::cache::large::LargeCache::prune_uncacheable(&headers_vec(&resp.headers));
    let has_etag = headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("etag"));
    let has_last_modified = headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("last-modified"));
    headers.retain(|(name, _)| !name.eq_ignore_ascii_case(VALIDATOR_SOURCE_HEADER));
    if has_etag {
        headers.push((VALIDATOR_SOURCE_HEADER.to_string(), "etag".to_string()));
    } else if has_last_modified {
        headers.push((
            VALIDATOR_SOURCE_HEADER.to_string(),
            "last-modified".to_string(),
        ));
    } else {
        let etag = compute_etag(&CacheEntry::new(
            resp.status.as_u16(),
            headers.clone(),
            resp.body.clone(),
        ));
        headers.push(("etag".to_string(), etag));
        headers.push((VALIDATOR_SOURCE_HEADER.to_string(), "computed".to_string()));
    }
    let Some(mut writer) = large
        .begin(
            key,
            resp.status.as_u16(),
            headers,
            len as u64,
            decision.ttl_secs,
            decision.swr_secs,
        )
        .await
    else {
        return false;
    };
    writer.write_all(&resp.body).await;
    match writer.commit().await {
        true => {
            tracing::debug!(%key, len, "stored large object from legacy handler");
            true
        }
        false => {
            tracing::warn!(%key, len, "large object cache commit failed");
            false
        }
    }
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

    let cleared = challenge::has_clearance(
        headers,
        host,
        domain.waf.challenge_ttl_secs,
        &state.challenge_secret,
    );
    if bot_guard::enabled()
        && !cleared
        && challenge_accepts_html(method, headers)
        && matches!(
            crate::server::cc::classify_path(path_only),
            crate::server::cc::CcPathClass::Dynamic | crate::server::cc::CcPathClass::Auth
        )
    {
        let behavior = bot_guard::analyze(headers);
        if behavior.score >= bot_guard::threshold() {
            let rule_name = if behavior.reasons.is_empty() {
                "behavior-score".to_string()
            } else {
                format!("behavior-score:{}", behavior.reasons.join(","))
            };
            state
                .waf_log
                .push(
                    host,
                    client_ip,
                    method.as_str(),
                    path_and_query,
                    "challenge",
                    "bot",
                    &rule_name,
                    "block",
                )
                .await;
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
                "BOT-CHALLENGE",
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
    }

    if let Some(ip) = client_ip_addr {
        let decision = state
            .cc
            .check(host, path_only, ip, &domain.cc, cleared)
            .await;
        if decision != CcDecision::Allow {
            let banned = decision.is_banned();
            let challenge_needed = domain.cc.mode == CcMode::Block
                && matches!(decision, CcDecision::Limit { .. })
                && !cleared
                && challenge_accepts_html(method, headers);
            let action = if domain.cc.mode == CcMode::Monitor {
                "log"
            } else if banned {
                "cc-ban"
            } else if challenge_needed {
                "challenge"
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
                    } else if challenge_needed {
                        "cc-challenge"
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
                    "CC-CHALLENGE",
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

    let skip_rate_limit =
        domain.cc.enabled && domain.cc.mode == CcMode::Block && domain.cc.global_rps > 0;
    if !skip_rate_limit {
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
            return Some(default_page::rate_limited_page(host, path_only, 1, false));
        }
    }

    if domain.waf.enabled {
        // Only pay for a database lookup when this domain configured Geo/ASN
        // rules. The lookup uses the already-resolved trusted client IP.
        let geo = if domain.waf.needs_geo() {
            state.geo.lookup(client_ip_addr)
        } else {
            crate::waf::geo::GeoInfo::default()
        };
        let waf_request = WafRequest {
            method: method.as_str(),
            path: path_only,
            query: url_query(path_and_query),
            user_agent: &user_agent,
            referer: &referer,
            ip: client_ip_addr,
            country: geo.country.as_deref(),
            asn: geo.asn,
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

    let hotlink_signature_ok = headers
        .get(crate::security::signed_url::HOTLINK_OK_HEADER)
        .is_some_and(|v| v == "1");
    if !hotlink_signature_ok
        && (domain.hotlink_signature_enabled || !domain.hotlink_allow_referers.is_empty())
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

/// Result of checking a request against the domain's signed-URL policy.
enum SignedUrlGate {
    /// No signature required: forward the request unchanged.
    Pass(Request<Body>),
    /// Signature valid: forward with the signature parameters removed.
    Signed(Request<Body>),
    /// Signature required but missing, expired or wrong: answer 403.
    Reject,
}

/// Verify the HMAC-signed URL for a domain that requires one.
///
/// This mirrors the check in the Pingora request filter. Both data planes must
/// enforce it: requests fall back to the in-process handler for HEAD, Range,
/// WebSocket, `Cache-Control: no-cache` and any request without a native plan,
/// and those are exactly the requests an attacker would use to fetch protected
/// content without a valid signature.
async fn signed_url_gate(domain: &DomainEntry, req: Request<Body>, host: &str) -> SignedUrlGate {
    use crate::security::signed_url;

    if signed_url::effective_mode(domain) == "off" {
        return SignedUrlGate::Pass(req);
    }
    let uri = req.uri().clone();
    // An unparsable path is treated as protected so it cannot slip through.
    let protected = signed_url::normalize_path(uri.path())
        .map(|normalized| signed_url::path_protected(domain, &normalized))
        .unwrap_or(true);
    if !protected {
        return SignedUrlGate::Pass(req);
    }
    let verified = match signed_url::verify(
        domain,
        req.method().as_str(),
        host,
        &uri,
        signed_url::now_epoch_secs(),
    ) {
        Ok(verified) => verified,
        Err(e) => {
            tracing::debug!(
                reason = e.reason(),
                host,
                "signed url rejected (legacy path)"
            );
            return SignedUrlGate::Reject;
        }
    };
    let mut parts = uri.into_parts();
    parts.path_and_query = verified
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string())
        .parse()
        .ok();
    let rewritten = match http::Uri::from_parts(parts) {
        Ok(uri) => uri,
        Err(_) => return SignedUrlGate::Reject,
    };
    let mut req = req;
    *req.uri_mut() = rewritten;
    SignedUrlGate::Signed(req)
}

/// Parse the host out of a `Referer` header value.
///
/// Returns `None` when there is no usable host: an empty value, a non-http(s)
/// scheme, or a value that is not a URL at all. `about:blank`, `file://` and
/// `data:` referers never grant access.
fn referer_host(referer: &str) -> Option<String> {
    let referer = referer.trim();
    if referer.is_empty() {
        return None;
    }
    // Only absolute http(s) URLs name a site. Bare strings such as
    // `example.com/page` have no scheme and are treated as unusable rather than
    // guessed at.
    let rest = referer
        .strip_prefix("https://")
        .or_else(|| referer.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // Strip userinfo so `https://example.com@evil.test/` cannot pass as
    // `example.com`: the real host is what follows the last `@`.
    let authority = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);
    if authority.is_empty() {
        return None;
    }
    let host = crate::config::registry::normalize_host(authority);
    if host.is_empty() {
        return None;
    }
    Some(host)
}

/// True when `host` equals `pattern` or is one of its subdomains.
///
/// `example.com` matches `example.com` and `www.example.com` but never
/// `evil-example.com` or `example.com.evil.test`. A leading `*.` is accepted and
/// means subdomains only (`*.example.com` matches `a.example.com`).
fn host_matches(pattern: &str, host: &str) -> bool {
    // The operator may type `Example.COM` in the console; the referer host is
    // always lowercase after normalization, so normalize the pattern too.
    let pattern: String = pattern
        .trim()
        .trim_start_matches("*.")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let pattern = pattern.as_str();
    if pattern.is_empty() {
        return false;
    }
    if host == pattern {
        return !pattern.is_empty();
    }
    // Boundary must be a real label separator, not any substring.
    host.len() > pattern.len()
        && host.ends_with(pattern)
        && host.as_bytes()[host.len() - pattern.len() - 1] == b'.'
}

/// Decide whether a request from `referer` may hotlink.
///
/// The previous implementation used `referer.contains(pattern)`, so a page at
/// `https://evil.test/?ref=https://example.com` was granted access to a domain
/// that only whitelisted `example.com`. Matching is now done on the parsed host
/// with label boundaries.
pub(crate) fn hotlink_allowed(allowed_list: &str, referer: &str) -> bool {
    let patterns: Vec<&str> = allowed_list
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if patterns.is_empty() {
        return false;
    }
    // An explicit `*` allows any source, including a missing Referer.
    if patterns.contains(&"*") {
        return true;
    }
    let Some(host) = referer_host(referer) else {
        // No Referer (or an unusable one) never matches a host pattern.
        return false;
    };
    patterns.iter().any(|pattern| host_matches(pattern, &host))
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

pub(crate) fn apply_cors_and_custom(headers: &mut HeaderMap, overrides: &ResponseHeaderOverrides) {
    overrides.apply(headers);
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
    response_headers: &ResponseHeaderOverrides,
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
    if let Some(ttl) = entry.ttl_secs() {
        if let Ok(v) = HeaderValue::from_str(&ttl.to_string()) {
            headers.insert(HeaderName::from_static("x-lagran-cache-ttl"), v);
        }
    }
    headers.insert(
        HeaderName::from_static("x-powered-by"),
        HeaderValue::from_static("lagran-edge"),
    );
    if !headers.contains_key(header::DATE) {
        if let Ok(date) =
            HeaderValue::from_str(&httpdate::fmt_http_date(std::time::SystemTime::now()))
        {
            headers.insert(header::DATE, date);
        }
    }
    if let Ok(v) = HeaderValue::from_str(etag) {
        headers.insert(header::ETAG, v);
    }
    apply_browser_ttl(&mut headers, browser_ttl);
    apply_security_headers(&mut headers);
    apply_cors_and_custom(&mut headers, response_headers);
    let mut resp = Response::new(Body::from(entry.body));
    *resp.status_mut() = status;
    *resp.headers_mut() = headers;
    resp
}

fn origin_response(
    resp: OriginResponse,
    cache_status: &str,
    etag: &str,
    response_headers: &ResponseHeaderOverrides,
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
    apply_cors_and_custom(&mut headers, response_headers);
    let mut out = Response::new(Body::from(resp.body));
    *out.status_mut() = resp.status;
    *out.headers_mut() = headers;
    set_cache_reason(&mut out, reason);
    out
}

fn pass_through_response(
    resp: OriginResponse,
    cache_status: &str,
    response_headers: &ResponseHeaderOverrides,
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
    apply_cors_and_custom(&mut headers, response_headers);
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

fn not_modified_response(etag: &str, entry: &CacheEntry) -> Response {
    let mut headers = HeaderMap::new();
    for name in [
        "cache-control",
        "vary",
        "expires",
        "content-location",
        "last-modified",
    ] {
        if let Some(value) = entry.header(name) {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(name, value);
            }
        }
    }
    if let Ok(v) = HeaderValue::from_str(etag) {
        headers.insert(header::ETAG, v);
    }
    headers.insert(
        header::DATE,
        HeaderValue::from_str(&httpdate::fmt_http_date(std::time::SystemTime::now()))
            .unwrap_or_else(|_| HeaderValue::from_static("Thu, 01 Jan 1970 00:00:00 GMT")),
    );
    headers.insert(
        HeaderName::from_static("age"),
        HeaderValue::from_str(&entry.age_secs().to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0")),
    );
    if let Some(ttl) = entry.ttl_secs() {
        if let Ok(v) = HeaderValue::from_str(&ttl.to_string()) {
            headers.insert(HeaderName::from_static("x-lagran-cache-ttl"), v);
        }
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

    /// The whitelist used to be applied with `referer.contains(pattern)`, so a
    /// page on an attacker domain could embed the allowed host in its query
    /// string or path and steal the asset.
    #[test]
    fn hotlink_rejects_pattern_smuggled_in_query_or_path() {
        for referer in [
            "https://evil.test/?ref=https://example.com",
            "https://evil.test/example.com/a.js",
            "https://evil.test/#example.com",
            "https://evil.test/a?next=example.com",
        ] {
            assert!(
                !hotlink_allowed("example.com", referer),
                "{referer} must not be allowed"
            );
        }
    }

    /// A matching suffix is not a matching host: only a real label boundary
    /// counts.
    #[test]
    fn hotlink_requires_label_boundary() {
        assert!(!hotlink_allowed(
            "example.com",
            "https://evil-example.com/a"
        ));
        assert!(!hotlink_allowed(
            "example.com",
            "https://example.com.evil.test/a"
        ));
        assert!(!hotlink_allowed("example.com", "https://notexample.com/a"));
        // Real subdomains are allowed.
        assert!(hotlink_allowed("example.com", "https://www.example.com/a"));
        assert!(hotlink_allowed("example.com", "https://a.b.example.com/x"));
    }

    /// `https://example.com@evil.test/` puts the allowed name in the userinfo.
    #[test]
    fn hotlink_ignores_userinfo() {
        assert!(!hotlink_allowed(
            "example.com",
            "https://example.com@evil.test/a"
        ));
    }

    /// Wildcard entries mean "subdomains of", not "everything".
    #[test]
    fn hotlink_wildcard_prefix_means_subdomains() {
        assert!(hotlink_allowed("*.example.com", "https://a.example.com/x"));
        assert!(!hotlink_allowed("*.example.com", "https://evil.test/x"));
        assert!(!hotlink_allowed(
            "*.example.com",
            "https://evilexample.com/x"
        ));
    }

    /// Only http(s) referers name a site; opaque schemes never grant access.
    #[test]
    fn hotlink_rejects_non_http_referers() {
        for referer in ["about:blank", "file:///etc/passwd", "data:text/html,x"] {
            assert!(
                !hotlink_allowed("example.com", referer),
                "{referer} must not be allowed"
            );
        }
    }

    /// Ports, trailing dots and case must not defeat the match.
    #[test]
    fn hotlink_normalizes_referer_host() {
        assert!(hotlink_allowed("example.com", "https://EXAMPLE.com:8443/a"));
        assert!(hotlink_allowed("example.com", "https://example.com./a"));
        assert!(hotlink_allowed("Example.COM", "https://example.com/a"));
    }

    /// An empty whitelist denies everything; only an explicit `*` opens it up.
    #[test]
    fn hotlink_empty_list_denies() {
        assert!(!hotlink_allowed("", "https://example.com/a"));
        assert!(!hotlink_allowed("  ,  ", "https://example.com/a"));
        assert!(hotlink_allowed("*", "https://anything.test/a"));
    }

    fn signed_domain(mode: &str, secret: &str) -> DomainEntry {
        DomainEntry {
            domain: "cdn.test".into(),
            signed_url_enabled: true,
            signed_url_mode: mode.into(),
            signed_url_secret: secret.into(),
            signed_url_ttl_secs: 3600,
            ..Default::default()
        }
    }

    fn sign(secret: &str, method: &str, host: &str, path: &str, expires: &str) -> String {
        use ring::hmac;
        let canonical = format!("{method}\n{host}\n{path}\n\n{expires}");
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        hmac::sign(&key, canonical.as_bytes())
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// The legacy data plane served protected objects whenever the Pingora
    /// path did not handle the request. This is the regression that let a
    /// single `Cache-Control: no-cache` header bypass `signed_url_mode=all`.
    #[tokio::test]
    async fn unsigned_request_is_rejected_on_the_legacy_path() {
        let domain = signed_domain("all", "secret");
        let req = Request::builder()
            .method(Method::GET)
            .uri("/paid/video.mp4")
            .header(header::HOST, "cdn.test")
            .body(Body::empty())
            .unwrap();

        assert!(matches!(
            signed_url_gate(&domain, req, "cdn.test").await,
            SignedUrlGate::Reject
        ));
    }

    #[tokio::test]
    async fn signed_request_strips_signature_on_the_legacy_path() {
        let domain = signed_domain("all", "secret");
        let now = crate::security::signed_url::now_epoch_secs();
        let expires = (now + 60).to_string();
        let sig = sign("secret", "GET", "cdn.test", "/paid/video.mp4", &expires);
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("/paid/video.mp4?expires={expires}&sig={sig}"))
            .header(header::HOST, "cdn.test")
            .body(Body::empty())
            .unwrap();

        let SignedUrlGate::Signed(req) = signed_url_gate(&domain, req, "cdn.test").await else {
            panic!("valid signature must pass the legacy gate");
        };
        // Signature must not reach the cache key or the origin.
        assert_eq!(req.uri().to_string(), "/paid/video.mp4");
    }

    #[tokio::test]
    async fn signature_is_not_required_when_policy_is_off() {
        let domain = signed_domain("off", "secret");
        let req = Request::builder()
            .method(Method::GET)
            .uri("/paid/video.mp4")
            .header(header::HOST, "cdn.test")
            .body(Body::empty())
            .unwrap();
        assert!(matches!(
            signed_url_gate(&domain, req, "cdn.test").await,
            SignedUrlGate::Pass(_)
        ));
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
        let resp = entry_to_response(
            entry,
            "HIT",
            "\"abc\"",
            &ResponseHeaderOverrides::default(),
            None,
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get("set-cookie").is_none());
        assert_eq!(resp.headers().get("age").unwrap(), "0");
        assert!(resp.headers().get(header::DATE).is_some());
        assert_eq!(resp.headers().get("x-cache").unwrap(), "HIT");
    }
}
