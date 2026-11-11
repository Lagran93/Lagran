//! Pingora public listener + native data plane.
//!
//! Pingora owns public HTTP/HTTPS, HTTP/1.1+HTTP/2, TLS and connection
//! management. Cacheable GET/HEAD requests use `pingora-cache` with the
//! existing `SharedCache` as storage and `upstream_peer` for direct origin
//! access. Requests that need the legacy engine (WAF/CC/rate-limit/hotlink,
//! bypass/dynamic traffic, disk/hybrid cache, control endpoints and
//! WebSocket) are handed to the in-process handler.

use crate::cache::CacheSource;
use crate::origin_dns::OriginDnsCache;
use crate::cache::policy::{
    apply_key_ignore_default, compute_etag, decide_storage_reason, request_bypass_reason_headers,
    resolve_rule_policy_for_response, ResolvedPolicy, RuleAction,
    VALIDATOR_SOURCE_HEADER,
};
use crate::config::registry::{DomainEntry, OriginTarget};
use crate::config::EdgeConfig;
use crate::server::cert_store::CertStore;
use crate::server::challenge;
use crate::server::compression::{should_compress, CompressionConfig, GzipEncoder};
use crate::server::default_page::{self, OriginFailure};
use crate::server::handler::{
    apply_browser_ttl, apply_cors_and_custom, apply_security_headers, hotlink_allowed,
    log_access, policy_browser_ttl, proxy_handler, AppState,
};
use crate::server::pipeline::{RequestFacts, RequestPipeline};
use crate::server::native_cache::{leak_storage_with_large, NativeStorage, META_HEADER};
use crate::server::purge;
use crate::security::header_guard;
use crate::security::origin_auth;
use crate::security::signed_url;
use async_trait::async_trait;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri, Version};
use axum::Json;
use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt;
use pingora::http::ResponseHeader;
use pingora::listeners::tls::TlsSettings;
use pingora::listeners::{TlsAccept, TlsAcceptCallbacks};
use pingora::protocols::tls::TlsRef;
use pingora::apps::HttpServerOptions;
use pingora::proxy::{FailToProxy, ProxyHttp, ProxyServiceBuilder, Session};
use pingora::server::Server;
use pingora::tls::{ext, pkey::PKey, ssl, x509::X509};
use pingora::upstreams::peer::HttpPeer;
use pingora::Result;
use pingora_cache::lock::CacheLock;
use pingora_cache::{
    CacheKey, CacheMeta, CacheOptionOverrides, CachePhase, ForcedFreshness, NoCacheReason,
    RespCacheable,
};

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

const MAX_PROXY_BODY: usize = 16 * 1024 * 1024;

#[derive(Debug)]
struct Sni(String);

struct CertCallback {
    store: Arc<CertStore>,
}

#[async_trait]
impl TlsAccept for CertCallback {
    async fn certificate_callback(&self, ssl: &mut TlsRef) {
        let name = ssl
            .servername(ssl::NameType::HOST_NAME)
            .unwrap_or_default()
            .to_string();
        let Some((cert_pem, key_pem)) = self.store.pem_for(&name) else {
            tracing::warn!(sni = %name, "no certificate for TLS SNI");
            return;
        };
        let cert = match X509::from_pem(&cert_pem) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(sni = %name, error = %e, "parse certificate failed");
                return;
            }
        };
        let key = match PKey::private_key_from_pem(&key_pem) {
            Ok(k) => k,
            Err(e) => {
                tracing::error!(sni = %name, error = %e, "parse private key failed");
                return;
            }
        };
        if let Err(e) = ext::ssl_use_certificate(ssl, &cert) {
            tracing::error!(sni = %name, error = %e, "install certificate failed");
            return;
        }
        if let Err(e) = ext::ssl_use_private_key(ssl, &key) {
            tracing::error!(sni = %name, error = %e, "install private key failed");
        }
    }

    async fn handshake_complete_callback(
        &self,
        ssl: &TlsRef,
    ) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
        ssl.servername(ssl::NameType::HOST_NAME)
            .map(|name| Arc::new(Sni(name.to_string())) as Arc<dyn std::any::Any + Send + Sync>)
    }
}

#[derive(Clone)]
struct NativePlan {
    domain: Arc<DomainEntry>,
    key: String,
    origin_host: String,
    origins: Vec<OriginTarget>,
    backup_url: String,
    /// TCP connect timeout. Kept separate so an unreachable origin fails over
    /// quickly instead of consuming the response budget.
    connect_timeout_ms: u64,
    read_timeout_ms: u64,
    cache_reason: Option<&'static str>,
    policy: ResolvedPolicy,
    cors: String,
    custom: String,
    cacheable: bool,
    is_head: bool,
    is_websocket: bool,
    label: &'static str,
}

struct RangeFill {
    key: String,
    raw_range: String,
}

enum RangeMsg {
    Chunk(Bytes),
    End,
}

struct RangeSink {
    tx: tokio::sync::mpsc::UnboundedSender<RangeMsg>,
    offset: u64,
    end: u64,
    /// Origin bytes to discard before the cacheable window starts. This is
    /// non-zero for a large suffix request where only the tail is cached.
    skip: u64,
    queued: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

struct ReqCtx {
    plan: Option<NativePlan>,
    host: String,
    path: String,
    method: Method,
    client_ip: String,
    request_id: String,
    user_agent: String,
    referer: String,
    start: Instant,
    cache_label: &'static str,
    cache_reason: Option<&'static str>,
    /// Age reported by pingora-cache for a hit; used to override a stale
    /// origin `Age: 0` with the actual shared-cache age.
    cache_age_secs: Option<u64>,
    cache_ttl_secs: Option<u64>,
    status: u16,
    attempt: usize,
    origin_order: Vec<String>,
    current_addresses: Vec<SocketAddr>,
    current_address_index: usize,
    current_origin: String,
    current_host_header: String,
    response_bypass: bool,
    head_body: BytesMut,
    head_headers: Option<ResponseHeader>,
    head_status: u16,
    range_fill: Option<RangeFill>,
    range_sink: Option<RangeSink>,
    /// Active gzip encoder for this response; set in `response_filter`.
    gzip: Option<GzipEncoder>,
    flight_guard: Option<crate::cache::flight::FlightGuard>,
    /// Set when the in-process handler already wrote its own access log.
    skip_logging: bool,
}

impl Default for ReqCtx {
    fn default() -> Self {
        Self {
            plan: None,
            host: String::new(),
            path: String::new(),
            method: Method::GET,
            client_ip: String::new(),
            request_id: String::new(),
            user_agent: String::new(),
            referer: String::new(),
            start: Instant::now(),
            cache_label: "MISS",
            cache_reason: None,
            cache_age_secs: None,
            cache_ttl_secs: None,
            status: 0,
            attempt: 0,
            origin_order: Vec::new(),
            current_addresses: Vec::new(),
            current_address_index: 0,
            current_origin: String::new(),
            current_host_header: String::new(),
            response_bypass: false,
            head_body: BytesMut::new(),
            head_headers: None,
            head_status: 0,
            range_fill: None,
            range_sink: None,
            gzip: None,
            flight_guard: None,
            skip_logging: false,
        }
    }
}

struct DataPlaneProxy {
    trust_proxy: bool,
    trusted_proxies: crate::security::trusted_proxy::TrustedProxies,
    state: Arc<AppState>,
    native_cache: bool,
    storage: Option<&'static NativeStorage>,
    cache_lock: &'static CacheLock,
    management_on_data: bool,
    /// Weighted round-robin seed for origin selection.
    origin_counter: std::sync::atomic::AtomicU64,
    dns_cache: OriginDnsCache,
    /// Downstream compression policy (cache stores identity).
    compression: CompressionConfig,
}

#[async_trait]
impl ProxyHttp for DataPlaneProxy {
    type CTX = ReqCtx;

    fn new_ctx(&self) -> Self::CTX {
        ReqCtx::default()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        prepare_proxy_headers(session, self.trust_proxy, &self.trusted_proxies)?;

        let req = session.req_header();
        ctx.host = request_host(req.headers.get("host").and_then(|v| v.to_str().ok()));
        ctx.path = req.uri.path().to_string();
        ctx.method = req.method.clone();
        // `prepare_proxy_headers` already replaced X-Forwarded-For with the
        // single address resolved from the trusted chain, so this header now
        // holds exactly the client IP (or is absent).
        ctx.client_ip = req
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .unwrap_or("")
            .to_string();
        ctx.request_id = req
            .headers
            .get("x-request-id")
            .or_else(|| req.headers.get("x-correlation-id"))
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                use std::time::{SystemTime, UNIX_EPOCH};
                let n = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                format!("lr-{n:x}")
            });
        ctx.user_agent = req
            .headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        ctx.referer = req
            .headers
            .get("referer")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        if let Err(violation) = header_guard::validate(
            &req.headers,
            &req.uri,
            &ctx.method,
            req.version,
        ) {
            ctx.cache_label = "BYPASS";
            ctx.cache_reason = Some(violation.reason);
            ctx.status = 400;
            write_plain(
                session,
                400,
                "text/plain; charset=utf-8",
                Bytes::from_static(b"bad request headers"),
            )
            .await;
            return Ok(true);
        }

        let path = ctx.path.clone();
        let is_https = session
            .req_header()
            .headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("https"))
            .unwrap_or(false);
        if path == "/__lagran/health" {
            ctx.skip_logging = true;
            write_plain(
                session,
                200,
                "text/plain; charset=utf-8",
                Bytes::from_static(b"ok"),
            )
            .await;
            return Ok(true);
        }
        if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
            let token = percent_decode(token);
            if let Some(key_auth) = self.state.challenges.get(&token) {
                write_plain(
                    session,
                    200,
                    "text/plain; charset=utf-8",
                    Bytes::from(key_auth),
                )
                .await;
            } else {
                write_plain(
                    session,
                    404,
                    "text/plain; charset=utf-8",
                    Bytes::from_static(b"not found"),
                )
                .await;
            }
            return Ok(true);
        }
        if path == "/__lagran/challenge/verify" {
            let query = session.req_header().uri.query().unwrap_or("");
            let n = query_param(query, "n").unwrap_or_default();
            let a = query_param(query, "a").unwrap_or_default();
            let next = query_param(query, "next");
            let headers = session.req_header().headers.clone();
            let resp = challenge::verify_direct(
                &self.state,
                &ctx.host,
                &headers,
                &n,
                &a,
                next.as_deref(),
                is_https,
            )
            .await;
            write_axum_response(session, resp, false).await;
            return Ok(true);
        }

        if path.starts_with("/__lagran/") {
            ctx.skip_logging = true;
            if !self.management_on_data {
                write_plain(
                    session,
                    405,
                    "text/plain; charset=utf-8",
                    Bytes::from_static(b"management port required"),
                )
                .await;
                return Ok(true);
            }
            return self.handle_management(session, &path).await;
        }

        // The hotlink marker is internal; never trust a client-supplied value.
        session
            .req_header_mut()
            .remove_header(signed_url::HOTLINK_OK_HEADER);

        // Control-plane prefetch connects to the loopback public listener.
        // It must pass through the native cache path, but is trusted to skip
        // hotlink/signed-URL checks that would block a server-side warmup.
        let internal_prefetch = session
            .req_header()
            .headers
            .get("x-lagran-prefetch")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value == "1")
            && ctx
                .client_ip
                .parse::<std::net::IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false);
        if internal_prefetch {
            session
                .req_header_mut()
                .remove_header("x-lagran-prefetch");
        }

        // WebSocket is intentionally legacy-only: Pingora's HTTP proxy does
        // not tunnel upgraded connections on this path.
        if let Some(domain) = self.state.domains.get(&ctx.host).await {
            let mut signed_verified = false;
            let mode = signed_url::effective_mode(&domain);
            if mode != "off" && !internal_prefetch {
                let uri = session.req_header().uri.clone();
                let protected = signed_url::normalize_path(uri.path())
                    .map(|path| signed_url::path_protected(&domain, &path))
                    .unwrap_or(true);
                if protected {
                    match signed_url::verify(
                        &domain,
                        ctx.method.as_str(),
                        &ctx.host,
                        &uri,
                        signed_url::now_epoch_secs(),
                    ) {
                        Ok(verified) => {
                            // Signature parameters must not enter the cache key
                            // or the origin request, otherwise every signed URL
                            // creates a separate cache object.
                            session.req_header_mut().set_uri(verified.uri);
                            signed_verified = true;
                        }
                        Err(e) => {
                            ctx.cache_label = "BYPASS";
                            ctx.cache_reason = Some(e.reason());
                            ctx.status = 403;
                            write_plain(
                                session,
                                403,
                                "text/plain; charset=utf-8",
                                Bytes::from_static(b"invalid or expired signed url"),
                            )
                            .await;
                            return Ok(true);
                        }
                    }
                }
            }

            if domain.hotlink_signature_enabled && !signed_verified && !internal_prefetch {
                let referer = session
                    .req_header()
                    .headers
                    .get("referer")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if !hotlink_allowed(&domain.hotlink_allow_referers, referer) {
                    let mut auth = (*domain).clone();
                    auth.signed_url_enabled = true;
                    auth.signed_url_mode = "all".to_string();
                    auth.signed_url_paths.clear();
                    let uri = session.req_header().uri.clone();
                    if let Ok(verified) = signed_url::verify(
                        &auth,
                        ctx.method.as_str(),
                        &ctx.host,
                        &uri,
                        signed_url::now_epoch_secs(),
                    ) {
                        session.req_header_mut().set_uri(verified.uri);
                        let _ = session
                            .req_header_mut()
                            .insert_header(signed_url::HOTLINK_OK_HEADER, "1");
                    }
                }
            }

            if signed_verified {
                let _ = session
                    .req_header_mut()
                    .insert_header(signed_url::HOTLINK_OK_HEADER, "1");
            }
        }

        if is_websocket_upgrade(&session.req_header().headers) {
            ctx.skip_logging = true;
            return self.handle_in_process(session).await;
        }

        if self.try_large_revalidation(session, ctx).await? {
            return Ok(true);
        }
        if let Some(plan) = self.native_plan(session).await {
            self.state.metrics.record_pingora_datapath();
            let path_and_query = session
                .req_header()
                .uri
                .path_and_query()
                .map(|p| p.as_str().to_string())
                .unwrap_or_else(|| "/".to_string());
            let is_https = session
                .req_header()
                .headers
                .get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.eq_ignore_ascii_case("https"))
                .unwrap_or(false);
            let headers = session.req_header().headers.clone();
            let pipeline = RequestPipeline::new(&self.state);
            let facts = RequestFacts {
                method: &ctx.method,
                host: &ctx.host,
                path_only: &ctx.path,
                path_and_query: &path_and_query,
                headers: &headers,
                client_ip: &ctx.client_ip,
                is_https,
                start: ctx.start,
            };
            if !internal_prefetch {
                if let Some(resp) = pipeline.preflight(&plan.domain, &facts).await {
                    write_axum_response(session, resp, false).await;
                    return Ok(true);
                }
            }
            let small_range =
                headers.contains_key("range") && range_is_small_bounded(&headers);
            if plan.cacheable && !self.state.cache.has_local(&plan.key).await {
                // Only take the cross-node lock when L1 does not already have
                // the object. A plain L1 hit must not issue Redis SET/EVAL
                // commands on every request.
                if let Some(flight) = self.state.flight.as_ref() {
                    if let Some(guard) =
                        crate::cache::flight::acquire(flight, &plan.key, self.state.cache.as_ref())
                            .await
                    {
                        ctx.flight_guard = Some(guard);
                    }
                }
            }
            // Small bounded ranges can be answered directly from a complete
            // SharedCache object, keeping range slices on the Pingora path.
            if plan.cache_reason == Some("range-bypass")
                && small_range
                && !headers.contains_key("if-range")
                && plan.policy.action == RuleAction::Cache
                && request_bypass_reason_headers(&headers, plan.policy.ignore_cookie).is_none()
            {
                let raw_range = headers
                    .get("range")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                if let Some(raw_range) = raw_range {
                    let (cache_result, source) =
                        self.state.cache.get_result_with_source(&plan.key).await;
                    let entry = match cache_result {
                        crate::cache::CacheGetResult::Hit(entry)
                        | crate::cache::CacheGetResult::Stale(entry) => Some(entry),
                        _ => None,
                    };
                    if let Some(entry) = entry {
                        let total = entry.body.len() as u64;
                        if let Some((start, end)) = parse_single_range(&raw_range, total) {
                            if self
                                .serve_normal_range(
                                    session, &entry, start, end, total, &plan, source,
                                )
                                .await
                            {
                                ctx.cache_label = "HIT";
                                ctx.cache_reason = Some("range-shared-cache");
                                ctx.status = StatusCode::PARTIAL_CONTENT.as_u16();
                                ctx.plan = Some(plan);
                                return Ok(true);
                            }
                        }
                    }
                }
            }
            // A Range request can be answered from the large-object cache when
            // the requested bytes are already covered. Otherwise stream the
            // origin response and fill the partial object in the background.
            // If-Range is left to the origin to preserve validator semantics.
            if plan.cache_reason == Some("range-bypass")
                && !headers.contains_key("if-range")
                && self.state.large_cache.is_some()
                && plan.policy.action == RuleAction::Cache
                && request_bypass_reason_headers(&headers, plan.policy.ignore_cookie).is_none()
            {
                let raw_range = headers
                    .get("range")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                if let Some(raw_range) = raw_range {
                    if let Some(large) = self.state.large_cache.as_ref() {
                        if let Some(mut entry) = large.get_any(&plan.key).await {
                            let total = entry.content_length();
                            if let Some((start, end)) = parse_single_range(&raw_range, total) {
                                let fresh = SystemTime::now()
                                    .duration_since(SystemTime::UNIX_EPOCH)
                                    .map(|d| d.as_secs() <= entry.meta.fresh_until)
                                    .unwrap_or(false);
                                if entry.covers(start, end) {
                                    if self
                                        .serve_large_range(
                                            session, &mut entry, start, end, total, &plan, fresh,
                                        )
                                        .await
                                    {
                                        ctx.cache_label = if fresh { "HIT" } else { "STALE" };
                                        ctx.cache_reason = Some(if fresh {
                                            "range-large-cache"
                                        } else {
                                            "stale-range"
                                        });
                                        ctx.status = StatusCode::PARTIAL_CONTENT.as_u16();
                                        ctx.plan = Some(plan);
                                        return Ok(true);
                                    }
                                } else if fresh {
                                    if let Some(cached_end) = entry.meta.contiguous_end(start) {
                                        if cached_end < end
                                            && self
                                                .serve_large_range_splice(
                                                    session,
                                                    &mut entry,
                                                    start,
                                                    cached_end,
                                                    end,
                                                    total,
                                                    &plan,
                                                )
                                                .await
                                        {
                                            ctx.cache_label = "HIT";
                                            ctx.cache_reason = Some("range-splice");
                                            ctx.status = StatusCode::PARTIAL_CONTENT.as_u16();
                                            ctx.plan = Some(plan);
                                            return Ok(true);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if range_fill_is_candidate(&raw_range, self.state.range_fill_max_bytes) {
                        ctx.range_fill = Some(RangeFill {
                            key: plan.key.clone(),
                            raw_range,
                        });
                        ctx.cache_label = "MISS";
                        ctx.cache_reason = Some("range-fill");
                        ctx.plan = Some(plan);
                        return Ok(false);
                    }
                }
            }
            if plan.is_head && self.serve_head_cache(session, &plan, ctx).await {
                return Ok(true);
            }
            if plan.cacheable || plan.is_head {
                // Chrome sends max-age=0 on reload; keep the cached entry
                // eligible so If-None-Match can produce a 304/revalidated
                // response. Never strip these from BYPASS/dynamic requests.
                session.req_header_mut().remove_header("cache-control");
                session.req_header_mut().remove_header("pragma");
            }
            ctx.cache_reason = plan.cache_reason;
            ctx.plan = Some(plan);
            return Ok(false);
        }

        ctx.skip_logging = true;
        self.handle_in_process(session).await
    }

    fn request_cache_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()> {
        if ctx.plan.as_ref().is_some_and(|p| p.cacheable) {
            if let Some(storage) = self.storage {
                let mut overrides = CacheOptionOverrides::default();
                overrides.wait_timeout = Some(Duration::from_secs(5));
                overrides.max_lock_retries = Some(1);
                session
                    .cache
                    .enable(storage, None, None, Some(self.cache_lock), Some(overrides));
            }
        }
        Ok(())
    }

    async fn cache_hit_filter(
        &self,
        session: &mut Session,
        meta: &CacheMeta,
        _hit_handler: &mut pingora_cache::HitHandler,
        _is_fresh: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<ForcedFreshness>> {
        ctx.cache_age_secs = Some(meta.age().as_secs());
        ctx.cache_ttl_secs = Some(meta.fresh_sec().saturating_sub(meta.age().as_secs()));
        let Some(plan) = ctx.plan.as_ref() else {
            return Ok(None);
        };
        let content_type = meta
            .response_header()
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if content_type.is_empty() {
            return Ok(None);
        }
        let query = session.req_header().uri.query().unwrap_or("");
        let mut response_policy = resolve_rule_policy_for_response(
            &plan.domain.rules,
            &ctx.path,
            ctx.method.as_str(),
            query,
            content_type,
        );
        apply_key_ignore_default(&mut response_policy, &plan.domain.cache_key_ignore_headers);
        if response_policy.action != RuleAction::Cache {
            return Ok(Some(ForcedFreshness::ForceMiss));
        }
        Ok(None)
    }

    fn cache_key_callback(&self, _session: &Session, ctx: &mut Self::CTX) -> Result<CacheKey> {
        let key = ctx
            .plan
            .as_ref()
            .map(|p| p.key.as_str())
            .unwrap_or_default();
        Ok(CacheKey::new(key.as_bytes(), ""))
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let plan = ctx
            .plan
            .clone()
            .ok_or_else(|| pingora::Error::new_str("native plan missing"))?;
        if ctx.origin_order.is_empty() {
            let order = self.origin_order(&ctx.host, &plan).await;
            if order.is_empty() {
                return Err(pingora::Error::new_str("no origin available"));
            }
            ctx.origin_order = order.into_iter().map(|o| o.url).collect();
        }

        loop {
            let index = ctx.attempt.min(ctx.origin_order.len() - 1);
            let url = ctx.origin_order[index].clone();
            ctx.current_origin = url.clone();
            let origin = plan.origins.iter().find(|o| o.url == url);
            ctx.current_host_header = origin
                .and_then(|o| o.host_header.clone())
                .unwrap_or_default();
            let sni = origin.and_then(|o| o.sni.clone()).unwrap_or_default();
            let (host, port, tls) =
                parse_origin(&url).ok_or_else(|| pingora::Error::new_str("invalid origin URL"))?;

            if ctx.current_addresses.is_empty() {
                match self.dns_cache.resolve(&host, port).await {
                    Ok(addresses) => {
                        ctx.current_addresses = addresses;
                        ctx.current_address_index = 0;
                    }
                    Err(error) => {
                        tracing::debug!(origin = %url, %error, "origin DNS resolution failed");
                        if !Self::advance_origin(ctx) {
                            return Err(pingora::Error::because(
                                pingora::ErrorType::ConnectError,
                                "resolve origin address",
                                error,
                            ));
                        }
                        continue;
                    }
                }
            }

            let addr = ctx.current_addresses[ctx.current_address_index];
            return self
                .peer_for(
                    addr,
                    &host,
                    tls,
                    plan.connect_timeout_ms,
                    if session.req_header().headers.contains_key("range") {
                        self.state.origin_stream_read_timeout_ms
                    } else {
                        plan.read_timeout_ms
                    },
                    if sni.is_empty() { None } else { Some(&sni) },
                )
                .await;
        }
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
        e: Box<pingora::Error>,
    ) -> Box<pingora::Error> {
        let mut e = e;
        if Self::advance_peer(ctx) {
            e.set_retry(true);
        }
        e
    }

    fn error_while_proxy(
        &self,
        _peer: &HttpPeer,
        session: &mut Session,
        e: Box<pingora::Error>,
        ctx: &mut Self::CTX,
        _client_reused: bool,
    ) -> Box<pingora::Error> {
        let mut e = e;
        match e.etype() {
            pingora::ErrorType::ConnectTimedout
            | pingora::ErrorType::TLSHandshakeTimedout
            | pingora::ErrorType::ReadTimedout => self.state.metrics.record_origin_timeout(),
            _ => self.state.metrics.record_origin_error(),
        }
        // Hard connectivity failures fail over immediately instead of waiting
        // for the scheduled prober's hysteresis. Without this, a dead origin
        // keeps being selected and every fetch pays the connect timeout.
        let hard_failure = matches!(
            e.etype(),
            pingora::ErrorType::ConnectError
                | pingora::ErrorType::ConnectRefused
                | pingora::ErrorType::ConnectNoRoute
                | pingora::ErrorType::ConnectTimedout
                | pingora::ErrorType::ConnectProxyFailure
                | pingora::ErrorType::TLSHandshakeFailure
                | pingora::ErrorType::TLSHandshakeTimedout
                | pingora::ErrorType::ReadTimedout
        );
        if hard_failure && !ctx.current_origin.is_empty() {
            // `error_while_proxy` is synchronous, so the health write is
            // handed to the runtime. It only runs on failures, never on the
            // success path.
            let health = self.state.origin_health.clone();
            let host = ctx.host.clone();
            let origin = ctx.current_origin.clone();
            let reason = e.to_string();
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    health.record_origin_failure(&host, &origin, &reason).await;
                });
            }
        }
        let idempotent = session.req_header().method.is_idempotent();
        let safe_to_retry = ctx
            .plan
            .as_ref()
            .map(|p| p.cacheable || p.is_head)
            .unwrap_or(false);
        tracing::debug!(
            domain = %ctx.host,
            attempt = ctx.attempt,
            origins = ctx.origin_order.len(),
            addresses = ctx.current_addresses.len(),
            idempotent,
            safe_to_retry,
            error = %e,
            "proxy error while reading upstream"
        );
        if idempotent
            && safe_to_retry
            && !session.as_ref().retry_buffer_truncated()
            && Self::advance_peer(ctx)
        {
            e.set_retry(true);
        } else {
            e.set_retry(false);
        }
        e
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora::http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        upstream_request.remove_header(signed_url::HOTLINK_OK_HEADER);
        if let Some(plan) = ctx.plan.as_ref() {
            // Keep HTTP Host aligned with the peer actually selected.
            let host = if !ctx.current_host_header.is_empty() {
                ctx.current_host_header.clone()
            } else if !ctx.current_origin.is_empty() {
                parse_origin(&ctx.current_origin)
                    .map(|(h, _, _)| h)
                    .unwrap_or_else(|| plan.origin_host.clone())
            } else {
                plan.origin_host.clone()
            };
            upstream_request.insert_header("host", host.as_str())?;
            if !plan.domain.origin_auth_header.trim().is_empty()
                && !plan.domain.origin_auth_value.trim().is_empty()
            {
                if let (Ok(name), Ok(value)) = (
                    HeaderName::from_bytes(plan.domain.origin_auth_header.trim().as_bytes()),
                    HeaderValue::from_str(plan.domain.origin_auth_value.trim()),
                ) {
                    upstream_request.insert_header(name, value)?;
                }
            }
            if plan.cacheable || plan.is_head {
                for name in [
                    "authorization",
                    "cookie",
                    "range",
                    "if-none-match",
                    "if-modified-since",
                    "accept-encoding",
                ] {
                    upstream_request.remove_header(name);
                }
                upstream_request.insert_header("accept-encoding", "identity")?;
            }
            if plan.is_head {
                upstream_request.set_method(Method::GET);
            }
        }
        Ok(())
    }

    fn response_cache_filter(
        &self,
        session: &Session,
        resp: &ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<RespCacheable> {
        let Some(plan) = ctx.plan.as_ref() else {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(
                "legacy path",
            )));
        };
        if !plan.cacheable {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(
                "dynamic request",
            )));
        }
        if resp.headers.contains_key("set-cookie") {
            ctx.cache_reason = Some("set-cookie");
            return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(
                "set-cookie",
            )));
        }
        let content_type = resp
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let query = session.req_header().uri.query().unwrap_or("");
        let mut response_policy = resolve_rule_policy_for_response(
            &plan.domain.rules,
            &ctx.path,
            ctx.method.as_str(),
            query,
            content_type,
        );
        apply_key_ignore_default(&mut response_policy, &plan.domain.cache_key_ignore_headers);
        if response_policy.action != RuleAction::Cache {
            ctx.response_bypass = true;
            ctx.cache_reason = Some("content-type-bypass");
            return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(
                "content-type rule",
            )));
        }
        let headers = header_vec(&resp.headers);
        let decision = match decide_storage_reason(
            resp.status.as_u16(),
            &headers,
            response_policy,
            self.state.default_ttl_secs,
        ) {
            Ok(decision) => decision,
            Err(reason) => {
                ctx.cache_reason = Some(reason);
                return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(
                    "cache policy",
                )));
            }
        };
        let now = SystemTime::now();
        let meta = CacheMeta::new(
            now + Duration::from_secs(decision.ttl_secs),
            now,
            decision.swr_secs.min(u32::MAX as u64) as u32,
            0,
            resp.clone(),
        );
        Ok(RespCacheable::Cacheable(meta))
    }

    fn should_serve_stale(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
        error: Option<&pingora::Error>,
    ) -> bool {
        // None means the normal SWR/stale-updating path. For errors, only
        // upstream failures should be masked by a stale object.
        match error {
            None => true,
            Some(e) => e.esource() == &pingora::ErrorSource::Upstream,
        }
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let Some(plan) = ctx.plan.as_ref() else {
            return Ok(());
        };
        // Bound idle HTTP/1.1 downstream connections. Without this Pingora
        // defaults to no keepalive request limit and no idle cap.
        session.set_keepalive(Some(self.state.downstream_keepalive_secs));
        let content_type = response
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let query = session.req_header().uri.query().unwrap_or("");
        let mut response_policy = resolve_rule_policy_for_response(
            &plan.domain.rules,
            &ctx.path,
            ctx.method.as_str(),
            query,
            content_type,
        );
        apply_key_ignore_default(&mut response_policy, &plan.domain.cache_key_ignore_headers);
        let mut label = if ctx.response_bypass {
            "BYPASS"
        } else if plan.is_websocket {
            "WS"
        } else if plan.cacheable {
            cache_label(session.cache.phase())
        } else {
            plan.label
        };
        if !ctx.response_bypass
            && plan.cacheable
            && response.status == 304
            && session.req_header().headers.contains_key("if-none-match")
        {
            label = "REVALIDATED";
        }
        ctx.cache_label = label;
        ctx.status = response.status.as_u16();
        // Shared-cache hits must expose the object's age, not the origin's
        // stored Age header (commonly `Age: 0` on every cached response).
        if matches!(label, "HIT" | "STALE" | "REVALIDATED") {
            response.remove_header("age");
            if let Some(age) = ctx.cache_age_secs {
                response.insert_header("age", age.to_string())?;
            }
        }
        response.remove_header(META_HEADER);
        response.remove_header(VALIDATOR_SOURCE_HEADER);
        response.remove_header("x-lagran-cache-reason");
        if !response.headers.contains_key("x-lagran-datapath") {
            response.insert_header("x-lagran-datapath", "pingora")?;
        }
        if matches!(label, "HIT" | "STALE" | "REVALIDATED") {
            if let Some(ttl) = ctx.cache_ttl_secs {
                response.insert_header("x-lagran-cache-ttl", ttl.to_string())?;
            }
        }
        response.insert_header("x-cache", label)?;
        response.insert_header("x-cache-status", label)?;
        response.insert_header("x-powered-by", "lagran-edge")?;
        if let Some(reason) = ctx.cache_reason {
            response.insert_header("x-lagran-cache-reason", reason)?;
        }
        let cache_source = if matches!(label, "HIT" | "STALE" | "REVALIDATED") {
            response
                .headers
                .get("x-lagran-cache-source")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("l1")
                .to_string()
        } else {
            "origin".to_string()
        };
        let lookup_ms = response
            .headers
            .get("x-lagran-cache-lookup-ms")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("0")
            .to_string();
        response.insert_header("x-lagran-cache-source", cache_source)?;
        response.insert_header("x-lagran-cache-lookup-ms", lookup_ms.clone())?;
        response.insert_header(
            "server-timing",
            format!("cache;dur={lookup_ms}"),
        )?;

        let mut headers = response.headers.clone();
        if plan.cacheable || plan.is_head {
            let browser_ttl = (response_policy.action == RuleAction::Cache)
                .then(|| policy_browser_ttl(&response_policy))
                .flatten();
            apply_browser_ttl(&mut headers, browser_ttl);
        }
        apply_security_headers(&mut headers);
        apply_cors_and_custom(&mut headers, &plan.cors, &plan.custom);
        for (name, value) in headers.iter() {
            response.insert_header(name.clone(), value.clone())?;
        }
        // Compress here, not upstream: the cache has already stored the
        // identity body, so one object serves every Accept-Encoding.
        if !plan.is_head && !plan.is_websocket {
            let req = session.req_header();
            if should_compress(
                &self.compression,
                req.version,
                &req.method,
                response.status.as_u16(),
                &response.headers,
                &req.headers,
            ) && ctx.gzip.is_none()
            {
                response.insert_header(header::CONTENT_ENCODING, "gzip")?;
                // The compressed length is not known up front.
                response.remove_header(&header::CONTENT_LENGTH);
                vary_on_accept_encoding(response)?;
                // H1 needs explicit framing once Content-Length is gone; H2
                // must not carry Transfer-Encoding at all.
                if req.version == Version::HTTP_11 {
                    response.insert_header(header::TRANSFER_ENCODING, "chunked")?;
                }
                weaken_etag(response)?;
                ctx.gzip = Some(GzipEncoder::new(self.compression.level));
            }
        }
        if plan.is_head {
            // HEAD carries no downstream body. Keeping the origin GET's
            // Content-Length makes Pingora's H1 encoder wait for bytes that
            // will never be written; use zero so the header completes.
            let _ = response.remove_header("transfer-encoding");
            let _ = response.insert_header("content-length", "0");
            ctx.head_headers = Some(response.clone());
            ctx.head_status = response.status.as_u16();
        }
        if let Some(fill) = ctx.range_fill.take() {
            if response_policy.action == RuleAction::Cache
                && response.status == StatusCode::PARTIAL_CONTENT.as_u16()
            {
                if let Some((start, end, total)) = response
                    .headers
                    .get("content-range")
                    .and_then(|v| v.to_str().ok())
                    .and_then(parse_content_range)
                {
                    if let Some(large) = self.state.large_cache.as_ref() {
                        let mut hdrs = header_vec(&response.headers);
                        hdrs.retain(|(name, _)| {
                            !name.eq_ignore_ascii_case("content-range")
                                && !name.eq_ignore_ascii_case("content-length")
                                && !name.eq_ignore_ascii_case("transfer-encoding")
                                && !name.eq_ignore_ascii_case("connection")
                                && !name.eq_ignore_ascii_case("x-cache")
                                && !name.eq_ignore_ascii_case("x-cache-status")
                                && !name.eq_ignore_ascii_case("x-lagran-cache-reason")
                                && !name.eq_ignore_ascii_case("x-powered-by")
                        });
                        if let Some((fill_start, fill_end)) = fill_window(
                            &fill.raw_range,
                            start,
                            end,
                            total,
                            self.state.range_fill_max_bytes,
                        ) {
                            if let Ok(decision) = decide_storage_reason(
                                200,
                                &hdrs,
                                response_policy,
                                self.state.default_ttl_secs,
                            ) {
                                if let Some(writer) = large
                                    .begin_range(
                                        &fill.key,
                                        200,
                                        hdrs,
                                        total,
                                        fill_start,
                                        fill_end,
                                        decision.ttl_secs,
                                        decision.swr_secs,
                                    )
                                    .await
                                {
                                    let (tx, mut rx) =
                                        tokio::sync::mpsc::unbounded_channel::<RangeMsg>();
                                    let queued =
                                        std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
                                    let writer_queued = queued.clone();
                                    tokio::spawn(async move {
                                        let mut writer = Some(writer);
                                        let mut finished = false;
                                        while let Some(msg) = rx.recv().await {
                                            match msg {
                                                RangeMsg::Chunk(data) => {
                                                    writer_queued.fetch_sub(
                                                        data.len() as u64,
                                                        std::sync::atomic::Ordering::Relaxed,
                                                    );
                                                    if let Some(w) = writer.as_mut() {
                                                        w.write_all(&data).await;
                                                    }
                                                }
                                                RangeMsg::End => {
                                                    // A short origin response or
                                                    // client disconnect still
                                                    // commits the bytes actually
                                                    // received; the metadata
                                                    // never marks it complete.
                                                    if let Some(w) = writer.take() {
                                                        let _ = w.commit_partial().await;
                                                    }
                                                    finished = true;
                                                    break;
                                                }
                                            }
                                        }
                                        if !finished {
                                            // Client disconnected or the writer
                                            // queue overflowed. Preserve the
                                            // completed prefix instead of
                                            // discarding the whole fill.
                                            if let Some(w) = writer.take() {
                                                let _ = w.commit_partial().await;
                                            }
                                        }
                                    });
                                    ctx.range_sink = Some(RangeSink {
                                        tx,
                                        offset: fill_start,
                                        end: fill_end,
                                        skip: fill_start.saturating_sub(start),
                                        queued,
                                    });
                                } else {
                                    ctx.cache_reason = Some(if fill_end
                                        .saturating_sub(fill_start)
                                        .saturating_add(1)
                                        > large.max_object_bytes()
                                    {
                                        "range-too-large"
                                    } else {
                                        "range-fill-skipped"
                                    });
                                }
                            } else {
                                ctx.cache_reason = Some("range-uncacheable");
                            }
                        } else {
                            ctx.cache_reason = Some("range-fill-skipped");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<Duration>> {
        if ctx.gzip.is_some() {
            let mut encoded = BytesMut::new();
            if let Some(chunk) = body.as_ref() {
                if let Some(encoder) = ctx.gzip.as_mut() {
                    encoded.extend_from_slice(&encoder.write(chunk));
                }
            }
            if end_of_stream {
                if let Some(encoder) = ctx.gzip.take() {
                    encoded.extend_from_slice(&encoder.finish());
                }
            }
            *body = if encoded.is_empty() {
                None
            } else {
                Some(encoded.freeze())
            };
            return Ok(None);
        }
        if let Some(sink) = ctx.range_sink.as_mut() {
            let mut reached_fill_end = false;
            if let Some(chunk) = body.as_ref() {
                // Only write bytes inside the planned fill window. For an
                // open-ended video request the client keeps receiving the
                // stream, but the cache stops at the bounded prefix.
                let mut chunk_ref = chunk.as_ref();
                if sink.skip > 0 {
                    let discard = (sink.skip as usize).min(chunk_ref.len());
                    chunk_ref = &chunk_ref[discard..];
                    sink.skip -= discard as u64;
                }
                let remaining = sink.end.saturating_sub(sink.offset).saturating_add(1);
                let take = (chunk_ref.len() as u64).min(remaining) as usize;
                if take > 0 {
                    let data = if take == chunk_ref.len() {
                        Bytes::copy_from_slice(chunk_ref)
                    } else {
                        Bytes::copy_from_slice(&chunk_ref[..take])
                    };
                    let queued = sink
                        .queued
                        .fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed)
                        + data.len() as u64;
                    if queued > 64 * 1024 * 1024 || sink.tx.send(RangeMsg::Chunk(data)).is_err() {
                        // Disk writer is slower than the origin. Drop the fill
                        // rather than growing an unbounded queue; the client
                        // body is still forwarded unchanged.
                        ctx.range_sink = None;
                        return Ok(None);
                    }
                    sink.offset = sink.offset.saturating_add(take as u64);
                }
                reached_fill_end = sink.offset > sink.end;
            }
            if end_of_stream || reached_fill_end {
                if let Some(sink) = ctx.range_sink.take() {
                    let _ = sink.tx.send(RangeMsg::End);
                }
            }
            return Ok(None);
        }
        if ctx.plan.as_ref().is_some_and(|p| p.is_head) {
            if let Some(chunk) = body.take() {
                ctx.head_body.extend_from_slice(&chunk);
            }
        }
        Ok(None)
    }

    async fn logging(
        &self,
        session: &mut Session,
        _e: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) {
        if ctx.skip_logging {
            return;
        }
        let status = session
            .response_written()
            .map(|r| r.status.as_u16())
            .unwrap_or(ctx.status);
        let bytes = session.body_bytes_sent() as u64;
        let label = ctx.cache_label;
        if let Some(plan) = ctx.plan.as_ref() {
        if plan.is_head && ctx.head_status == 200 && !ctx.head_body.is_empty() {
            if let Some(headers) = ctx.head_headers.as_ref() {
                let mut hdrs = header_vec(&headers.headers);
                hdrs.retain(|(k, _)| !k.eq_ignore_ascii_case("content-length"));
                hdrs.push((
                    "content-length".to_string(),
                    ctx.head_body.len().to_string(),
                ));
                if let Ok(decision) = decide_storage_reason(
                    ctx.head_status,
                    &hdrs,
                    plan.policy,
                    self.state.default_ttl_secs,
                ) {
                    if ctx.head_body.len() <= 8 * 1024 * 1024 {
                        let now_epoch = SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let mut entry = crate::cache::CacheEntry {
                            status: ctx.head_status,
                            headers: hdrs,
                            body: ctx.head_body.clone().freeze(),
                            stored_at_epoch_secs: now_epoch,
                            fresh_until_epoch_secs: now_epoch
                                + decision.ttl_secs.max(1),
                            stale_until_epoch_secs: now_epoch
                                + decision.ttl_secs.max(1)
                                + decision.swr_secs,
                        };
                        if entry.header("etag").is_none() {
                            let etag = compute_etag(&entry);
                            entry.headers.push(("etag".to_string(), etag));
                        }
                        self.state
                            .cache
                            .set_with_swr(&plan.key, entry, decision.ttl_secs, decision.swr_secs)
                            .await;
                    }
                }
            }
        }
        }
        log_access(
            &self.state.access_log,
            &ctx.method,
            &ctx.host,
            &ctx.path,
            status,
            ctx.start,
            &ctx.client_ip,
            &ctx.user_agent,
            &ctx.referer,
            bytes,
            label,
            &ctx.request_id,
        )
        .await;
        match label {
            "HIT" | "STALE" => self.state.metrics.record_hit(&ctx.host, bytes).await,
            "MISS" | "REVALIDATED" => self.state.metrics.record_miss(&ctx.host, bytes).await,
            _ => self.state.metrics.record_bypass(&ctx.host, bytes).await,
        }
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &pingora::Error,
        ctx: &mut Self::CTX,
    ) -> FailToProxy {
        let timeout = matches!(
            e.etype(),
            pingora::ErrorType::ConnectTimedout
                | pingora::ErrorType::TLSHandshakeTimedout
                | pingora::ErrorType::ReadTimedout
                | pingora::ErrorType::WriteTimedout
        );
        let failure = if timeout {
            OriginFailure::Timeout
        } else {
            OriginFailure::Unreachable
        };
        let code = if ctx.plan.is_some() {
            let status = failure.status().as_u16();
            let page = default_page::origin_error_page(&ctx.host, &ctx.path, failure);
            write_axum_response(session, page, ctx.method == Method::HEAD).await;
            status
        } else {
            502
        };
        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }
}

impl DataPlaneProxy {
    /// Large-object conditional revalidation. For strict requests, try a HEAD
    /// conditional request first. A 304 is served from the existing large file
    /// without touching its body; a 200 removes the stale object and lets the
    /// normal native path stream and replace it.
    async fn try_large_revalidation(
        &self,
        session: &mut Session,
        ctx: &mut ReqCtx,
    ) -> Result<bool> {
        if session.req_header().method != Method::GET
            || session.req_header().headers.contains_key("range")
        {
            return Ok(false);
        }
        let strict = session
            .req_header()
            .headers
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .map(|v| {
                v.split(',')
                    .any(|p| p.trim().eq_ignore_ascii_case("no-cache"))
                    || v.split(',')
                        .any(|p| p.trim().eq_ignore_ascii_case("max-age=0"))
            })
            .unwrap_or(false)
            || session
                .req_header()
                .headers
                .get("pragma")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.eq_ignore_ascii_case("no-cache"));
        if !strict {
            return Ok(false);
        }

        let cache_control = session.req_header().headers.get("cache-control").cloned();
        let pragma = session.req_header().headers.get("pragma").cloned();
        session.req_header_mut().remove_header("cache-control");
        session.req_header_mut().remove_header("pragma");
        let plan = self.native_plan(session).await;
        let Some(plan) = plan else {
            if let Some(v) = cache_control {
                let _ = session.req_header_mut().insert_header("cache-control", v);
            }
            if let Some(v) = pragma {
                let _ = session.req_header_mut().insert_header("pragma", v);
            }
            return Ok(false);
        };
        // Normal-object conditional revalidation. On 304 the cached body is
        // served here; on a changed origin the entry is dropped and the native
        // path performs a single streaming fill. This keeps strict no-cache
        // GETs out of the legacy data plane.
        let _revalidation_guard = if let Some(flight) = self.state.flight.as_ref() {
            match flight.try_lock(&plan.key).await {
                Ok(Some(guard)) => Some(guard),
                Ok(None) => {
                    // Another node is validating this key. Wait for its
                    // conditional request to finish, then use the refreshed
                    // shared entry instead of firing a duplicate origin check.
                    flight.wait_unlocked(&plan.key).await;
                    None
                }
                Err(_) => None,
            }
        } else {
            None
        };
        if let Some(entry) = self.state.cache.get(&plan.key).await {
            if self
                .try_normal_revalidation(session, ctx, &plan, entry)
                .await?
            {
                self.state.metrics.record_pingora_datapath();
                return Ok(true);
            }
            return Ok(false);
        }
        let Some(large) = self.state.large_cache.as_ref() else {
            // No LargeCache: the normal-object path above is sufficient. The
            // native path will stream and fill SharedCache for this cold/large
            // object.
            return Ok(false);
        };
        let Some(entry) = large.get_any(&plan.key).await else {
            // No large object: leave request cache headers removed so the
            // native path streams and fills the large cache in one pass.
            return Ok(false);
        };
        if !entry.meta.complete {
            return Ok(false);
        }
        let etag = entry
            .meta
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("etag"))
            .map(|(_, v)| v.clone());
        let last_modified = entry
            .meta
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("last-modified"))
            .map(|(_, v)| v.clone());
        let validator_source = entry
            .meta
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(VALIDATOR_SOURCE_HEADER))
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        if validator_source == "computed" {
            large.delete(&plan.key).await;
            return Ok(false);
        }
        if etag.is_none() && last_modified.is_none() {
            large.delete(&plan.key).await;
            return Ok(false);
        }

        let target = match plan.origins.iter().find(|origin| origin.enabled) {
            Some(target) => target.clone(),
            None => return Ok(false),
        };
        let path_and_query = session
            .req_header()
            .uri
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        let mut headers = session.req_header().headers.clone();
        if let Some(host) = target.host_header.as_deref() {
            if let Ok(value) = HeaderValue::from_str(host) {
                headers.insert(axum::http::header::HOST, value);
            }
        }
        origin_auth::apply(
            &mut headers,
            &plan.domain.origin_auth_header,
            &plan.domain.origin_auth_value,
        );
        if let Some(etag) = etag {
            if let Ok(value) = HeaderValue::from_str(&etag) {
                headers.insert("if-none-match", value);
            }
        } else if let Some(last_modified) = last_modified {
            if let Ok(value) = HeaderValue::from_str(&last_modified) {
                headers.insert("if-modified-since", value);
            }
        }
        let conditional = match self
            .state
            .origin
            .request_with_sni(
                &target.url,
                &Method::HEAD,
                &path_and_query,
                &headers,
                None,
                false,
                target.sni.as_deref(),
            )
            .await
        {
            Ok(response) => response,
            Err(_) => {
                large.delete(&plan.key).await;
                return Ok(false);
            }
        };
        if conditional.status != StatusCode::NOT_MODIFIED {
            large.delete(&plan.key).await;
            return Ok(false);
        }
        let conditional_headers = header_vec(&conditional.headers);
        let mut merged_headers = entry.meta.headers.clone();
        for (name, value) in &conditional_headers {
            if name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("transfer-encoding")
                || name.eq_ignore_ascii_case("connection")
                || name.eq_ignore_ascii_case("age")
            {
                continue;
            }
            merged_headers.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
            merged_headers.push((name.clone(), value.clone()));
        }
        let decision = match decide_storage_reason(
            200,
            &merged_headers,
            plan.policy,
            self.state.default_ttl_secs,
        ) {
            Ok(decision) => decision,
            Err(_) => return Ok(false),
        };
        if !large
            .refresh_meta(
                &plan.key,
                &conditional_headers,
                decision.ttl_secs,
                decision.swr_secs,
            )
            .await
        {
            return Ok(false);
        }
        let Some(entry) = large.get(&plan.key).await else {
            return Ok(false);
        };
        ctx.cache_label = "REVALIDATED";
        ctx.cache_reason = Some("origin-304");
        self.serve_large_full(session, entry, &plan).await;
        self.state.metrics.record_pingora_datapath();
        Ok(true)
    }

    async fn try_normal_revalidation(
        &self,
        session: &mut Session,
        ctx: &mut ReqCtx,
        plan: &NativePlan,
        entry: crate::cache::CacheEntry,
    ) -> Result<bool> {
        let source = entry
            .header(VALIDATOR_SOURCE_HEADER)
            .unwrap_or("");
        let etag = entry.header("etag").map(str::to_string);
        let last_modified = entry.header("last-modified").map(str::to_string);
        if source == "computed" {
            self.state.cache.delete(&plan.key).await;
            return Ok(false);
        }
        let use_etag = match source {
            "etag" => etag.is_some(),
            "last-modified" => false,
            _ => etag.is_some(),
        };
        let use_last_modified = !use_etag && last_modified.is_some();
        if !use_etag && !use_last_modified {
            self.state.cache.delete(&plan.key).await;
            return Ok(false);
        }

        let target = match plan.origins.iter().find(|origin| origin.enabled) {
            Some(target) => target.clone(),
            None => return Ok(false),
        };
        let path_and_query = session
            .req_header()
            .uri
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        let mut headers = session.req_header().headers.clone();
        headers.remove("cache-control");
        headers.remove("pragma");
        headers.remove("if-none-match");
        headers.remove("if-modified-since");
        if let Some(host) = target.host_header.as_deref() {
            if let Ok(value) = HeaderValue::from_str(host) {
                headers.insert(axum::http::header::HOST, value);
            }
        }
        origin_auth::apply(
            &mut headers,
            &plan.domain.origin_auth_header,
            &plan.domain.origin_auth_value,
        );
        if use_etag {
            if let Some(etag) = etag.as_deref() {
                if let Ok(value) = HeaderValue::from_str(etag) {
                    headers.insert("if-none-match", value);
                }
            }
        } else if let Some(last_modified) = last_modified.as_deref() {
            if let Ok(value) = HeaderValue::from_str(last_modified) {
                headers.insert("if-modified-since", value);
            }
        }

        let conditional = match tokio::time::timeout(
            Duration::from_millis(plan.read_timeout_ms),
            self.state.origin.request_with_sni(
                &target.url,
                &Method::GET,
                &path_and_query,
                &headers,
                None,
                false,
                target.sni.as_deref(),
            ),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(_)) | Err(_) => {
                self.state.metrics.record_origin_error();
                self.state.cache.delete(&plan.key).await;
                return Ok(false);
            }
        };
        if conditional.status != StatusCode::NOT_MODIFIED {
            // Some origins/shields answer a conditional GET with an empty 200
            // even though the cached representation is non-empty. Keep the
            // cached body instead of replacing it with a blank response.
            if conditional.status.is_success()
                && conditional.body.is_empty()
                && !entry.body.is_empty()
            {
                ctx.cache_label = "REVALIDATED";
                ctx.cache_reason = Some("origin-empty-fallback");
                self.serve_normal_entry(session, entry, plan, "origin-empty-fallback")
                    .await;
                return Ok(true);
            }
            if conditional.status.is_success() {
                let entry = conditional.into_entry();
                if entry.body.len() <= self.state.max_cacheable_body {
                    if let Ok(decision) = decide_storage_reason(
                        entry.status,
                        &entry.headers,
                        plan.policy,
                        self.state.default_ttl_secs,
                    ) {
                        self.state
                            .cache
                            .set_with_swr(
                                &plan.key,
                                entry.clone(),
                                decision.ttl_secs,
                                decision.swr_secs,
                            )
                            .await;
                    }
                }
                ctx.cache_label = "REVALIDATED";
                ctx.cache_reason = Some("origin-200");
                self.serve_normal_entry(session, entry, plan, "origin-200")
                    .await;
                return Ok(true);
            }
            self.state.cache.delete(&plan.key).await;
            return Ok(false);
        }

        let mut refreshed = entry;
        refreshed
            .headers
            .retain(|(name, _)| !name.eq_ignore_ascii_case("date"));
        for (name, value) in &conditional.headers {
            if name.as_str().eq_ignore_ascii_case("content-length")
                || name.as_str().eq_ignore_ascii_case("transfer-encoding")
                || name.as_str().eq_ignore_ascii_case("connection")
                || name.as_str().eq_ignore_ascii_case("age")
            {
                continue;
            }
            refreshed
                .headers
                .retain(|(existing, _)| !existing.eq_ignore_ascii_case(name.as_str()));
            refreshed
                .headers
                .push((name.as_str().to_string(), value.to_str().unwrap_or("").to_string()));
        }
        let decision = match decide_storage_reason(
            refreshed.status,
            &refreshed.headers,
            plan.policy,
            self.state.default_ttl_secs,
        ) {
            Ok(decision) => decision,
            Err(_) => {
                self.state.cache.delete(&plan.key).await;
                return Ok(false);
            }
        };
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        refreshed.stored_at_epoch_secs = now;
        refreshed.fresh_until_epoch_secs = now + decision.ttl_secs.max(1);
        refreshed.stale_until_epoch_secs = now + decision.ttl_secs.max(1) + decision.swr_secs;
        self.state
            .cache
            .set_with_swr(
                &plan.key,
                refreshed.clone(),
                decision.ttl_secs,
                decision.swr_secs,
            )
            .await;
        ctx.cache_label = "REVALIDATED";
        ctx.cache_reason = Some("origin-304");
        self.serve_normal_entry(session, refreshed, plan, "origin-304")
            .await;
        Ok(true)
    }

    async fn serve_normal_range(
        &self,
        session: &mut Session,
        entry: &crate::cache::CacheEntry,
        start: u64,
        end: u64,
        total: u64,
        plan: &NativePlan,
        source: CacheSource,
    ) -> bool {
        let len = end.saturating_sub(start).saturating_add(1);
        if len == 0 || end >= total {
            return false;
        }
        let Ok(mut response) = ResponseHeader::build(
            StatusCode::PARTIAL_CONTENT.as_u16(),
            Some(len as usize),
        ) else {
            return false;
        };
        for (name, value) in &entry.headers {
            if name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("content-range")
                || name.eq_ignore_ascii_case("age")
                || name.eq_ignore_ascii_case(META_HEADER)
                || name.eq_ignore_ascii_case(VALIDATOR_SOURCE_HEADER)
                || is_hop_by_hop(name)
            {
                continue;
            }
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                let _ = response.insert_header(name, value);
            }
        }
        let _ = response.insert_header("content-range", format!("bytes {start}-{end}/{total}"));
        let _ = response.insert_header("content-length", len.to_string());
        let _ = response.insert_header("accept-ranges", "bytes");
        let _ = response.insert_header("x-cache", "HIT");
        let _ = response.insert_header("x-cache-status", "HIT");
        let _ = response.insert_header("x-lagran-cache-source", source.as_str());
        let _ = response.insert_header("x-lagran-cache-reason", "range-shared-cache");
        let _ = response.insert_header("x-powered-by", "lagran-edge");
        let _ = response.insert_header("x-lagran-datapath", "pingora");
        if let Some(age) = entry.ttl_secs() {
            let _ = age;
        }
        let _ = response.insert_header("age", entry.age_secs().to_string());
        if let Some(ttl) = entry.ttl_secs() {
            let _ = response.insert_header("x-lagran-cache-ttl", ttl.to_string());
        }
        let mut final_headers = response.headers.clone();
        apply_security_headers(&mut final_headers);
        apply_cors_and_custom(&mut final_headers, &plan.cors, &plan.custom);
        for (name, value) in final_headers.iter() {
            let _ = response.insert_header(name.clone(), value.clone());
        }
        if session
            .write_response_header(Box::new(response), false)
            .await
            .is_err()
        {
            return false;
        }
        let body = entry
            .body
            .slice(start as usize..=(end as usize).min(entry.body.len().saturating_sub(1)));
        session
            .write_response_body(Some(body), true)
            .await
            .is_ok()
    }

    async fn serve_normal_entry(
        &self,
        session: &mut Session,
        entry: crate::cache::CacheEntry,
        plan: &NativePlan,
        reason: &'static str,
    ) {
        let len = entry.body.len();
        let client_match = entry
            .header("etag")
            .is_some_and(|etag| {
                session
                    .req_header()
                    .headers
                    .get("if-none-match")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|value| {
                        value
                            .split(',')
                            .map(str::trim)
                            .any(|candidate| candidate == etag || candidate == "*")
                    })
            });
        let status = StatusCode::OK;
        let mut response = match ResponseHeader::build(status.as_u16(), None) {
            Ok(response) => response,
            Err(_) => return,
        };
        for (name, value) in &entry.headers {
            if name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("age")
                || name.eq_ignore_ascii_case(META_HEADER)
                || name.eq_ignore_ascii_case(VALIDATOR_SOURCE_HEADER)
                || is_hop_by_hop(name)
            {
                continue;
            }
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                let _ = response.insert_header(name, value);
            }
        }
        let _ = response.insert_header("x-cache", "REVALIDATED");
        let _ = response.insert_header("x-cache-status", "REVALIDATED");
        let _ = response.insert_header("x-lagran-cache-reason", reason);
        let _ = response.insert_header("x-powered-by", "lagran-edge");
        let _ = response.insert_header("x-lagran-datapath", "pingora");
        let _ = response.insert_header("age", "0");
        if let Some(ttl) = entry.ttl_secs() {
            let _ = response.insert_header("x-lagran-cache-ttl", ttl.to_string());
        }
        let mut final_headers = response.headers.clone();
        apply_security_headers(&mut final_headers);
        apply_cors_and_custom(&mut final_headers, &plan.cors, &plan.custom);
        for (name, value) in final_headers.iter() {
            let _ = response.insert_header(name.clone(), value.clone());
        }

        if client_match {
            let mut not_modified = match ResponseHeader::build(StatusCode::NOT_MODIFIED.as_u16(), None)
            {
                Ok(response) => response,
                Err(_) => return,
            };
            for name in [
                "cache-control",
                "vary",
                "expires",
                "etag",
                "last-modified",
                "age",
            ] {
                if let Some(value) = entry.header(name) {
                    if let Ok(value) = HeaderValue::from_str(value) {
                        let _ = not_modified.insert_header(name, value);
                    }
                }
            }
            if let Some(ttl) = entry.ttl_secs() {
                let _ = not_modified.insert_header("x-lagran-cache-ttl", ttl.to_string());
            }
            let _ = not_modified.insert_header("x-cache", "REVALIDATED");
            let _ = not_modified.insert_header("x-cache-status", "REVALIDATED");
            let _ = not_modified.insert_header("x-lagran-cache-reason", reason);
            let _ = not_modified.insert_header("x-powered-by", "lagran-edge");
            let _ = not_modified.insert_header("x-lagran-datapath", "pingora");
            let _ = session
                .write_response_header(Box::new(not_modified), true)
                .await;
            return;
        }

        let _ = response.insert_header("content-length", len.to_string());
        if session
            .write_response_header(Box::new(response), false)
            .await
            .is_err()
        {
            return;
        }
        let _ = session
            .write_response_body(Some(entry.body), true)
            .await;
    }

    async fn serve_large_full(
        &self,
        session: &mut Session,
        entry: crate::cache::large::LargeEntry,
        plan: &NativePlan,
    ) {
        let total = entry.content_length();
        let now_epoch = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let cache_ttl = entry.meta.fresh_until.saturating_sub(now_epoch);
        let etag = entry
            .meta
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("etag"))
            .map(|(_, v)| v.clone());
        if let Some(etag) = etag.as_deref() {
            let client_match = session
                .req_header()
                .headers
                .get("if-none-match")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|value| {
                    value
                        .split(',')
                        .map(str::trim)
                        .any(|candidate| candidate == etag || candidate == "*")
                });
            if client_match {
                let Ok(mut response) = ResponseHeader::build(StatusCode::NOT_MODIFIED.as_u16(), None)
                else {
                    return;
                };
                for (name, value) in &entry.meta.headers {
                    if name.eq_ignore_ascii_case("content-length")
                        || name.eq_ignore_ascii_case(META_HEADER)
                        || name.eq_ignore_ascii_case(VALIDATOR_SOURCE_HEADER)
                        || is_hop_by_hop(name)
                        || !crate::cache::large::LargeCache::replayable_header(name)
                    {
                        continue;
                    }
                    if let (Ok(name), Ok(value)) = (
                        HeaderName::from_bytes(name.as_bytes()),
                        HeaderValue::from_str(value),
                    ) {
                        let _ = response.insert_header(name, value);
                    }
                }
                let _ = response.insert_header("x-cache", "REVALIDATED");
                let _ = response.insert_header("x-cache-status", "REVALIDATED");
                let _ = response.insert_header("x-lagran-cache-reason", "origin-304");
                let _ = response.insert_header("x-lagran-cache-ttl", cache_ttl.to_string());
                let _ = response.insert_header("x-powered-by", "lagran-edge");
        let _ = response.insert_header("x-lagran-datapath", "pingora");
                let _ = session.write_response_header(Box::new(response), true).await;
                return;
            }
        }

        let Ok(mut response) =
            ResponseHeader::build(StatusCode::OK.as_u16(), Some(total as usize))
        else {
            return;
        };
        for (name, value) in &entry.meta.headers {
            if name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("content-range")
                || name.eq_ignore_ascii_case(META_HEADER)
                || name.eq_ignore_ascii_case(VALIDATOR_SOURCE_HEADER)
                || is_hop_by_hop(name)
                || !crate::cache::large::LargeCache::replayable_header(name)
            {
                continue;
            }
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                let _ = response.insert_header(name, value);
            }
        }
        let _ = response.insert_header("content-length", total.to_string());
        let _ = response.insert_header("x-cache", "REVALIDATED");
        let _ = response.insert_header("x-cache-status", "REVALIDATED");
        let _ = response.insert_header("x-lagran-cache-reason", "origin-304");
        let _ = response.insert_header("x-powered-by", "lagran-edge");
        let _ = response.insert_header("x-lagran-datapath", "pingora");
        let _ = response.insert_header("age", "0");
        let _ = response.insert_header("x-lagran-cache-ttl", cache_ttl.to_string());
        let mut final_headers = response.headers.clone();
        apply_security_headers(&mut final_headers);
        apply_cors_and_custom(&mut final_headers, &plan.cors, &plan.custom);
        for (name, value) in final_headers.iter() {
            let _ = response.insert_header(name.clone(), value.clone());
        }
        if session
            .write_response_header(Box::new(response), false)
            .await
            .is_err()
        {
            return;
        }
        let mut entry = entry;
        const CHUNK: u64 = 8 * 1024 * 1024;
        let mut pos = 0;
        while pos < total {
            let want = (total - pos).min(CHUNK) as usize;
            let Ok(Some(chunk)) = entry.read_at(pos, want).await else {
                return;
            };
            pos += chunk.len() as u64;
            let done = pos >= total;
            if session
                .write_response_body(Some(chunk), done)
                .await
                .is_err()
            {
                return;
            }
            if done {
                break;
            }
        }
    }

    async fn native_plan(&self, session: &Session) -> Option<NativePlan> {
        if !self.native_cache || self.storage.is_none() {
            return None;
        }
        let req = session.req_header();
        // HEAD stays on the in-process engine: it fetches GET, returns the real
        // Content-Length, and shares the GET cache entry. Pingora's H1 encoder
        // cannot carry an upstream GET body under a HEAD response.
        if req.method == Method::HEAD {
            return None;
        }
        let has_range = req.headers.contains_key("range");
        // Small bounded ranges are served from SharedCache when possible; the
        // remaining ranges use native streaming.
        // Small bounded ranges normally use the in-process slice cache. When
        // the complete object is already in the large-object cache, keep the
        // request on the Pingora path so it can be served directly from disk.
        // Open-ended ranges (`bytes=0-`) stay streaming as before.
        let host = request_host(req.headers.get("host").and_then(|v| v.to_str().ok()));
        if host.is_empty() {
            return None;
        }
        if !self.state.node_control.is_serving() {
            return None;
        }
        let domain = self.state.domains.get(&host).await?;
        let path = req.uri.path().to_string();
        let path_and_query = req
            .uri
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        let pipeline = RequestPipeline::new(&self.state);
        let policy = pipeline.policy_for(
            &domain,
            &req.method,
            &path,
            req.uri.query().unwrap_or(""),
        );
        let class = pipeline.classify_request(&req.method, &req.headers, &policy);
        let request_reason = if has_range {
            // Range requests must stay streaming. Fetching a full video to
            // serve a slice (especially `bytes=0-`) exceeds origin timeouts.
            Some("range-bypass")
        } else {
            class.reason()
        };
        // Strict client revalidation has a dedicated conditional-origin path in
        // the in-process engine (304 refresh). Keep it off the native cache
        // fast path so a stale body is never served on max-age=0/no-cache.
        if matches!(
            request_reason,
            Some("request-max-age-0" | "request-no-cache" | "request-pragma-no-cache")
        ) {
            return None;
        }
        let bypasses = request_reason.is_some();
        let is_head = req.method == Method::HEAD && policy.action == RuleAction::Cache && !bypasses;
        let is_websocket = is_websocket_upgrade(&req.headers);
        let cacheable = req.method == Method::GET
            && policy.action == RuleAction::Cache
            && !is_websocket
            && !bypasses
            && !has_range;
        let label = if cacheable || is_head {
            "MISS"
        } else if policy.action == RuleAction::Bypass || req.method == Method::GET {
            "BYPASS"
        } else {
            "DYNAMIC"
        };
        let (origin_host, _, _) = parse_origin(&domain.origin_url)?;
        let key = pipeline.cache_key_for(
            &domain,
            &req.method,
            &host,
            &path,
            &path_and_query,
            &req.headers,
            &policy,
        );
        // Ranges use native streaming unless a complete cached object covers
        // the slice above. This keeps every GET/HEAD request on Pingora.
        Some(NativePlan {
            domain: domain.clone(),
            key,
            origin_host,
            origins: domain.origins.clone(),
            backup_url: domain.backup_origin_url.clone(),
            connect_timeout_ms: effective_connect_timeout_ms(
                domain.origin_timeout_ms,
                self.state.origin.connect_timeout_ms(),
            ),
            read_timeout_ms: self.state.origin_read_timeout_ms,
            cache_reason: request_reason,
            policy,
            cors: domain.cors_origins.clone(),
            custom: domain.custom_headers.clone(),
            cacheable,
            is_head,
            is_websocket,
            label,
        })
    }

    async fn serve_large_range(
        &self,
        session: &mut Session,
        entry: &mut crate::cache::large::LargeEntry,
        start: u64,
        end: u64,
        total: u64,
        plan: &NativePlan,
        fresh: bool,
    ) -> bool {
        let len = end.saturating_sub(start).saturating_add(1);
        if len == 0 || len > usize::MAX as u64 {
            return false;
        }
        let cache_label = if fresh { "HIT" } else { "STALE" };
        let Ok(mut response) =
            ResponseHeader::build(StatusCode::PARTIAL_CONTENT.as_u16(), Some(len as usize))
        else {
            return false;
        };
        for (name, value) in &entry.meta.headers {
            if name.eq_ignore_ascii_case(META_HEADER)
                || name.eq_ignore_ascii_case(VALIDATOR_SOURCE_HEADER)
                || name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("content-range")
                || name.eq_ignore_ascii_case("cache-status")
                || is_hop_by_hop(name)
                || !crate::cache::large::LargeCache::replayable_header(name)
            {
                continue;
            }
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                if response.append_header(name, value).is_err() {
                    return false;
                }
            }
        }
        if response
            .insert_header("content-range", format!("bytes {start}-{end}/{total}"))
            .is_err()
            || response
                .insert_header("content-length", len.to_string())
                .is_err()
            || response.insert_header("accept-ranges", "bytes").is_err()
            || response.insert_header("x-cache", cache_label).is_err()
            || response
                .insert_header("x-cache-status", cache_label)
                .is_err()
            || response
                .insert_header("x-lagran-cache-source", "l3")
                .is_err()
            || (!fresh
                && response
                    .insert_header("x-lagran-cache-reason", "stale-range")
                    .is_err())
        {
            return false;
        }
        let mut final_headers = response.headers.clone();
        apply_security_headers(&mut final_headers);
        apply_cors_and_custom(&mut final_headers, &plan.cors, &plan.custom);
        let _ = final_headers.insert("x-powered-by", HeaderValue::from_static("lagran-edge"));
        for (name, value) in final_headers.iter() {
            if response.insert_header(name.clone(), value.clone()).is_err() {
                return false;
            }
        }
        if entry.meta.stored_at > 0 {
            let age = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs().saturating_sub(entry.meta.stored_at))
                .unwrap_or(0);
            let _ = response.insert_header("age", age.to_string());
            let ttl = entry.meta.fresh_until.saturating_sub(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            );
            let _ = response.insert_header("x-lagran-cache-ttl", ttl.to_string());
        }
        if session
            .write_response_header(Box::new(response), false)
            .await
            .is_err()
        {
            return false;
        }

        const CHUNK: u64 = 8 * 1024 * 1024;
        let mut pos = start;
        while pos <= end {
            let want = (end - pos + 1).min(CHUNK) as usize;
            let Ok(Some(chunk)) = entry.read_at(pos, want).await else {
                // Headers are already on the wire; closing the stream is safer
                // than appending a contradictory error response.
                return true;
            };
            if chunk.is_empty() {
                return true;
            }
            pos += chunk.len() as u64;
            let done = pos > end;
            if session
                .write_response_body(Some(chunk), done)
                .await
                .is_err()
            {
                return true;
            }
            if done {
                break;
            }
        }
        true
    }

    /// Serve a Range from a cached contiguous prefix plus the origin for the
    /// remaining bytes. This makes a second `Range: bytes=0-` request use the
    /// cached prefix immediately while still returning the complete object.
    #[allow(clippy::too_many_arguments)]
    async fn serve_large_range_splice(
        &self,
        session: &mut Session,
        entry: &mut crate::cache::large::LargeEntry,
        start: u64,
        cached_end: u64,
        end: u64,
        total: u64,
        plan: &NativePlan,
    ) -> bool {
        let len = end.saturating_sub(start).saturating_add(1);
        if len == 0 || len > usize::MAX as u64 || cached_end < start || cached_end >= end {
            return false;
        }
        // The prefix must be identity-encoded to concatenate with an identity
        // origin remainder. Compressed prefixes fall back to the normal path.
        if entry.meta.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("content-encoding")
                && !value.eq_ignore_ascii_case("identity")
                && !value.is_empty()
        }) {
            return false;
        }
        let remainder_start = cached_end.saturating_add(1);
        let path_and_query = session
            .req_header()
            .uri
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());

        let target = plan
            .origins
            .iter()
            .find(|origin| origin.enabled)
            .cloned()
            .unwrap_or_else(|| OriginTarget {
                url: plan.domain.origin_url.clone(),
                weight: 100,
                priority: 0,
                enabled: true,
                host_header: None,
                sni: None,
            });

        let mut origin_headers = session.req_header().headers.clone();
        for name in [
            "if-range",
            "if-none-match",
            "if-modified-since",
            "if-match",
            "if-unmodified-since",
        ] {
            origin_headers.remove(name);
        }
        if let Ok(range) = HeaderValue::from_str(&format!("bytes={remainder_start}-{end}")) {
            origin_headers.insert("range", range);
        } else {
            return false;
        }
        origin_headers.insert("accept-encoding", HeaderValue::from_static("identity"));
        // If the cached prefix has a validator, make the origin return 206 only
        // when the object is still the same. A changed object returns 200 and
        // this splice attempt falls back to the normal origin path.
        for (name, value) in &entry.meta.headers {
            if (name.eq_ignore_ascii_case("etag") || name.eq_ignore_ascii_case("last-modified"))
                && !value.is_empty()
            {
                if let Ok(value) = HeaderValue::from_str(value) {
                    origin_headers.insert("if-range", value);
                }
                break;
            }
        }
        let origin_host = target
            .host_header
            .clone()
            .or_else(|| target.sni.clone())
            .or_else(|| parse_origin(&target.url).map(|(host, _, _)| host));
        if let Some(host) = origin_host {
            if let Ok(value) = HeaderValue::from_str(&host) {
                origin_headers.insert(axum::http::header::HOST, value);
            }
        }
        origin_auth::apply(
            &mut origin_headers,
            &plan.domain.origin_auth_header,
            &plan.domain.origin_auth_value,
        );

        let idle_timeout =
            Duration::from_millis(self.state.origin_stream_read_timeout_ms.max(1_000));
        let origin = match tokio::time::timeout(
            idle_timeout,
            self.state.origin.request_stream_with_sni(
                &target.url,
                &Method::GET,
                &path_and_query,
                &origin_headers,
                None,
                true,
                target.sni.as_deref(),
            ),
        )
        .await
        {
            Ok(Ok(response)) => response,
            _ => return false,
        };
        if origin.status != StatusCode::PARTIAL_CONTENT {
            return false;
        }
        if origin.headers.get("content-encoding").is_some_and(|value| {
            value
                .to_str()
                .map(|v| !v.eq_ignore_ascii_case("identity") && !v.is_empty())
                .unwrap_or(true)
        }) {
            return false;
        }
        let Some((origin_start, origin_end, origin_total)) = origin
            .headers
            .get("content-range")
            .and_then(|value| value.to_str().ok())
            .and_then(parse_content_range)
        else {
            return false;
        };
        if origin_total != total || origin_start > remainder_start || origin_end < end {
            return false;
        }

        let Ok(mut response) =
            ResponseHeader::build(StatusCode::PARTIAL_CONTENT.as_u16(), Some(len as usize))
        else {
            return false;
        };
        for (name, value) in &entry.meta.headers {
            if name.eq_ignore_ascii_case(META_HEADER)
                || name.eq_ignore_ascii_case(VALIDATOR_SOURCE_HEADER)
                || name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("content-range")
                || name.eq_ignore_ascii_case("cache-status")
                || is_hop_by_hop(name)
                || !crate::cache::large::LargeCache::replayable_header(name)
            {
                continue;
            }
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                if response.append_header(name, value).is_err() {
                    return false;
                }
            }
        }
        if response
            .insert_header("content-range", format!("bytes {start}-{end}/{total}"))
            .is_err()
            || response
                .insert_header("content-length", len.to_string())
                .is_err()
            || response.insert_header("accept-ranges", "bytes").is_err()
            || response.insert_header("x-cache", "HIT").is_err()
            || response.insert_header("x-cache-status", "HIT").is_err()
            || response
                .insert_header("x-lagran-cache-source", "l3+origin")
                .is_err()
            || response
                .insert_header("x-lagran-cache-reason", "range-splice")
                .is_err()
        {
            return false;
        }
        let mut final_headers = response.headers.clone();
        apply_security_headers(&mut final_headers);
        apply_cors_and_custom(&mut final_headers, &plan.cors, &plan.custom);
        let _ = final_headers.insert("x-powered-by", HeaderValue::from_static("lagran-edge"));
        for (name, value) in final_headers.iter() {
            if response.insert_header(name.clone(), value.clone()).is_err() {
                return false;
            }
        }
        if entry.meta.stored_at > 0 {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let _ = response.insert_header("age", now.saturating_sub(entry.meta.stored_at).to_string());
            let _ = response.insert_header(
                "x-lagran-cache-ttl",
                entry.meta.fresh_until.saturating_sub(now).to_string(),
            );
        }
        if session
            .write_response_header(Box::new(response), false)
            .await
            .is_err()
        {
            return false;
        }

        const CHUNK: u64 = 8 * 1024 * 1024;
        let mut pos = start;
        while pos <= cached_end {
            let want = (cached_end - pos + 1).min(CHUNK) as usize;
            let Ok(Some(chunk)) = entry.read_at(pos, want).await else {
                return true;
            };
            if chunk.is_empty() {
                return true;
            }
            pos += chunk.len() as u64;
            if session
                .write_response_body(Some(chunk), false)
                .await
                .is_err()
            {
                return true;
            }
        }

        let mut body = origin.body;
        let mut remaining = end.saturating_sub(remainder_start).saturating_add(1);
        let mut skip = remainder_start.saturating_sub(origin_start);
        while remaining > 0 {
            let frame = match tokio::time::timeout(idle_timeout, body.frame()).await {
                Ok(Some(Ok(frame))) => frame,
                _ => {
                    tracing::warn!(key = %plan.key, "range splice origin body ended early");
                    return true;
                }
            };
            let Ok(data) = frame.into_data() else {
                continue;
            };
            if data.is_empty() {
                continue;
            }
            let mut data = data.as_ref();
            if skip > 0 {
                let discard = (skip as usize).min(data.len());
                data = &data[discard..];
                skip -= discard as u64;
            }
            if data.is_empty() {
                continue;
            }
            let take = (data.len() as u64).min(remaining) as usize;
            remaining -= take as u64;
            let done = remaining == 0;
            if session
                .write_response_body(Some(Bytes::copy_from_slice(&data[..take])), done)
                .await
                .is_err()
            {
                return true;
            }
            if done {
                break;
            }
        }
        true
    }

    async fn handle_management(&self, session: &mut Session, path: &str) -> Result<bool> {
        let method = session.req_header().method.clone();
        let expected = self.state.agent_token.as_str();
        let got = session
            .req_header()
            .headers
            .get("x-lagran-agent-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let allow_insecure = matches!(
            std::env::var("ALLOW_INSECURE_AGENT")
                .unwrap_or_default()
                .to_ascii_lowercase()
                .as_str(),
            "1" | "true" | "yes" | "on"
        );
        let unauthorized = if expected.is_empty() {
            !allow_insecure
        } else {
            got != expected
        };
        if unauthorized {
            write_plain(
                session,
                401,
                "text/plain; charset=utf-8",
                Bytes::from_static(b"unauthorized agent"),
            )
            .await;
            return Ok(true);
        }
        match (method.as_str(), path) {
            ("POST", "/__lagran/purge") => {
                let body = read_body(session, 1024 * 1024).await?;
                let req: purge::EdgePurgeRequest = match serde_json::from_slice(&body) {
                    Ok(req) => req,
                    Err(e) => {
                        let msg = format!("bad request: {e}");
                        write_plain(session, 400, "text/plain; charset=utf-8", Bytes::from(msg))
                            .await;
                        return Ok(true);
                    }
                };
                let Json(resp) = purge::purge_handler(State(self.state.clone()), Json(req)).await;
                write_json(session, 200, &resp).await;
            }
            ("POST", "/__lagran/prefetch") => {
                let body = read_body(session, 1024 * 1024).await?;
                let req: crate::server::prefetch::EdgePrefetchRequest =
                    match serde_json::from_slice(&body) {
                        Ok(req) => req,
                        Err(e) => {
                            let msg = format!("bad request: {e}");
                            write_plain(
                                session,
                                400,
                                "text/plain; charset=utf-8",
                                Bytes::from(msg),
                            )
                            .await;
                            return Ok(true);
                        }
                    };
                let Json(resp) =
                    crate::server::prefetch::prefetch_handler(State(self.state.clone()), Json(req))
                        .await;
                write_json(session, 200, &resp).await;
            }
            ("POST", "/__lagran/cache-diagnose") => {
                let body = read_body(session, 1024 * 1024).await?;
                let req: crate::server::cache_diag::EdgeDiagRequest =
                    match serde_json::from_slice(&body) {
                        Ok(req) => req,
                        Err(e) => {
                            let msg = format!("bad request: {e}");
                            write_plain(
                                session,
                                400,
                                "text/plain; charset=utf-8",
                                Bytes::from(msg),
                            )
                            .await;
                            return Ok(true);
                        }
                    };
                let Json(resp) =
                    crate::server::cache_diag::diag_handler(State(self.state.clone()), Json(req))
                        .await;
                write_json(session, 200, &resp).await;
            }
            ("PUT", "/__lagran/acme/challenge") => {
                let body = read_body(session, 1024 * 1024).await?;
                let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) else {
                    write_plain(
                        session,
                        400,
                        "text/plain; charset=utf-8",
                        Bytes::from_static(b"bad request"),
                    )
                    .await;
                    return Ok(true);
                };
                if let (Some(token), Some(key)) = (
                    value.get("token").and_then(|v| v.as_str()),
                    value.get("key_authorization").and_then(|v| v.as_str()),
                ) {
                    self.state.challenges.put(token, key);
                    write_plain(session, 204, "text/plain; charset=utf-8", Bytes::new()).await;
                } else {
                    write_plain(
                        session,
                        400,
                        "text/plain; charset=utf-8",
                        Bytes::from_static(b"bad request"),
                    )
                    .await;
                }
            }
            ("POST", "/__lagran/certs/load") => {
                let body = read_body(session, 16 * 1024 * 1024).await?;
                let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) else {
                    write_plain(
                        session,
                        400,
                        "text/plain; charset=utf-8",
                        Bytes::from_static(b"bad request"),
                    )
                    .await;
                    return Ok(true);
                };
                let names: Vec<String> = value
                    .get("names")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                let cert = value.get("cert_pem").and_then(|v| v.as_str()).unwrap_or("");
                let key = value.get("key_pem").and_then(|v| v.as_str()).unwrap_or("");
                match self
                    .state
                    .certs
                    .upsert(&names, cert.as_bytes(), key.as_bytes())
                {
                    Ok(()) => write_json(session, 200, &serde_json::json!({"ok": true})).await,
                    Err(e) => write_json(session, 400, &serde_json::json!({"error": e})).await,
                }
            }
            ("POST", "/__lagran/update") => {
                let body = read_body(session, 64 * 1024).await?;
                let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) else {
                    write_json(
                        session,
                        400,
                        &serde_json::json!({ "error": "invalid json" }),
                    )
                    .await;
                    return Ok(true);
                };
                let Some(version) = value.get("version").and_then(|v| v.as_str()) else {
                    write_json(
                        session,
                        400,
                        &serde_json::json!({ "error": "version is required" }),
                    )
                    .await;
                    return Ok(true);
                };
                if !valid_release_tag(version) {
                    write_json(
                        session,
                        400,
                        &serde_json::json!({ "error": "invalid release version" }),
                    )
                    .await;
                    return Ok(true);
                }
                if !edge_update_helper_installed() {
                    write_json(
                        session,
                        503,
                        &serde_json::json!({
                            "error": "edge updater is not installed; re-run install.sh edge"
                        }),
                    )
                    .await;
                    return Ok(true);
                }
                if let Err(e) = queue_edge_update(version) {
                    tracing::error!(error = %e, "queue edge update failed");
                    write_json(
                        session,
                        500,
                        &serde_json::json!({ "error": format!("cannot queue update: {e}") }),
                    )
                    .await;
                    return Ok(true);
                }
                tracing::info!(version, "edge update queued");
                write_json(
                    session,
                    202,
                    &serde_json::json!({
                        "queued": true,
                        "version": version,
                        "message": "edge updater will download, verify and restart the service"
                    }),
                )
                .await;
            }
            ("POST", "/__lagran/config/reload") => {
                crate::agent::config_sync::request_config_reload();
                write_json(
                    session,
                    200,
                    &serde_json::json!({ "ok": true, "reloading": true }),
                )
                .await;
            }
            ("GET", "/__lagran/metrics") => {
                let snaps = self.state.metrics.take_snapshots_peek().await;
                let mut body = String::from(
                    "# HELP lagran_edge_requests_total Requests handled by this edge\n\
                     # TYPE lagran_edge_requests_total counter\n\
                     # HELP lagran_edge_cache_hits_total Cache hits\n\
                     # TYPE lagran_edge_cache_hits_total counter\n\
                     # HELP lagran_edge_cache_misses_total Cache misses\n\
                     # TYPE lagran_edge_cache_misses_total counter\n\
                     # HELP lagran_edge_bytes_sent_total Bytes sent\n\
                     # TYPE lagran_edge_bytes_sent_total counter\n",
                );
                for s in snaps {
                    let d = s.domain.replace('"', "");
                    body.push_str(&format!(
                        "lagran_edge_requests_total{{domain=\"{d}\"}} {v}\n\
                         lagran_edge_cache_hits_total{{domain=\"{d}\"}} {h}\n\
                         lagran_edge_cache_misses_total{{domain=\"{d}\"}} {m}\n\
                         lagran_edge_bytes_sent_total{{domain=\"{d}\"}} {b}\n",
                        v = s.requests,
                        h = s.cache_hits,
                        m = s.cache_misses,
                        b = s.bytes_sent,
                    ));
                }
                write_plain(
                    session,
                    200,
                    "text/plain; version=0.0.4; charset=utf-8",
                    Bytes::from(body),
                )
                .await;
            }
            ("GET", "/__lagran/access-logs") => {
                let entries = self.state.access_log.snapshot(200).await;
                write_json(session, 200, &serde_json::json!({ "entries": entries })).await;
            }
            _ => {
                write_plain(
                    session,
                    404,
                    "text/plain; charset=utf-8",
                    Bytes::from_static(b"not found"),
                )
                .await;
            }
        }
        Ok(true)
    }

    async fn serve_head_cache(
        &self,
        session: &mut Session,
        plan: &NativePlan,
        ctx: &ReqCtx,
    ) -> bool {
        let entry = match self.state.cache.get_result(&plan.key).await {
            crate::cache::CacheGetResult::Hit(entry) => (entry, "HIT"),
            crate::cache::CacheGetResult::Stale(entry) => (entry, "STALE"),
            _ => return false,
        };
        let (entry, label) = entry;
        let etag = entry
            .header("etag")
            .map(str::to_string)
            .unwrap_or_else(|| compute_etag(&entry));
        let inm = session
            .req_header()
            .headers
            .get("if-none-match")
            .and_then(|v| v.to_str().ok());
        let not_modified = inm.is_some_and(|v| {
            v.split(',')
                .map(str::trim)
                .any(|candidate| candidate == etag || candidate == "*")
        });
        let status = if not_modified { 304 } else { entry.status };
        let is_h2 = session.downstream_session.is_http2();
        let len = if not_modified {
            0
        } else if is_h2 {
            entry.body.len()
        } else {
            0
        };
        let mut headers = HeaderMap::new();
        for (name, value) in &entry.headers {
            if name.eq_ignore_ascii_case(META_HEADER)
                || name.eq_ignore_ascii_case(VALIDATOR_SOURCE_HEADER)
                || name.eq_ignore_ascii_case("content-length")
                || is_hop_by_hop(name)
            {
                continue;
            }
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(name, value);
            }
        }
        headers.insert(
            HeaderName::from_static("x-cache"),
            HeaderValue::from_static(if not_modified { "REVALIDATED" } else { label }),
        );
        headers.insert(
            HeaderName::from_static("x-cache-status"),
            HeaderValue::from_static(if not_modified { "REVALIDATED" } else { label }),
        );
        headers.insert(
            HeaderName::from_static("age"),
            HeaderValue::from_str(&entry.age_secs().to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("0")),
        );
        headers.insert(
            HeaderName::from_static("x-powered-by"),
            HeaderValue::from_static("lagran-edge"),
        );
        if let Ok(value) = HeaderValue::from_str(&etag) {
            headers.insert(HeaderName::from_static("etag"), value);
        }
        apply_browser_ttl(&mut headers, policy_browser_ttl(&plan.policy));
        apply_security_headers(&mut headers);
        apply_cors_and_custom(&mut headers, &plan.cors, &plan.custom);
        headers.insert(
            HeaderName::from_static("content-length"),
            HeaderValue::from_str(&len.to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("0")),
        );

        let Ok(mut response) = ResponseHeader::build(status, Some(0)) else {
            return false;
        };
        for (name, value) in headers.iter() {
            if response.append_header(name.clone(), value.clone()).is_err() {
                return false;
            }
        }
        let _ = response.remove_header("content-length");
        let _ = response.insert_header("content-length", len.to_string());
        if session
            .write_response_header(Box::new(response), true)
            .await
            .is_err()
        {
            return false;
        }
        let cache_label = if not_modified { "REVALIDATED" } else { label };
        log_access(
            &self.state.access_log,
            &ctx.method,
            &ctx.host,
            &ctx.path,
            status,
            ctx.start,
            &ctx.client_ip,
            &ctx.user_agent,
            &ctx.referer,
            0,
            cache_label,
            &ctx.request_id,
        )
        .await;
        if cache_label == "HIT" {
            self.state.metrics.record_hit(&ctx.host, 0).await;
        } else {
            self.state.metrics.record_miss(&ctx.host, 0).await;
        }
        true
    }

    fn advance_origin(ctx: &mut ReqCtx) -> bool {
        if ctx.attempt + 1 >= ctx.origin_order.len() {
            return false;
        }
        ctx.attempt += 1;
        ctx.current_addresses.clear();
        ctx.current_address_index = 0;
        true
    }

    fn advance_peer(ctx: &mut ReqCtx) -> bool {
        if ctx.current_address_index + 1 < ctx.current_addresses.len() {
            ctx.current_address_index += 1;
            return true;
        }
        Self::advance_origin(ctx)
    }

    async fn origin_order(&self, domain: &str, plan: &NativePlan) -> Vec<OriginTarget> {
        let mut pool: Vec<OriginTarget> = if plan.origins.is_empty() {
            let mut list = vec![OriginTarget {
                url: plan.domain.origin_url.clone(),
                weight: 100,
                priority: 0,
                enabled: true,
                host_header: None,
                sni: None,
            }];
            if !plan.backup_url.is_empty() {
                list.push(OriginTarget {
                    url: plan.backup_url.clone(),
                    weight: 100,
                    priority: 1,
                    enabled: true,
                    host_header: None,
                    sni: None,
                });
            }
            list
        } else {
            plan.origins.clone()
        };
        pool.retain(|o| o.enabled);
        if pool.is_empty() {
            return Vec::new();
        }

        let mut healthy = Vec::with_capacity(pool.len());
        for origin in &pool {
            if self
                .state
                .origin_health
                .is_origin_healthy(domain, &origin.url)
                .await
            {
                healthy.push(origin.clone());
            }
        }
        let mut candidates = if healthy.is_empty() {
            tracing::warn!(
                domain,
                "all origins unhealthy; trying best available origin"
            );
            pool
        } else {
            healthy
        };
        let min_priority = candidates
            .iter()
            .map(|o| o.priority)
            .min()
            .unwrap_or_default();
        candidates.retain(|o| o.priority == min_priority);
        if candidates.is_empty() {
            return Vec::new();
        }

        let seed = self
            .origin_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        OriginTarget::weighted_order(candidates, seed)
    }

    async fn peer_for(
        &self,
        addr: SocketAddr,
        host: &str,
        tls: bool,
        connect_timeout_ms: u64,
        read_timeout_ms: u64,
        sni: Option<&str>,
    ) -> Result<Box<HttpPeer>> {
        // Pass a resolved address to avoid Pingora's panicking DNS path.
        let server_name = sni.filter(|s| !s.is_empty()).unwrap_or(host);
        let mut peer = HttpPeer::new(addr, tls, server_name.to_string());
        peer.options.connection_timeout = Some(Duration::from_millis(connect_timeout_ms));
        peer.options.read_timeout = Some(Duration::from_millis(read_timeout_ms));
        Ok(Box::new(peer))
    }

    async fn handle_in_process(&self, session: &mut Session) -> Result<bool> {
        let req_header = session.req_header();
        let method: Method = req_header.method.clone();
        let is_head = method == Method::HEAD;
        let uri: Uri = req_header.uri.clone();
        let version = req_header.version;
        let headers = req_header.headers.clone();

        let mut body = BytesMut::new();
        while let Some(chunk) = session.read_request_body().await? {
            if body.len() + chunk.len() > MAX_PROXY_BODY {
                session
                    .respond_error_with_body(
                        StatusCode::PAYLOAD_TOO_LARGE.as_u16(),
                        Bytes::from_static(b"request body too large"),
                    )
                    .await?;
                return Ok(true);
            }
            body.extend_from_slice(&chunk);
        }

        let mut builder = Request::builder().method(method).uri(uri).version(version);
        for (name, value) in headers.iter() {
            builder = builder.header(name.clone(), value.clone());
        }
        let mut axum_req = match builder.body(Body::from(body.freeze())) {
            Ok(req) => req,
            Err(e) => {
                tracing::warn!(error = %e, "build internal request failed");
                session
                    .respond_error_with_body(500, Bytes::from_static(b"internal request error"))
                    .await?;
                return Ok(true);
            }
        };
        if let Some(peer) = session.client_addr().and_then(|a| a.as_inet()).copied() {
            axum_req.extensions_mut().insert(ConnectInfo(peer));
        }
        // The legacy handler cannot see this session, so forward the fact that
        // the downstream connection was TLS. Without it the HTTPS redirect
        // fires for requests that already arrived over HTTPS (HEAD, no-cache
        // revalidation and other in-process fallbacks).
        let downstream_tls = session
            .digest()
            .is_some_and(|digest| digest.ssl_digest.is_some());
        if downstream_tls {
            axum_req
                .extensions_mut()
                .insert(crate::server::host_util::TlsTerminated);
        }

        let resp = proxy_handler(State(self.state.clone()), axum_req).await;
        write_axum_response(session, resp, is_head).await;
        Ok(true)
    }
}

pub(crate) fn edge_update_helper_installed() -> bool {
    if let Ok(helper) = std::env::var("EDGE_UPDATE_HELPER") {
        if !helper.trim().is_empty() {
            return std::path::Path::new(helper.trim()).is_file();
        }
    }
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("lagran-edge-update")))
        .is_some_and(|path| path.is_file())
}

pub(crate) fn valid_release_tag(raw: &str) -> bool {
    let tag = raw.trim();
    let Some(rest) = tag.strip_prefix('v') else {
        return false;
    };
    if rest.is_empty() || rest.len() > 64 {
        return false;
    }
    if !rest
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '+')
    {
        return false;
    }
    let core = match rest.split(['+', '-']).next() {
        Some(core) => core,
        None => return false,
    };
    let mut parts = core.split('.');
    let (Some(major), Some(minor), Some(patch)) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    parts.next().is_none()
        && [major, minor, patch]
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

pub(crate) fn queue_edge_update(version: &str) -> std::io::Result<()> {
    let path = match std::env::var("EDGE_UPDATE_REQUEST_PATH") {
        Ok(value) if !value.trim().is_empty() => std::path::PathBuf::from(value.trim()),
        _ => std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .join("edge-update.request"),
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp, format!("{version}\n"))?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

async fn read_body(session: &mut Session, limit: usize) -> Result<Bytes> {
    let mut out = BytesMut::new();
    while let Some(chunk) = session.read_request_body().await? {
        if out.len() + chunk.len() > limit {
            return Err(pingora::Error::new_str("request body too large"));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out.freeze())
}

async fn write_json<T: serde::Serialize>(session: &mut Session, status: u16, value: &T) {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    write_plain(session, status, "application/json", Bytes::from(body)).await;
}

async fn write_plain(session: &mut Session, status: u16, content_type: &str, body: Bytes) {
    let Ok(mut response) = ResponseHeader::build(status, Some(body.len())) else {
        return;
    };
    let _ = response.insert_header("content-type", content_type);
    let _ = response.insert_header("content-length", body.len().to_string());
    let _ = session
        .write_response_header(Box::new(response), body.is_empty())
        .await;
    if !body.is_empty() {
        let _ = session.write_response_body(Some(body), true).await;
    }
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = &input[i + 1..i + 3];
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v as char);
                    i += 3;
                    continue;
                }
                out.push('%');
                i += 1;
            }
            b'+' => {
                out.push(' ');
                i += 1;
            }
            b => {
                out.push(b as char);
                i += 1;
            }
        }
    }
    out
}

fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (percent_decode(k) == name).then(|| percent_decode(v))
    })
}

fn head_content_length_for_protocol(is_h2: bool, body_len: usize) -> String {
    if is_h2 {
        body_len.to_string()
    } else {
        "0".to_string()
    }
}

async fn write_axum_response(session: &mut Session, resp: axum::response::Response, is_head: bool) {
    let is_h2 = session.downstream_session.is_http2();
    let (mut parts, body) = resp.into_parts();
    if !parts.headers.contains_key("x-lagran-datapath") {
        parts.headers.insert(
            HeaderName::from_static("x-lagran-datapath"),
            HeaderValue::from_static("pingora"),
        );
    }
    let bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            tracing::warn!(error = %e, "collect engine response failed");
            let _ = session
                .respond_error_with_body(502, Bytes::from_static(b"engine response error"))
                .await;
            return;
        }
    };
    let body_len = bytes.len();
    let no_content = parts.status == StatusCode::NOT_MODIFIED
        || parts.status == StatusCode::NO_CONTENT;
    let head_content_length = if is_head {
        // HTTP/2 frames HEAD with END_STREAM and can safely carry the real
        // representation length. Pingora's H1 encoder cannot reliably do so
        // without waiting for a body, so H1 keeps the 0 workaround.
        head_content_length_for_protocol(is_h2, body_len)
    } else {
        "0".to_string()
    };
    let bytes = if is_head { Bytes::new() } else { bytes };
    let end_of_stream = bytes.is_empty();
    let initial_len = if is_head || no_content {
        None
    } else {
        Some(bytes.len())
    };
    let Ok(mut response) = ResponseHeader::build(parts.status.as_u16(), initial_len) else {
        return;
    };
    for (name, value) in parts.headers.iter() {
        if is_hop_by_hop(name.as_str()) || name == axum::http::header::CONTENT_LENGTH {
            continue;
        }
        if response.append_header(name.clone(), value.clone()).is_err() {
            return;
        }
    }
    if is_head {
        if response
            .insert_header("content-length", head_content_length.as_str())
            .is_err()
        {
            return;
        }
    } else if end_of_stream {
        // A 304/204 has no payload. Sending `Content-Length: 0` is misleading
        // (RFC 9110 allows Content-Length on 304 only when it equals the 200
        // representation length), so omit it entirely.
        if !no_content && response.insert_header("content-length", "0").is_err() {
            return;
        }
    } else if response
        .insert_header("content-length", body_len.to_string())
        .is_err()
    {
        return;
    }
    let _ = session
        .write_response_header(Box::new(response), end_of_stream)
        .await;
    if !end_of_stream {
        let _ = session.write_response_body(Some(bytes), true).await;
    }
}

fn parse_content_range(raw: &str) -> Option<(u64, u64, u64)> {
    let rest = raw.trim().strip_prefix("bytes ")?;
    let (range, total) = rest.split_once('/')?;
    if total.trim() == "*" {
        return None;
    }
    let total: u64 = total.trim().parse().ok()?;
    let (start, end) = range.trim().split_once('-')?;
    let start: u64 = start.trim().parse().ok()?;
    let end: u64 = end.trim().parse().ok()?;
    (start <= end && end < total).then_some((start, end, total))
}

/// Whether a single Range request is worth attempting to fill. The actual
/// cached window is chosen later from the origin `Content-Range`, because an
/// open-ended `bytes=start-` does not reveal the object size at request time.
fn range_fill_is_candidate(raw: &str, max_fill_bytes: u64) -> bool {
    if max_fill_bytes == 0 {
        return false;
    }
    let Some(value) = raw.trim().strip_prefix("bytes=") else {
        return false;
    };
    if value.contains(',') {
        return false;
    }
    let Some((start, end)) = value.split_once('-') else {
        return false;
    };
    let (start, end) = (start.trim(), end.trim());
    if start.is_empty() && end.is_empty() {
        return false;
    }
    if !start.is_empty() && start.parse::<u64>().is_err() {
        return false;
    }
    if !end.is_empty() && end.parse::<u64>().is_err() {
        return false;
    }
    true
}

/// Select the cacheable byte window for a Range response.
///
/// - bounded ranges: only when the requested span is <= max_fill_bytes
/// - open-ended `bytes=start-`: cache up to max_fill_bytes from start
/// - suffix `bytes=-N`: cache the last min(N, max_fill_bytes) bytes
///
/// The returned window must be covered by the origin `Content-Range` already
/// received. Leaving a Range uncached is always allowed.
fn fill_window(
    raw: &str,
    origin_start: u64,
    origin_end: u64,
    total: u64,
    max_fill_bytes: u64,
) -> Option<(u64, u64)> {
    if max_fill_bytes == 0 || total == 0 || origin_start > origin_end || origin_end >= total {
        return None;
    }
    let value = raw.trim().strip_prefix("bytes=")?;
    if value.contains(',') {
        return None;
    }
    let (start, end) = value.split_once('-')?;
    let (start, end) = (start.trim(), end.trim());

    let (fill_start, fill_end) = if start.is_empty() {
        let suffix = end.parse::<u64>().ok()?;
        if suffix == 0 {
            return None;
        }
        if suffix >= total {
            (0, total - 1)
        } else {
            (total - suffix, total - 1)
        }
    } else {
        let start = start.parse::<u64>().ok()?;
        if start >= total {
            return None;
        }
        let requested_end = if end.is_empty() {
            total - 1
        } else {
            end.parse::<u64>().ok()?.min(total - 1)
        };
        if requested_end < start {
            return None;
        }
        (start, requested_end)
    };

    let requested_len = fill_end.saturating_sub(fill_start).saturating_add(1);
    let (fill_start, fill_end) = if requested_len <= max_fill_bytes {
        (fill_start, fill_end)
    } else if start.is_empty() {
        // A huge suffix request is effectively "the whole object"; cache its
        // tail rather than the entire file.
        (total.saturating_sub(max_fill_bytes), total - 1)
    } else if end.is_empty() {
        // Open-ended video/audio: cache a bounded prefix. The client still
        // receives the complete stream from origin.
        (
            fill_start,
            fill_start
                .saturating_add(max_fill_bytes)
                .saturating_sub(1)
                .min(total - 1),
        )
    } else {
        // A large bounded Range is left uncached to avoid a huge one-shot fill.
        return None;
    };

    if fill_start < origin_start || fill_end > origin_end || fill_end < fill_start {
        return None;
    }
    Some((fill_start, fill_end))
}

fn parse_single_range(raw: &str, total: u64) -> Option<(u64, u64)> {
    if total == 0 {
        return None;
    }
    let value = raw.trim().strip_prefix("bytes=")?;
    if value.contains(',') {
        return None;
    }
    let (start, end) = value.split_once('-')?;
    let (start, end) = (start.trim(), end.trim());
    let (start, end) = if start.is_empty() {
        let suffix: u64 = end.parse().ok()?;
        if suffix == 0 {
            return None;
        }
        (total.saturating_sub(suffix), total - 1)
    } else {
        let start: u64 = start.parse().ok()?;
        let end = if end.is_empty() {
            total - 1
        } else {
            end.parse::<u64>().ok()?.min(total - 1)
        };
        (start, end)
    };
    (start <= end && start < total).then_some((start, end))
}

fn range_is_small_bounded(headers: &HeaderMap) -> bool {
    const MAX_SLICE: u64 = 1024 * 1024;
    let Some(raw) = headers.get("range").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(value) = raw.trim().strip_prefix("bytes=") else {
        return false;
    };
    if value.contains(',') {
        return false;
    }
    let Some((start, end)) = value.split_once('-') else {
        return false;
    };
    let (Ok(start), Ok(end)) = (start.trim().parse::<u64>(), end.trim().parse::<u64>()) else {
        return false;
    };
    end >= start && end - start < MAX_SLICE
}

/// Resolve the request host for registry lookups.
///
/// Delegates to [`crate::config::registry::normalize_host`] so the Pingora path,
/// the in-process handler and the registry itself cannot disagree. The previous
/// local implementation split on `:` and kept the brackets on IPv6 literals,
/// which produced a different key than the one the registry was populated with.
fn request_host(raw: Option<&str>) -> String {
    raw.map(crate::config::registry::normalize_host)
        .unwrap_or_default()
}

fn parse_origin(url: &str) -> Option<(String, u16, bool)> {
    let uri: Uri = url.parse().ok()?;
    let scheme = uri.scheme_str()?;
    let tls = scheme.eq_ignore_ascii_case("https");
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let host = uri.host()?.to_string();
    let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
    // Reject origin base paths; they are still served by the legacy engine.
    let path = uri.path();
    if !path.is_empty() && path != "/" {
        return None;
    }
    Some((host, port, tls))
}

fn header_vec(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_string(), v.to_string()))
        })
        .collect()
}

/// Resolve the connect timeout for one domain.
///
/// `domain_override_ms` is the operator's per-domain setting; 0 means "inherit
/// the edge-wide default". This is the only place the two settings meet, so the
/// precedence is identical for every origin of a request.
pub(crate) fn effective_connect_timeout_ms(domain_override_ms: u32, global_ms: u64) -> u64 {
    if domain_override_ms > 0 {
        u64::from(domain_override_ms)
    } else {
        global_ms
    }
}

/// Add `Accept-Encoding` to `Vary` without discarding existing values.
fn vary_on_accept_encoding(response: &mut ResponseHeader) -> Result<()> {
    let already_present = response
        .headers
        .get_all(header::VARY)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| {
            value
                .split(',')
                .any(|field| field.trim().eq_ignore_ascii_case("accept-encoding"))
        });
    if already_present {
        return Ok(());
    }
    let existing = response
        .headers
        .get_all(header::VARY)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let value = if existing.is_empty() {
        "Accept-Encoding".to_string()
    } else {
        format!("{existing}, Accept-Encoding")
    };
    response.insert_header(header::VARY, value)?;
    Ok(())
}

/// A compressed representation is different representation data, so a strong
/// validator must not be reused verbatim. `If-None-Match` uses weak comparison
/// (RFC 9110 §13.1.2), so `W/` keeps 304 revalidation working.
fn weaken_etag(response: &mut ResponseHeader) -> Result<()> {
    let Some(etag) = response
        .headers
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
    else {
        return Ok(());
    };
    if etag.trim_start().starts_with("W/") {
        return Ok(());
    }
    if let Ok(value) = HeaderValue::from_str(&format!("W/{etag}")) {
        response.insert_header(header::ETAG, value)?;
    }
    Ok(())
}

fn cache_label(phase: CachePhase) -> &'static str {
    match phase {
        CachePhase::Hit => "HIT",
        CachePhase::Miss => "MISS",
        CachePhase::Stale | CachePhase::StaleUpdating => "STALE",
        CachePhase::Revalidated => "REVALIDATED",
        CachePhase::Bypass => "BYPASS",
        _ => "MISS",
    }
}

fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    let upgrade = headers
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    let connection_upgrade = headers
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("upgrade"))
        .unwrap_or(false);
    upgrade || connection_upgrade
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Rewrite the forwarding headers before the request reaches cache/WAF/origin.
///
/// The client IP and scheme are decided by
/// [`crate::security::trusted_proxy::resolve`], the same function the in-process
/// handler uses. Previously this compared only "trust on/off": with trust
/// enabled, a direct client could send `X-Forwarded-For: 1.2.3.4` and
/// `X-Forwarded-Proto: https` and be believed, which defeated WAF IP deny lists,
/// CC bans and the HTTPS redirect at once.
fn prepare_proxy_headers(
    session: &mut Session,
    trust_proxy: bool,
    trusted: &crate::security::trusted_proxy::TrustedProxies,
) -> Result<()> {
    let peer = session.client_addr().and_then(|addr| addr.as_inet());
    let is_https = session
        .digest()
        .and_then(|d| d.ssl_digest.as_ref())
        .is_some();
    let sni = session
        .digest()
        .and_then(|d| d.ssl_digest.as_ref())
        .and_then(|d| d.extension.get::<Sni>())
        .map(|s| s.0.clone());

    let req = session.req_header();
    let xff = req
        .headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok());
    let xfp = req
        .headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok());

    // `trust_proxy_headers` is the legacy switch. When true but no CIDR list is
    // configured, trust the immediate peer: that is only sane for the loopback
    // hop, and it is what the header names always meant.
    let effective_trusted;
    let trusted = if trust_proxy && trusted.is_empty() {
        effective_trusted = peer
            .map(|addr| {
                crate::security::trusted_proxy::TrustedProxies::parse(&addr.ip().to_string())
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        &effective_trusted
    } else if trust_proxy {
        trusted
    } else {
        // Trust disabled: nothing is trusted, so forwarded headers are ignored.
        effective_trusted = crate::security::trusted_proxy::TrustedProxies::default();
        &effective_trusted
    };

    let identity =
        crate::security::trusted_proxy::resolve(trusted, peer.copied(), xff, xfp, is_https);

    let client_ip = identity
        .ip
        .map(|ip| ip.to_string())
        .unwrap_or_default();
    let req = session.req_header_mut();

    // Always restate X-Forwarded-For with the resolved client address. Dropping
    // the untrusted prefix means origin logs and any downstream trust decision
    // see a value this edge vouches for.
    req.remove_header("x-forwarded-for");
    if !client_ip.is_empty() {
        req.insert_header("x-forwarded-for", client_ip.as_str())?;
    }
    req.remove_header("x-real-ip");
    if !client_ip.is_empty() {
        req.insert_header("x-real-ip", client_ip.as_str())?;
    }
    // Same for the scheme: only a trusted hop may override what we observed.
    req.remove_header("x-forwarded-proto");
    req.insert_header(
        "x-forwarded-proto",
        if identity.is_https { "https" } else { "http" },
    )?;

    if !req.headers.contains_key("host") {
        if let Some(sni) = sni {
            req.insert_header("host", sni.as_str())?;
        }
    }
    req.insert_header("x-lagran-pingora", "1")?;
    Ok(())
}

/// Run the Pingora public listener. `upstream` is the loopback fallback router.
pub fn run(config: EdgeConfig, certs: Arc<CertStore>, state: Arc<AppState>) -> anyhow::Result<()> {
    // `serve` is our subcommand; Pingora's own clap parser must not see it.
    let opt = if std::env::args().nth(1).as_deref() == Some("serve") {
        pingora::server::configuration::Opt {
            upgrade: false,
            daemon: false,
            nocapture: false,
            test: false,
            conf: None,
        }
    } else {
        pingora::server::configuration::Opt::parse_args()
    };
    // Pingora's own default is a single worker thread. With one thread, every
    // downstream TLS handshake, WAF scan and upstream TLS handshake runs on the
    // same core, so origin fetches queue behind each other. Size the service
    // runtime from configuration (default: available CPUs).
    let mut conf = pingora::server::configuration::ServerConf::new()
        .ok_or_else(|| anyhow::anyhow!("cannot load default Pingora configuration"))?;
    conf.threads = config.worker_threads.max(1);
    tracing::info!(
        threads = conf.threads,
        listener_tasks_per_fd = conf.listener_tasks_per_fd,
        "Pingora data plane runtime"
    );
    let mut server = Server::new_with_opt_and_conf(Some(opt), conf);
    server.bootstrap();

    let storage = Some(leak_storage_with_large(
        state.cache.clone(),
        state.max_cacheable_body,
        state.large_cache.clone(),
    ));
    let cache_lock_secs = if state.large_cache.is_some() { 300 } else { 10 };
    let cache_lock: &'static CacheLock =
        Box::leak(CacheLock::new_boxed(Duration::from_secs(cache_lock_secs)));
    let proxy = DataPlaneProxy {
        trust_proxy: config.trust_proxy_headers,
        trusted_proxies: config.trusted_proxies.clone(),
        state,
        native_cache: storage.is_some(),
        storage,
        cache_lock,
        management_on_data: config.admin_listen_addr.is_none(),
        origin_counter: std::sync::atomic::AtomicU64::new(0),
        dns_cache: OriginDnsCache::new(),
        compression: CompressionConfig {
            enabled: config.compression_enabled,
            min_bytes: config.compression_min_bytes,
            level: config.compression_level,
        },
    };
    match std::net::TcpListener::bind(&config.listen_addr) {
        Ok(probe) => drop(probe),
        Err(e) => anyhow::bail!("cannot bind EDGE_LISTEN {}: {e}", config.listen_addr),
    }
    let mut downstream_options = HttpServerOptions::default();
    downstream_options.keepalive_request_limit =
        Some(config.downstream_keepalive_requests);
    downstream_options.h2_idle_timeout =
        Some(Duration::from_secs(config.downstream_h2_idle_secs));
    let mut service = ProxyServiceBuilder::new(&server.configuration, proxy)
        .server_options(downstream_options)
        .build();
    service.add_tcp(&config.listen_addr);

    if let Some(ref https) = config.https_listen_addr {
        match std::net::TcpListener::bind(https) {
            Ok(probe) => drop(probe),
            Err(e) => {
                tracing::error!(listen = %https, error = %e, "HTTPS listener unavailable; continuing with HTTP only");
                tracing::info!(listen = %config.listen_addr, "Pingora HTTP listener");
                server.add_service(service);
                server.run_forever();
            }
        }
        let mut tls = TlsSettings::with_callbacks(
            Box::new(CertCallback { store: certs }) as TlsAcceptCallbacks
        )?;
        tls.enable_h2();
        service.add_tls_with_settings(https, None, tls);
        tracing::info!(listen = %https, "Pingora HTTPS listener");
    }
    tracing::info!(listen = %config.listen_addr, "Pingora HTTP listener");

    server.add_service(service);
    server.run_forever();
}

#[cfg(test)]
mod tests {
    use super::{
        effective_connect_timeout_ms, fill_window, head_content_length_for_protocol,
        parse_single_range, range_fill_is_candidate, valid_release_tag,
        vary_on_accept_encoding, weaken_etag,
    };
    use pingora::http::ResponseHeader;

    fn header_values(response: &ResponseHeader, name: &str) -> Vec<String> {
        response
            .headers
            .get_all(name)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn vary_appends_accept_encoding_without_dropping_existing_values() {
        let mut response = ResponseHeader::build(200, None).unwrap();
        response.insert_header("vary", "Origin").unwrap();
        vary_on_accept_encoding(&mut response).unwrap();
        assert_eq!(
            header_values(&response, "vary").join(", "),
            "Origin, Accept-Encoding"
        );

        // Idempotent: a second pass must not duplicate the field.
        vary_on_accept_encoding(&mut response).unwrap();
        assert_eq!(
            header_values(&response, "vary").join(", "),
            "Origin, Accept-Encoding"
        );

        let mut bare = ResponseHeader::build(200, None).unwrap();
        vary_on_accept_encoding(&mut bare).unwrap();
        assert_eq!(header_values(&bare, "vary").join(", "), "Accept-Encoding");
    }

    #[test]
    fn etag_is_weakened_once() {
        let mut response = ResponseHeader::build(200, None).unwrap();
        response.insert_header("etag", "\"abc\"").unwrap();
        weaken_etag(&mut response).unwrap();
        assert_eq!(header_values(&response, "etag"), vec!["W/\"abc\""]);

        // Already weak: leave it untouched.
        weaken_etag(&mut response).unwrap();
        assert_eq!(header_values(&response, "etag"), vec!["W/\"abc\""]);

        // No ETag: no header is synthesised.
        let mut none = ResponseHeader::build(200, None).unwrap();
        weaken_etag(&mut none).unwrap();
        assert!(header_values(&none, "etag").is_empty());
    }

    /// A per-domain value of 0 must inherit the cluster default; any positive
    /// value overrides it. This is the whole precedence rule between the two
    /// settings, so it is worth pinning down.
    #[test]
    fn domain_connect_timeout_zero_inherits_global() {
        assert_eq!(effective_connect_timeout_ms(0, 3_000), 3_000);
        assert_eq!(effective_connect_timeout_ms(800, 3_000), 800);
        assert_eq!(effective_connect_timeout_ms(15_000, 3_000), 15_000);
        // A global of 0 is "unset" from configuration's point of view; the edge
        // clamps it to >= 500 before it ever reaches here.
        assert_eq!(effective_connect_timeout_ms(0, 500), 500);
    }

    #[test]
    fn address_failure_retries_same_origin_before_failing_over() {
        let mut ctx = super::ReqCtx::default();
        ctx.origin_order = vec!["https://one.example".into(), "https://two.example".into()];
        ctx.current_addresses = vec![
            "192.0.2.1:443".parse().unwrap(),
            "192.0.2.2:443".parse().unwrap(),
        ];

        assert!(super::DataPlaneProxy::advance_peer(&mut ctx));
        assert_eq!(ctx.attempt, 0);
        assert_eq!(ctx.current_address_index, 1);

        assert!(super::DataPlaneProxy::advance_peer(&mut ctx));
        assert_eq!(ctx.attempt, 1);
        assert!(ctx.current_addresses.is_empty());
        assert_eq!(ctx.current_address_index, 0);

        assert!(!super::DataPlaneProxy::advance_peer(&mut ctx));
    }

    #[test]
    fn release_tag_validation() {
        assert!(valid_release_tag("v1.2.3"));
        assert!(valid_release_tag("v1.2.3-rc.1"));
        assert!(!valid_release_tag("1.2.3"));
        assert!(!valid_release_tag("v1.2"));
        assert!(!valid_release_tag("v1.2.3; reboot"));
        assert!(!valid_release_tag("latest"));
    }

    #[test]
    fn head_length_is_http2_only() {
        assert_eq!(head_content_length_for_protocol(true, 1234), "1234");
        assert_eq!(head_content_length_for_protocol(false, 1234), "0");
        assert_eq!(head_content_length_for_protocol(true, 0), "0");
    }

    #[test]
    fn range_fill_candidates_include_open_ended_and_suffix() {
        let max = 32 * 1024 * 1024;
        assert!(range_fill_is_candidate("bytes=0-1023", max));
        assert!(range_fill_is_candidate("bytes=0-1048575", max));
        assert!(range_fill_is_candidate("bytes=0-", max));
        assert!(range_fill_is_candidate("bytes=-512", max));
        assert!(!range_fill_is_candidate("bytes=0-1,4-5", max));
        assert!(!range_fill_is_candidate("bytes=-", max));
        assert!(!range_fill_is_candidate("bytes=0-1023", 0));
    }

    #[test]
    fn fill_window_caps_open_ended_video_and_suffix() {
        let max = 32 * 1024 * 1024;
        let total = 100 * 1024 * 1024;
        assert_eq!(
            fill_window("bytes=0-", 0, total - 1, total, max),
            Some((0, max - 1))
        );
        assert_eq!(
            fill_window("bytes=10-", 0, total - 1, total, max),
            Some((10, 10 + max - 1))
        );
        assert_eq!(
            fill_window("bytes=-512", total - 512, total - 1, total, max),
            Some((total - 512, total - 1))
        );
        assert_eq!(
            fill_window(&format!("bytes=-{total}"), 0, total - 1, total, max),
            Some((total - max, total - 1))
        );
        assert_eq!(
            fill_window("bytes=0-1048575", 0, 1048575, total, max),
            Some((0, 1048575))
        );
        assert_eq!(
            fill_window("bytes=0-33554432", 0, 33554432, total, max),
            None
        );
        assert_eq!(
            fill_window("bytes=0-", 0, max - 2, total, max),
            None
        );
    }

    #[test]
    fn single_byte_ranges_for_large_cache() {
        assert_eq!(parse_single_range("bytes=0-1023", 4096), Some((0, 1023)));
        assert_eq!(parse_single_range("bytes=1000-", 4096), Some((1000, 4095)));
        assert_eq!(parse_single_range("bytes=-512", 4096), Some((3584, 4095)));
        assert_eq!(parse_single_range("bytes=0-999999", 4096), Some((0, 4095)));
        assert_eq!(parse_single_range("bytes=0-1,4-5", 4096), None);
        assert_eq!(parse_single_range("bytes=5000-", 4096), None);
        assert_eq!(parse_single_range("bytes=-0", 4096), None);
        assert_eq!(parse_single_range("items=0-1", 4096), None);
    }
}
