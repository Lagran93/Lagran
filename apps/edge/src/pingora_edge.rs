//! Pingora public listener + native data plane.
//!
//! Pingora owns public HTTP/HTTPS, HTTP/1.1+HTTP/2, TLS and connection
//! management. Cacheable GET/HEAD requests use `pingora-cache` with the
//! existing `SharedCache` as storage and `upstream_peer` for direct origin
//! access. Requests that need the legacy engine (WAF/CC/rate-limit/hotlink,
//! bypass/dynamic traffic, disk/hybrid cache, control endpoints and
//! WebSocket) are handed to the in-process handler.

use crate::cache::large::{ChunkPlan, FillBudget, LargeEntry, RangeWriter};
use crate::cache::policy::{
    ResolvedPolicy, RuleAction, VALIDATOR_SOURCE_HEADER, apply_key_ignore_default, compute_etag,
    decide_storage_reason, decide_storage_reason_map, request_bypass_reason_headers,
    resolve_rule_policy_for_response,
};
use crate::cache::{CacheBackend, CacheSource};
use crate::config::EdgeConfig;
use crate::config::registry::{DomainEntry, OriginTarget};
use crate::metrics::LegacyFallback;
use crate::origin_dns::OriginDnsCache;
use crate::security::header_guard;
use crate::security::origin_auth;
use crate::security::signed_url;
use crate::server::cert_store::CertStore;
use crate::server::challenge;
use crate::server::compression::{CompressionConfig, GzipEncoder, replay_chunk, should_compress};
use crate::server::default_page::{self, OriginFailure};
use crate::server::handler::{AppState, proxy_handler};
use crate::server::shared::{
    apply_browser_ttl, apply_cors_and_custom, apply_security_headers, hotlink_allowed, log_access,
    policy_browser_ttl,
};
use crate::server::host_util::normalized_authority_host;
use crate::server::native_cache::{META_HEADER, NativeStorage, leak_storage_with_large};
use crate::server::pipeline::{RequestFacts, RequestPipeline};
use crate::server::purge;
use async_trait::async_trait;
use axum::Json;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri, Version, header,
};
use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt;
use pingora::Result;
use pingora::apps::HttpServerOptions;
use pingora::http::ResponseHeader;
use pingora::listeners::tls::TlsSettings;
use pingora::listeners::{TlsAccept, TlsAcceptCallbacks};
use pingora::protocols::tls::TlsRef;
use pingora::proxy::{FailToProxy, ProxyHttp, ProxyServiceBuilder, Session};
use pingora::server::Server;
use pingora::tls::{ext, ssl};
use pingora::upstreams::peer::HttpPeer;
use pingora_cache::lock::CacheLock;
use pingora_cache::{
    CacheKey, CacheMeta, CacheOptionOverrides, CachePhase, ForcedFreshness, NoCacheReason,
    RespCacheable,
};

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

const MAX_PROXY_BODY: usize = 16 * 1024 * 1024;
/// Bound the number of sequential origin requests for one client request.
/// A pathologically fragmented cache would otherwise produce one connection
/// per chunk; above this the initial range path is used instead.
const MAX_CHUNK_ORIGIN_RUNS: usize = 16;
/// Bound multipart Range parts so one request cannot create unbounded origin
/// work or response overhead.
const MAX_MULTI_RANGES: usize = 16;

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
        let Some((cert, key, chain)) = self.store.certificate_for(&name) else {
            tracing::warn!(sni = %name, "no certificate for TLS SNI");
            return;
        };
        if let Err(e) = ext::ssl_use_certificate(ssl, &cert) {
            tracing::error!(sni = %name, error = %e, "install certificate failed");
            return;
        }
        // Without the intermediate(s) in the handshake, clients that do not
        // already have them cached reject the leaf ("unable to verify the first
        // certificate"). The store keeps the full PEM, so install the rest of
        // the chain alongside the leaf.
        for intermediate in &chain {
            if let Err(e) = ext::ssl_add_chain_cert(ssl, intermediate) {
                tracing::error!(sni = %name, error = %e, "install chain certificate failed");
            }
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
    /// TCP connect timeout. Kept separate so an unreachable origin fails over
    /// quickly instead of consuming the response budget.
    connect_timeout_ms: u64,
    read_timeout_ms: u64,
    cache_reason: Option<&'static str>,
    policy: ResolvedPolicy,
    cacheable: bool,
    is_head: bool,
    is_websocket: bool,
    label: &'static str,
}

struct RangeFill {
    key: String,
    raw_range: String,
}

#[derive(Clone)]
struct ResponsePolicySlot {
    content_type: Option<HeaderValue>,
    policy: ResolvedPolicy,
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
    budget: std::sync::Arc<FillBudget>,
    metrics: std::sync::Arc<crate::metrics::EdgeMetrics>,
    queue_limit: u64,
}

/// Fill sink for a manual cache+origin chunk response.
///
/// The origin stream starts at the span start, so unlike [`RangeSink`] there is
/// no `skip`; bytes before `end` are written to the background RangeWriter and
/// bytes after `end` are only forwarded to the client.
struct RangeFillSink {
    tx: Option<tokio::sync::mpsc::UnboundedSender<RangeMsg>>,
    queued: std::sync::Arc<std::sync::atomic::AtomicU64>,
    budget: std::sync::Arc<FillBudget>,
    metrics: std::sync::Arc<crate::metrics::EdgeMetrics>,
    queue_limit: u64,
    offset: u64,
    end: u64,
    /// Kept so a request with several missing chunk runs can wait for the
    /// previous writer to commit before the next run tries to take the key
    /// lock. Dropping it detaches the worker, which still commits its prefix.
    task: Option<tokio::task::JoinHandle<()>>,
}

impl RangeFillSink {
    fn push(&mut self, data: &[u8]) {
        if self.tx.is_none() || self.offset > self.end {
            return;
        }
        let take = (data.len() as u64).min(self.end.saturating_sub(self.offset).saturating_add(1))
            as usize;
        if take == 0 {
            return;
        }
        let queued = self
            .queued
            .fetch_add(take as u64, std::sync::atomic::Ordering::Relaxed)
            + take as u64;
        if queued > self.queue_limit {
            // Disk is slower than the origin/client path. Drop the fill and
            // let the worker commit whatever it already drained.
            self.queued
                .fetch_sub(take as u64, std::sync::atomic::Ordering::Relaxed);
            self.metrics.record_chunk_fill_drop_queue(take as u64);
            self.tx = None;
            return;
        }
        if !self.budget.reserve(take as u64) {
            self.queued
                .fetch_sub(take as u64, std::sync::atomic::Ordering::Relaxed);
            self.metrics.record_chunk_fill_drop_budget(take as u64);
            self.tx = None;
            return;
        }
        let Some(tx) = self.tx.as_ref() else {
            self.budget.release(take as u64);
            self.queued
                .fetch_sub(take as u64, std::sync::atomic::Ordering::Relaxed);
            return;
        };
        let chunk = Bytes::copy_from_slice(&data[..take]);
        if tx.send(RangeMsg::Chunk(chunk)).is_err() {
            self.budget.release(take as u64);
            self.queued
                .fetch_sub(take as u64, std::sync::atomic::Ordering::Relaxed);
            self.metrics.record_chunk_fill_drop_send(take as u64);
            self.tx = None;
            return;
        }
        self.offset = self.offset.saturating_add(take as u64);
    }

    async fn finish(mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(RangeMsg::End);
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

/// Spawn the background disk writer shared by the initial Range fill and the
/// manual span path. Dropping the sender without an `End` still commits the
/// prefix the worker received, which is what a client disconnect should keep.
fn spawn_range_writer(
    writer: RangeWriter,
    budget: Option<std::sync::Arc<FillBudget>>,
) -> (
    tokio::sync::mpsc::UnboundedSender<RangeMsg>,
    std::sync::Arc<std::sync::atomic::AtomicU64>,
    tokio::task::JoinHandle<()>,
) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<RangeMsg>();
    let queued = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let writer_queued = queued.clone();
    let task = tokio::spawn(async move {
        let mut writer = Some(writer);
        let mut finished = false;
        while let Some(msg) = rx.recv().await {
            match msg {
                RangeMsg::Chunk(data) => {
                    writer_queued
                        .fetch_sub(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    if let Some(budget) = budget.as_ref() {
                        budget.release(data.len() as u64);
                    }
                    if let Some(w) = writer.as_mut() {
                        w.write_all(&data).await;
                    }
                }
                RangeMsg::End => {
                    if let Some(w) = writer.take() {
                        let _ = w.commit_partial().await;
                    }
                    finished = true;
                    break;
                }
            }
        }
        if !finished {
            if let Some(w) = writer.take() {
                let _ = w.commit_partial().await;
            }
        }
    });
    (tx, queued, task)
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
    /// Response policy computed by the cache filter, reused by the response
    /// filter for the same Content-Type.
    response_policy: Option<ResponsePolicySlot>,
    range_fill: Option<RangeFill>,
    range_sink: Option<RangeSink>,
    /// Active gzip encoder for this response; set in `response_filter`.
    gzip: Option<GzipEncoder>,
    /// Pre-compressed body to replay instead of re-gzipping this response.
    gzip_replay: Option<Bytes>,
    /// Accumulates gzip output on the first request so it can be reused later.
    gzip_store: Option<(String, BytesMut)>,
    /// Remaining lifetime of the identity entry, reused as the variant TTL.
    identity_ttl_secs: Option<u64>,
    flight_guard: Option<crate::cache::flight::FlightGuard>,
    /// Set when the in-process handler already wrote its own access log.
    skip_logging: bool,
    /// Set once the shared preflight has run for this request, so the
    /// in-process fallback does not charge CC / rate limits a second time.
    preflight_done: bool,
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
            response_policy: None,
            range_fill: None,
            range_sink: None,
            gzip: None,
            gzip_replay: None,
            gzip_store: None,
            identity_ttl_secs: None,
            flight_guard: None,
            skip_logging: false,
            preflight_done: false,
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

fn cached_response_policy(
    slot: Option<&ResponsePolicySlot>,
    content_type: Option<&HeaderValue>,
) -> Option<ResolvedPolicy> {
    slot.filter(|slot| slot.content_type.as_ref() == content_type)
        .map(|slot| slot.policy)
}

/// A client closing/resetting a response stream is not an edge or origin
/// failure. Pingora reports it as a downstream write/read error.
fn is_downstream_disconnect(error: &pingora::Error) -> bool {
    error.esource() == &pingora::ErrorSource::Downstream
        && matches!(
            error.etype(),
            pingora::ErrorType::WriteError
                | pingora::ErrorType::ReadError
                | pingora::ErrorType::ConnectionClosed
        )
}

fn resolve_response_policy(
    plan: &NativePlan,
    path: &str,
    method: &str,
    query: &str,
    content_type: &str,
) -> ResolvedPolicy {
    let mut policy =
        resolve_rule_policy_for_response(&plan.domain.rules, path, method, query, content_type);
    apply_key_ignore_default(&mut policy, &plan.domain.cache_key_ignore_headers);
    policy
}

#[async_trait]
impl ProxyHttp for DataPlaneProxy {
    type CTX = ReqCtx;

    /// Do not emit a process log for a client that stopped reading a cached
    /// response. The stream is already unusable, and a load generator stopping
    /// at its deadline otherwise produces one ERROR per in-flight stream. The
    /// condition is counted separately for diagnostics.
    fn suppress_error_log(
        &self,
        _session: &Session,
        _ctx: &Self::CTX,
        error: &pingora::Error,
    ) -> bool {
        if is_downstream_disconnect(error) {
            self.state.metrics.record_downstream_cancel();
            return true;
        }
        false
    }

    /// Cache hits are written through Pingora's streaming path. When a client
    /// resets exactly at that point Pingora reports a downstream WriteError,
    /// which is expected cancellation rather than a cache failure.
    fn suppress_proxy_warn_log(
        &self,
        _session: &Session,
        _ctx: &Self::CTX,
        error: &pingora::Error,
        context: pingora::proxy::ProxyWarnLogContext,
    ) -> bool {
        matches!(
            context,
            pingora::proxy::ProxyWarnLogContext::DownstreamCache
        ) && is_downstream_disconnect(error)
    }

    fn new_ctx(&self) -> Self::CTX {
        ReqCtx::default()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        prepare_proxy_headers(
            session,
            self.trust_proxy,
            &self.trusted_proxies,
            &self.state.prefetch_token,
        )?;

        let req = session.req_header();
        let (authority, host) = (
            req.uri.authority().map(|authority| authority.as_str()),
            req.headers.get("host").and_then(|v| v.to_str().ok()),
        );
        ctx.host = normalized_authority_host(authority, host);
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

        if let Err(violation) =
            header_guard::validate(&req.headers, &req.uri, &ctx.method, req.version)
        {
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
            write_axum_response(session, resp, false, Some(&self.compression)).await;
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

        // Origin Shield loop protection. The request is stamped once here, so
        // every downstream origin path (native proxy, revalidation, streaming,
        // and the in-process fallback) forwards the same chain. The in-process
        // fallback receives the FromPingora marker and therefore does not stamp
        // again.
        // Strip loop headers from any peer outside `TRUSTED_EDGES` before taking
        // the verdict, so a public client cannot inject a 508 (SEC-NEW-04).
        let trusted_peer = session
            .client_addr()
            .and_then(|addr| addr.as_inet())
            .is_some_and(|addr| self.state.trusted_edges.contains(addr.ip()));
        if let Some(reason) = crate::security::loop_guard::guard_pingora(
            session.req_header_mut(),
            &self.state.node_id,
            trusted_peer,
        ) {
            ctx.cache_label = "BYPASS";
            ctx.cache_reason = Some(reason.as_str());
            ctx.status = 508;
            tracing::debug!(
                node_id = %self.state.node_id,
                reason = reason.as_str(),
                host = %ctx.host,
                path = %ctx.path,
                "origin shield loop detected"
            );
            write_plain(
                session,
                508,
                "text/plain; charset=utf-8",
                Bytes::from_static(b"loop detected"),
            )
            .await;
            return Ok(true);
        }
        crate::security::loop_guard::stamp_pingora(session.req_header_mut(), &self.state.node_id);

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
            && session
                .req_header()
                .headers
                .get("x-lagran-prefetch-token")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value == self.state.prefetch_token)
            && ctx
                .client_ip
                .parse::<std::net::IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false);
        if internal_prefetch {
            // If this request falls back to the in-process engine, it must not
            // run the public preflight (HTTPS redirect/WAF) a second time.
            ctx.preflight_done = true;
        }
        // Internal prefetch headers never reach the origin, even when the
        // marker/token combination is invalid.
        session.req_header_mut().remove_header("x-lagran-prefetch");
        session
            .req_header_mut()
            .remove_header("x-lagran-prefetch-token");

        // WebSocket is intentionally legacy-only: Pingora's HTTP proxy does
        // not tunnel upgraded connections on this path.
        let (registry_empty, domain) = self.state.domains.lookup(&ctx.host).await;
        if let Some(ref domain) = domain {
            let mut signed_verified = false;
            let mode = signed_url::effective_mode(domain);
            if mode != "off" && !internal_prefetch {
                let uri = session.req_header().uri.clone();
                let protected = signed_url::normalize_path(uri.path())
                    .map(|path| signed_url::path_protected(domain, &path))
                    .unwrap_or(true);
                if protected {
                    match signed_url::verify(
                        domain,
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
                    let mut auth = domain.as_ref().clone();
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

        // Upgrade requests go through the native proxy path: Pingora 0.9
        // validates matching H1 upgrade state on both legs and tunnels the
        // connection after 101. Routing them to the in-process engine could
        // never work (it has no `OnUpgrade` handle) and answered every
        // WebSocket handshake with 400.

        let Some(domain) = domain else {
            if ctx.host.is_empty() {
                // No Host, `:authority`, or SNI: attribute this as a 400-level
                // protocol error before the legacy handler, and do not create
                // an access-log row that no tenant can own or filter.
                ctx.cache_label = "BYPASS";
                ctx.cache_reason = Some("missing-host");
                ctx.status = 400;
                write_axum_response(
                    session,
                    default_page::missing_host_page(),
                    false,
                    Some(&self.compression),
                )
                .await;
                return Ok(true);
            }
            if !registry_empty {
                // A configured edge must not hand an unknown domain to the
                // legacy single-origin path: that would proxy the request to
                // the default origin under an empty logical host and log a
                // 404 row the console cannot attribute to any domain.
                ctx.cache_label = "NONE";
                ctx.status = StatusCode::NOT_FOUND.as_u16();
                let response = default_page::unknown_domain_page(&ctx.host);
                write_axum_response(session, response, false, Some(&self.compression)).await;
                return Ok(true);
            }
            // No domain entry and no static single-origin fallback. With the
            // native fallback installed at startup this is only reachable for a
            // hostless request, and there is no origin to serve it from. Answer
            // 404 instead of handing the request to the in-process engine: the
            // unconfigured edge has nothing to attribute the row to, so logging
            // is skipped exactly as it was on the legacy path.
            ctx.cache_label = "NONE";
            ctx.skip_logging = true;
            ctx.status = StatusCode::NOT_FOUND.as_u16();
            let response = default_page::unknown_domain_page(&ctx.host);
            write_axum_response(session, response, false, Some(&self.compression)).await;
            return Ok(true);
        };
        // Run the shared preflight (HTTPS redirect, bot challenge, CC, rate
        // limit, WAF, hotlink) before ANY cache revalidation. This used to live
        // inside the native-plan branch below, while `try_large_revalidation`
        // ran first and answered a cached object directly — so a client sending
        // `Cache-Control: no-cache` skipped every L7 protection for that
        // request (WAF, CC, rate limit, hotlink, HTTPS redirect).
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
        if !internal_prefetch {
            let pipeline = RequestPipeline::new(&self.state);
            let preflight = {
                let headers = &session.req_header().headers;
                let facts = RequestFacts {
                    method: &ctx.method,
                    host: &ctx.host,
                    path_only: &ctx.path,
                    path_and_query: &path_and_query,
                    headers,
                    client_ip: &ctx.client_ip,
                    is_https,
                    start: ctx.start,
                };
                pipeline.preflight(&domain, &facts).await
            };
            if let Some(resp) = preflight {
                let is_head = ctx.method == Method::HEAD;
                write_axum_response(session, resp, is_head, Some(&self.compression)).await;
                return Ok(true);
            }
            // Mark it so the in-process fallback does not run CC / rate limits
            // a second time for this client request.
            ctx.preflight_done = true;
        }
        // A node disabled from the console keeps serving nothing but its management
        // endpoints (health, heartbeat, purge). Answer here rather than falling back
        // to the in-process engine: the page goes out through `write_axum_response`,
        // so it carries the pingora datapath marker and the access log records the
        // refusal instead of an anonymous legacy hand-off.
        if !self.state.node_control.is_serving() {
            ctx.cache_label = "NODE_DISABLED";
            ctx.status = StatusCode::SERVICE_UNAVAILABLE.as_u16();
            let is_head = ctx.method == Method::HEAD;
            write_axum_response(
                session,
                default_page::node_disabled_page(&ctx.host),
                is_head,
                Some(&self.compression),
            )
            .await;
            return Ok(true);
        }
        // A domain whose origin configuration cannot be parsed is a control-plane
        // input error. Answer 502 here instead of handing the request to the
        // in-process engine: the legacy path would only fail the same way after a
        // wasted round trip, and `UNSUPPORTED_ORIGIN_URL` names the real problem.
        // `config_sync` derives `origin_url` from the (sorted) origin pool, so a
        // parse failure means the pool itself is unusable.
        if parse_origin(&domain.origin_url).is_none() {
            self.state.metrics.record_config_error();
            ctx.cache_label = "CONFIG_ERROR";
            ctx.status = StatusCode::BAD_GATEWAY.as_u16();
            let is_head = ctx.method == Method::HEAD;
            write_axum_response(
                session,
                default_page::config_error_page(&ctx.host),
                is_head,
                Some(&self.compression),
            )
            .await;
            return Ok(true);
        }
        if self.try_large_revalidation(session, ctx, &domain).await? {
            return Ok(true);
        }
        if let Some(plan) = self.native_plan(session, &ctx.host, &domain).await {
            self.state.metrics.record_pingora_datapath();
            let small_range = session.req_header().headers.contains_key("range")
                && range_is_small_bounded(&session.req_header().headers);
            if plan.cacheable && !self.state.cache.has_local(&plan.key).await {
                // Only take the cross-node lock when L1 does not already have
                // the object. A plain L1 hit must not issue Redis SET/EVAL
                // commands on every request.
                if let Some(flight) = self.state.flight.as_ref() {
                    let outcome = crate::cache::flight::acquire(
                        flight,
                        &plan.key,
                        plan.read_timeout_ms,
                        self.state.cache.as_ref(),
                    )
                    .await;
                    if outcome.is_degraded() {
                        // Redis is down: this request is not coalescing with the
                        // other nodes. Counted so the state is visible.
                        self.state.metrics.record_flight_degraded();
                    }
                    if let Some(guard) = outcome.into_guard() {
                        ctx.flight_guard = Some(guard);
                    }
                }
            }
            // Small bounded ranges can be answered directly from a complete
            // SharedCache object, keeping range slices on the Pingora path.
            if plan.cache_reason == Some("range-bypass")
                && small_range
                && !session.req_header().headers.contains_key("if-range")
                && plan.policy.action == RuleAction::Cache
                && request_bypass_reason_headers(
                    &session.req_header().headers,
                    plan.policy.ignore_cookie,
                )
                .is_none()
            {
                let raw_range = session
                    .req_header()
                    .headers
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
                && !session.req_header().headers.contains_key("if-range")
                && self.state.large_cache.is_some()
                && plan.policy.action == RuleAction::Cache
                && request_bypass_reason_headers(
                    &session.req_header().headers,
                    plan.policy.ignore_cookie,
                )
                .is_none()
            {
                let raw_range = session
                    .req_header()
                    .headers
                    .get("range")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                if let Some(raw_range) = raw_range {
                    if let Some(large) = self.state.large_cache.as_ref() {
                        if raw_range.contains(',') {
                            let total = if let Some(entry) = large.get_any(&plan.key).await {
                                entry.content_length()
                            } else {
                                self.probe_origin_total(session, &plan)
                                    .await
                                    .unwrap_or_default()
                            };
                            if total > 0 {
                                if let Some(ranges) = parse_multi_ranges(&raw_range, total) {
                                    if self
                                        .serve_large_multipart(session, &plan, &ranges, total)
                                        .await
                                    {
                                        ctx.cache_label = "HIT";
                                        ctx.cache_reason = Some("range-multipart");
                                        ctx.status = StatusCode::PARTIAL_CONTENT.as_u16();
                                        ctx.plan = Some(plan);
                                        return Ok(true);
                                    }
                                }
                            }
                        }
                        let mut had_entry = false;
                        if let Some(mut entry) = large.get_any(&plan.key).await {
                            had_entry = true;
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
                                    if let Some(chunk_plan) = entry.meta.chunk_plan(
                                        start,
                                        end,
                                        self.state.large_cache_chunk_bytes,
                                    ) {
                                        let missing_runs = chunk_plan
                                            .runs
                                            .iter()
                                            .filter(|run| !run.cached)
                                            .count();
                                        if missing_runs > MAX_CHUNK_ORIGIN_RUNS {
                                            self.state.metrics.record_chunk_fallback();
                                        }
                                        if missing_runs > 0
                                            && missing_runs <= MAX_CHUNK_ORIGIN_RUNS
                                            && self
                                                .serve_large_range_chunks(
                                                    session,
                                                    &mut entry,
                                                    &chunk_plan,
                                                    start,
                                                    end,
                                                    total,
                                                    &plan,
                                                )
                                                .await
                                        {
                                            ctx.cache_label = "HIT";
                                            ctx.cache_reason = Some("range-chunks");
                                            ctx.status = StatusCode::PARTIAL_CONTENT.as_u16();
                                            ctx.plan = Some(plan);
                                            return Ok(true);
                                        }
                                    }
                                }
                            }
                        }
                        if !had_entry
                            && self
                                .serve_large_range_miss_chunks(session, &plan, &raw_range)
                                .await
                        {
                            ctx.cache_label = "MISS";
                            ctx.cache_reason = Some("range-chunk-fill");
                            ctx.status = StatusCode::PARTIAL_CONTENT.as_u16();
                            ctx.plan = Some(plan);
                            return Ok(true);
                        }
                    }
                    let fill_cap = self
                        .state
                        .large_cache
                        .as_ref()
                        .map(|cache| {
                            cache.fill_cap(u64::MAX, self.state.large_cache_fill_max_bytes)
                        })
                        .unwrap_or(0);
                    if range_fill_is_candidate(&raw_range, fill_cap) {
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
        // A GET/HEAD that reached this point had a valid domain but could not
        // use the native cache path (HEAD, strict revalidation, a missing origin
        // or a method the in-process engine must handle). This is expected
        // routing, not an error; leave diagnostics to the access log so a
        // high-QPS workload cannot flood the process log. The reason is counted
        // so the remaining legacy surface stays visible.
        ctx.skip_logging = true;
        let reason = self.legacy_reason(session, &domain);
        self.handle_in_process(session, ctx.preflight_done, reason)
            .await
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
        // A complete normal-cache copy must not mask a partial large-cache
        // object. Otherwise a Range can be answered from an old full entry and
        // the missing chunk is never filled. Force an origin fetch and let the
        // Range fill path repair the chunk grid.
        if session.req_header().headers.contains_key("range") {
            if let (Some(plan), Some(large)) = (ctx.plan.as_ref(), self.state.large_cache.as_ref())
            {
                if let Some(entry) = large.get_any(&plan.key).await {
                    if !entry.meta.complete {
                        if ctx.range_fill.is_none() {
                            if let Some(raw) = session
                                .req_header()
                                .headers
                                .get("range")
                                .and_then(|value| value.to_str().ok())
                            {
                                ctx.range_fill = Some(RangeFill {
                                    key: plan.key.clone(),
                                    raw_range: raw.to_string(),
                                });
                            }
                        }
                        return Ok(Some(ForcedFreshness::ForceMiss));
                    }
                }
            }
        }
        ctx.cache_age_secs = Some(meta.age().as_secs());
        ctx.cache_ttl_secs = Some(meta.fresh_sec().saturating_sub(meta.age().as_secs()));
        let Some(plan) = ctx.plan.as_ref() else {
            return Ok(None);
        };
        let content_type_value = meta.response_header().headers.get("content-type");
        let content_type = content_type_value
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        let query = session.req_header().uri.query().unwrap_or("");
        let response_policy = if content_type.is_empty() || !plan.domain.has_content_type_rules {
            plan.policy
        } else {
            resolve_response_policy(plan, &ctx.path, ctx.method.as_str(), query, content_type)
        };
        if plan.domain.has_content_type_rules && !content_type.is_empty() {
            ctx.response_policy = Some(ResponsePolicySlot {
                content_type: content_type_value.cloned(),
                policy: response_policy,
            });
        }
        if content_type.is_empty() {
            return Ok(None);
        }
        if response_policy.action != RuleAction::Cache {
            return Ok(Some(ForcedFreshness::ForceMiss));
        }
        // How long the identity object can still be served; a pre-compressed
        // variant outliving it would only waste memory.
        let lifespan = meta
            .fresh_sec()
            .saturating_add(u64::from(meta.stale_while_revalidate_sec()));
        ctx.identity_ttl_secs = Some(lifespan.saturating_sub(meta.age().as_secs()).max(1));
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
        let (domain, connect_timeout_ms, read_timeout_ms) = {
            let plan = ctx
                .plan
                .as_ref()
                .ok_or_else(|| pingora::Error::new_str("native plan missing"))?;
            (
                Arc::clone(&plan.domain),
                plan.connect_timeout_ms,
                plan.read_timeout_ms,
            )
        };
        if ctx.origin_order.is_empty() {
            let order = self.origin_order(&ctx.host, &domain).await;
            if order.is_empty() {
                return Err(pingora::Error::new_str("no origin available"));
            }
            ctx.origin_order = order;
        }

        loop {
            let index = ctx.attempt.min(ctx.origin_order.len() - 1);
            let url = ctx.origin_order[index].clone();
            ctx.current_origin = url.clone();
            let origin = domain.origins.iter().find(|o| o.url == url);
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
                    connect_timeout_ms,
                    if session.req_header().headers.contains_key("range") {
                        self.state.origin_stream_read_timeout_ms
                    } else {
                        read_timeout_ms
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
        crate::security::loop_guard::ensure_stamped_pingora(upstream_request, &self.state.node_id);
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
        let content_type_value = resp.headers.get("content-type");
        let content_type = content_type_value
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        let query = session.req_header().uri.query().unwrap_or("");
        let response_policy = if plan.domain.has_content_type_rules {
            resolve_response_policy(plan, &ctx.path, ctx.method.as_str(), query, content_type)
        } else {
            plan.policy
        };
        if plan.domain.has_content_type_rules {
            ctx.response_policy = Some(ResponsePolicySlot {
                content_type: content_type_value.cloned(),
                policy: response_policy,
            });
        }
        if response_policy.action != RuleAction::Cache {
            ctx.response_bypass = true;
            ctx.cache_reason = Some("content-type-bypass");
            return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(
                "content-type rule",
            )));
        }
        // Borrow the header map directly: materialising it cost two `String`s per
        // header (20-40 of them) for four lookups, on every response.
        let decision = match decide_storage_reason_map(
            resp.status.as_u16(),
            &resp.headers,
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
        ctx.identity_ttl_secs = Some(decision.ttl_secs.saturating_add(decision.swr_secs).max(1));
        let now = SystemTime::now();
        // Never let an origin header overflow the clock: this exact addition
        // used to panic and kill a Pingora worker thread.
        let fresh_until = now
            .checked_add(Duration::from_secs(decision.ttl_secs))
            .unwrap_or(now);
        let meta = CacheMeta::new(
            fresh_until,
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
        let content_type_value = response.headers.get("content-type");
        let content_type = content_type_value
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        let query = session.req_header().uri.query().unwrap_or("");
        let response_policy = if plan.domain.has_content_type_rules {
            cached_response_policy(ctx.response_policy.as_ref(), content_type_value).unwrap_or_else(
                || {
                    resolve_response_policy(
                        plan,
                        &ctx.path,
                        ctx.method.as_str(),
                        query,
                        content_type,
                    )
                },
            )
        } else {
            plan.policy
        };
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
        let cache_source = resolve_cache_source(
            label,
            response
                .headers
                .get("x-lagran-cache-source")
                .and_then(|v| v.to_str().ok()),
        );
        let lookup_ms = response
            .headers
            .get("x-lagran-cache-lookup-ms")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("0")
            .to_string();
        response.insert_header("x-lagran-cache-source", cache_source)?;
        response.insert_header("x-lagran-cache-lookup-ms", lookup_ms.clone())?;
        response.insert_header("server-timing", format!("cache;dur={lookup_ms}"))?;

        if plan.cacheable || plan.is_head {
            let browser_ttl = (response_policy.action == RuleAction::Cache)
                .then(|| policy_browser_ttl(&response_policy))
                .flatten();
            Self::apply_browser_ttl(response, browser_ttl);
        }
        Self::apply_security_headers(response);
        Self::apply_cors_and_custom(response, &plan.domain.response_headers);
        // Compress here, not upstream: the cache has already stored the
        // identity body, so one object serves every Accept-Encoding.
        if !plan.is_head && !plan.is_websocket && ctx.gzip.is_none() && ctx.gzip_replay.is_none() {
            let (compress, request_version) = {
                let req = session.req_header();
                (
                    should_compress(
                        &self.compression,
                        req.version,
                        &req.method,
                        response.status.as_u16(),
                        &response.headers,
                        &req.headers,
                    ),
                    req.version,
                )
            };
            if compress {
                // Key variants by the validator so a changed object can never
                // be served from a stale compressed copy.
                let etag = response
                    .headers
                    .get(header::ETAG)
                    .and_then(|value| value.to_str().ok())
                    .filter(|value| !value.is_empty())
                    .map(str::to_string);
                let variant_key = if plan.cacheable && ctx.identity_ttl_secs.is_some() {
                    etag.as_deref()
                        .map(|etag| compressed_variant_key(&plan.key, etag))
                } else {
                    None
                };
                if let Some(key) = variant_key.as_deref() {
                    if let Some(cached) = self.state.compressed.get(key).await {
                        if !cached.body.is_empty() {
                            ctx.gzip_replay = Some(cached.body);
                        }
                    }
                }

                response.insert_header(header::CONTENT_ENCODING, "gzip")?;
                // The compressed length is not known up front.
                response.remove_header(&header::CONTENT_LENGTH);
                vary_on_accept_encoding(response)?;
                // H1 needs explicit framing once Content-Length is gone; H2
                // must not carry Transfer-Encoding at all.
                if request_version == Version::HTTP_11 {
                    response.insert_header(header::TRANSFER_ENCODING, "chunked")?;
                }
                weaken_etag(response)?;

                if ctx.gzip_replay.is_none() {
                    ctx.gzip = Some(GzipEncoder::new(self.compression.level));
                    if let Some(key) = variant_key {
                        if self.compression.variant_max_object_bytes > 0 {
                            ctx.gzip_store = Some((key, BytesMut::new()));
                        }
                    }
                }
            }
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
                        let present = large
                            .get_any(&fill.key)
                            .await
                            .map(|entry| entry.meta.stored_bytes())
                            .unwrap_or(0);
                        let fill_cap = large
                            .fill_cap(total, self.state.large_cache_fill_max_bytes)
                            .saturating_sub(present);
                        if let Some((fill_start, fill_end)) =
                            fill_window(&fill.raw_range, start, end, total, fill_cap)
                        {
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
                                    let budget = large.fill_budget();
                                    let (tx, queued, _task) =
                                        spawn_range_writer(writer, Some(budget.clone()));
                                    ctx.range_sink = Some(RangeSink {
                                        tx,
                                        offset: fill_start,
                                        end: fill_end,
                                        skip: fill_start.saturating_sub(start),
                                        queued,
                                        budget,
                                        metrics: self.state.metrics.clone(),
                                        queue_limit: self.state.large_cache_fill_queue_bytes,
                                    });
                                } else {
                                    ctx.cache_reason = Some(
                                        if fill_end.saturating_sub(fill_start).saturating_add(1)
                                            > large.max_object_bytes()
                                        {
                                            "range-too-large"
                                        } else {
                                            "range-fill-skipped"
                                        },
                                    );
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
        if ctx.gzip_replay.is_some() || ctx.gzip.is_some() {
            // Replay path: the compressed copy is already in memory. The
            // identity body is still streamed by the cache layer, so it is
            // dropped here instead of being re-compressed.
            if let Some(replay) = ctx.gzip_replay.as_mut() {
                let input_len = body.as_ref().map(|chunk| chunk.len()).unwrap_or(0);
                let out = replay_chunk(replay, input_len, end_of_stream);
                *body = if out.is_empty() { None } else { Some(out) };
                if end_of_stream {
                    ctx.gzip_replay = None;
                }
                return Ok(None);
            }

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
            if let Some((_, buffer)) = ctx.gzip_store.as_mut() {
                if buffer.len() + encoded.len() <= self.compression.variant_max_object_bytes {
                    buffer.extend_from_slice(&encoded);
                } else {
                    // Too large to retain; keep streaming without the store.
                    ctx.gzip_store = None;
                }
            }
            if end_of_stream {
                if let Some((key, buffer)) = ctx.gzip_store.take() {
                    let ttl = ctx
                        .identity_ttl_secs
                        .unwrap_or(self.compression.variant_ttl_secs)
                        .max(1);
                    let entry = crate::cache::CacheEntry::new(200, Vec::new(), buffer.freeze());
                    if let Ok(handle) = tokio::runtime::Handle::try_current() {
                        let store = self.state.compressed.clone();
                        handle.spawn(async move {
                            store.set_with_swr(&key, entry, ttl, 0).await;
                        });
                    }
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
                    let bytes = data.len() as u64;
                    if !sink.budget.reserve(bytes) {
                        sink.metrics.record_chunk_fill_drop_budget(bytes);
                        ctx.range_sink = None;
                        return Ok(None);
                    }
                    let queued = sink
                        .queued
                        .fetch_add(bytes, std::sync::atomic::Ordering::Relaxed)
                        + bytes;
                    if queued > sink.queue_limit {
                        // Disk writer is slower than the origin. Drop the fill
                        // rather than growing an unbounded queue; the client
                        // body is still forwarded unchanged.
                        sink.queued
                            .fetch_sub(bytes, std::sync::atomic::Ordering::Relaxed);
                        sink.budget.release(bytes);
                        sink.metrics.record_chunk_fill_drop_queue(bytes);
                        ctx.range_sink = None;
                        return Ok(None);
                    }
                    if sink.tx.send(RangeMsg::Chunk(data)).is_err() {
                        sink.queued
                            .fetch_sub(bytes, std::sync::atomic::Ordering::Relaxed);
                        sink.budget.release(bytes);
                        sink.metrics.record_chunk_fill_drop_send(bytes);
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
            "HIT" | "STALE" => self.state.metrics.record_hit(&ctx.host, bytes),
            "MISS" | "REVALIDATED" => self.state.metrics.record_miss(&ctx.host, bytes),
            _ => self.state.metrics.record_bypass(&ctx.host, bytes),
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
            write_axum_response(
                session,
                page,
                ctx.method == Method::HEAD,
                Some(&self.compression),
            )
            .await;
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
    fn apply_browser_ttl(response: &mut ResponseHeader, ttl: Option<u64>) {
        let Some(ttl) = ttl.filter(|ttl| *ttl > 0) else {
            return;
        };
        if response.headers.contains_key(header::SET_COOKIE) {
            return;
        }
        if let Some(cache_control) = response
            .headers
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
        {
            let cache_control = cache_control.to_ascii_lowercase();
            if cache_control.contains("no-store") || cache_control.contains("private") {
                return;
            }
        }
        let value = format!("public, max-age={ttl}");
        let _ = response.insert_header(header::CACHE_CONTROL, value);
    }

    fn apply_security_headers(response: &mut ResponseHeader) {
        let _ = response.insert_header("x-content-type-options", "nosniff");
        let _ = response.insert_header("x-frame-options", "SAMEORIGIN");
        let _ = response.insert_header("referrer-policy", "strict-origin-when-cross-origin");
    }

    fn apply_cors_and_custom(
        response: &mut ResponseHeader,
        overrides: &crate::server::response_headers::ResponseHeaderOverrides,
    ) {
        if let Some(origin) = overrides.cors_origin() {
            let _ = response.insert_header("access-control-allow-origin", origin.clone());
        }
        for (name, value) in overrides.custom() {
            let _ = response.insert_header(name.clone(), value.clone());
        }
    }

    /// Large-object conditional revalidation. For strict requests, try a HEAD
    /// conditional request first. A 304 is served from the existing large file
    /// without touching its body; a 200 removes the stale object and lets the
    /// normal native path stream and replace it.
    async fn try_large_revalidation(
        &self,
        session: &mut Session,
        ctx: &mut ReqCtx,
        domain: &Arc<DomainEntry>,
    ) -> Result<bool> {
        if session.req_header().method != Method::GET
            || session.req_header().headers.contains_key("range")
        {
            return Ok(false);
        }
        let strict = is_strict_revalidation(&session.req_header().headers);
        if !strict {
            return Ok(false);
        }

        let cache_control = session.req_header().headers.get("cache-control").cloned();
        let pragma = session.req_header().headers.get("pragma").cloned();
        session.req_header_mut().remove_header("cache-control");
        session.req_header_mut().remove_header("pragma");
        let result = self.revalidate_strict(session, ctx, domain).await;
        // Restore the client's strict-revalidation intent whenever this helper
        // did not serve the response. The caller rebuilds its plan afterwards;
        // if `Cache-Control: no-cache` were left stripped, that plan would look
        // like an ordinary cacheable GET and Pingora would serve a stale HIT the
        // client explicitly asked not to get. Restoring after a served response
        // is harmless — the request is already finished.
        if let Some(v) = cache_control {
            let _ = session.req_header_mut().insert_header("cache-control", v);
        }
        if let Some(v) = pragma {
            let _ = session.req_header_mut().insert_header("pragma", v);
        }
        result
    }

    /// Body of [`Self::try_large_revalidation`] after the strict-revalidation
    /// headers were removed, so the plan it builds is cacheable.
    async fn revalidate_strict(
        &self,
        session: &mut Session,
        ctx: &mut ReqCtx,
        domain: &Arc<DomainEntry>,
    ) -> Result<bool> {
        let plan = self.native_plan(session, &ctx.host, domain).await;
        let Some(plan) = plan else {
            return Ok(false);
        };
        if !plan.cacheable {
            // Authorization / Cookie / rule-bypass requests must not be served
            // from the shared cache, even when they ask for revalidation.
            return Ok(false);
        }
        // Normal-object conditional revalidation. On 304 the cached body is
        // served here; on a changed origin the entry is dropped and the native
        // path performs a single streaming fill. This keeps strict no-cache
        // GETs out of the legacy data plane.
        let _revalidation_guard = if let Some(flight) = self.state.flight.as_ref() {
            // Same derivation as `acquire`: the lock must outlive the fetch it
            // protects, and the wait must fit inside the lock.
            let ttl_ms = crate::cache::flight::lock_ttl_ms(plan.read_timeout_ms);
            match flight.try_lock(&plan.key, ttl_ms).await {
                Ok(Some(guard)) => Some(guard),
                Ok(None) => {
                    // Another node is validating this key. Wait for its
                    // conditional request to finish, then use the refreshed
                    // shared entry instead of firing a duplicate origin check.
                    flight
                        .wait_unlocked(&plan.key, crate::cache::flight::lock_wait(ttl_ms))
                        .await;
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

        let target = match plan.domain.origins.iter().find(|origin| origin.enabled) {
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
        // Build the merged list in one pass. `header_vec` used to materialise the
        // conditional headers first and this loop copied them again; the vector is
        // still needed below for `refresh_meta`, but it now comes from the merged
        // list rather than being built twice.
        let mut merged_headers = entry.meta.headers.clone();
        let mut conditional_headers: Vec<(String, String)> = Vec::new();
        for (name, value) in &conditional.headers {
            let name = name.as_str();
            if name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("transfer-encoding")
                || name.eq_ignore_ascii_case("connection")
                || name.eq_ignore_ascii_case("age")
            {
                continue;
            }
            let Ok(value) = value.to_str() else {
                continue;
            };
            merged_headers.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
            merged_headers.push((name.to_string(), value.to_string()));
            conditional_headers.push((name.to_string(), value.to_string()));
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
        let source = entry.header(VALIDATOR_SOURCE_HEADER).unwrap_or("");
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

        let target = match plan.domain.origins.iter().find(|origin| origin.enabled) {
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
            refreshed.headers.push((
                name.as_str().to_string(),
                value.to_str().unwrap_or("").to_string(),
            ));
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
        refreshed.fresh_until_epoch_secs = now.saturating_add(decision.ttl_secs.max(1));
        refreshed.stale_until_epoch_secs = now
            .saturating_add(decision.ttl_secs.max(1))
            .saturating_add(decision.swr_secs);
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

    // These are the byte-range coordinates plus the session/cache context;
    // grouping them would add wrapper types used only at these call sites.
    #[allow(clippy::too_many_arguments)]
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
        let Ok(mut response) =
            ResponseHeader::build(StatusCode::PARTIAL_CONTENT.as_u16(), Some(len as usize))
        else {
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
        Self::apply_security_headers(&mut response);
        Self::apply_cors_and_custom(&mut response, &plan.domain.response_headers);
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
        session.write_response_body(Some(body), true).await.is_ok()
    }

    async fn serve_normal_entry(
        &self,
        session: &mut Session,
        entry: crate::cache::CacheEntry,
        plan: &NativePlan,
        reason: &'static str,
    ) {
        let len = entry.body.len();
        let client_match = entry.header("etag").is_some_and(|etag| {
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
        Self::apply_security_headers(&mut response);
        Self::apply_cors_and_custom(&mut response, &plan.domain.response_headers);

        if client_match {
            let mut not_modified =
                match ResponseHeader::build(StatusCode::NOT_MODIFIED.as_u16(), None) {
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
        let _ = session.write_response_body(Some(entry.body), true).await;
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
                let Ok(mut response) =
                    ResponseHeader::build(StatusCode::NOT_MODIFIED.as_u16(), None)
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
                let _ = session
                    .write_response_header(Box::new(response), true)
                    .await;
                return;
            }
        }

        let Ok(mut response) = ResponseHeader::build(StatusCode::OK.as_u16(), Some(total as usize))
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
        Self::apply_security_headers(&mut response);
        Self::apply_cors_and_custom(&mut response, &plan.domain.response_headers);
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

    /// Why no native plan can be built for this session, if that is the case.
    ///
    /// One definition for two callers: `native_plan` decides routing with it and
    /// `legacy_reason` labels the fallback with it. Keeping them separate would let
    /// the metric drift away from the actual routing decision.
    fn plan_blocker(&self, session: &Session) -> Option<LegacyFallback> {
        if !self.native_cache || self.storage.is_none() {
            return Some(LegacyFallback::NativeCacheDisabled);
        }
        let req = session.req_header();
        // HEAD is served natively: a cache hit answers from `serve_head_cache`
        // (real representation length, no body), a miss proxies the HEAD request
        // itself so the origin supplies the length and nothing is written to the
        // cache. Both stay inside Pingora.
        // Strict client revalidation has a dedicated conditional-origin path in
        // the in-process engine (304 refresh). Keep it off the native cache
        // fast path so a stale body is never served on max-age=0/no-cache.
        if is_strict_revalidation(&req.headers) {
            return Some(LegacyFallback::StrictRevalidation);
        }
        None
    }

    /// Label a request that is about to be handed to the in-process engine.
    ///
    /// Only called on the fallback path, so it never runs on the native fast path.
    fn legacy_reason(&self, session: &Session, domain: &DomainEntry) -> LegacyFallback {
        if let Some(blocker) = self.plan_blocker(session) {
            return blocker;
        }
        // `request_filter` answers an unparseable `origin_url` with a 502 before it
        // reaches this point, so this is not an origin-configuration fallback any
        // more; labelling it `parse_origin` would make the metric disagree with the
        // actual routing decision.
        let _ = domain;
        LegacyFallback::Other
    }

    async fn native_plan(
        &self,
        session: &Session,
        host: &str,
        domain: &Arc<DomainEntry>,
    ) -> Option<NativePlan> {
        if self.plan_blocker(session).is_some() {
            return None;
        }
        let req = session.req_header();
        // Small bounded ranges are served from SharedCache when possible; the
        // remaining ranges use native streaming. Open-ended ranges (`bytes=0-`)
        // stay streaming as before.
        let has_range = req.headers.contains_key("range");
        let path = req.uri.path().to_string();
        let path_and_query = req
            .uri
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        let pipeline = RequestPipeline::new(&self.state);
        let policy = pipeline.policy_for(domain, &req.method, &path, req.uri.query().unwrap_or(""));
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
            domain,
            &req.method,
            host,
            &path,
            &path_and_query,
            &req.headers,
            &policy,
        );
        // Ranges use native streaming unless a complete cached object covers
        // the slice above. This keeps every GET/HEAD request on Pingora.
        Some(NativePlan {
            domain: Arc::clone(domain),
            key,
            origin_host,
            connect_timeout_ms: effective_connect_timeout_ms(
                domain.origin_timeout_ms,
                self.state.origin.connect_timeout_ms(),
            ),
            read_timeout_ms: self.state.origin_read_timeout_ms,
            cache_reason: request_reason,
            policy,
            cacheable,
            is_head,
            is_websocket,
            label,
        })
    }

    #[allow(clippy::too_many_arguments)]
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
            || response
                .insert_header(
                    "x-lagran-cache-reason",
                    if fresh {
                        "range-large-cache"
                    } else {
                        "stale-range"
                    },
                )
                .is_err()
        {
            return false;
        }
        Self::apply_security_headers(&mut response);
        Self::apply_cors_and_custom(&mut response, &plan.domain.response_headers);
        let _ = response.insert_header("x-powered-by", "lagran-edge");
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

        let _ = self
            .write_large_body(session, entry, start, end, true)
            .await;
        true
    }

    /// Fill the chunk-aligned span covering a multipart request without
    /// writing a client response. Returns false when the cache cannot be made
    /// complete for the span (no entry, stale entry, cap/disk limits, origin
    /// mismatch); the caller then falls back to the origin's multipart response.
    async fn fill_large_span(
        &self,
        session: &Session,
        native_plan: &NativePlan,
        start: u64,
        end: u64,
        total: u64,
    ) -> bool {
        if start > end || end >= total {
            return false;
        }
        let chunk_bytes = self.state.large_cache_chunk_bytes;
        if chunk_bytes == 0 {
            return false;
        }
        let Some(large) = self.state.large_cache.as_ref() else {
            return false;
        };
        if let Some(entry) = large.get_any(&native_plan.key).await {
            let fill_chunk_bytes = if entry.meta.chunk_bytes > 0 {
                entry.meta.chunk_bytes
            } else {
                chunk_bytes
            };
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if now > entry.meta.fresh_until {
                return false;
            }
            if entry.covers(start, end) {
                return true;
            }
            let Some(plan) = entry.meta.chunk_plan(start, end, chunk_bytes) else {
                return false;
            };
            let missing_runs = plan.runs.iter().filter(|run| !run.cached).count();
            if missing_runs == 0 || missing_runs > MAX_CHUNK_ORIGIN_RUNS {
                return false;
            }
            let cap = large.fill_cap(total, self.state.large_cache_fill_max_bytes);
            let missing_bytes = entry.meta.missing_bytes(start, end);
            if entry.meta.stored_bytes().saturating_add(missing_bytes) > cap {
                return false;
            }
            let fresh_secs = entry.meta.fresh_until.saturating_sub(now).max(1);
            let swr_secs = entry
                .meta
                .stale_until
                .saturating_sub(entry.meta.fresh_until);
            for run in plan.runs.iter().filter(|run| !run.cached) {
                let origin = match self
                    .open_chunk_origin(session, native_plan, &entry, run.start, run.end, total)
                    .await
                {
                    Ok(origin) => origin,
                    Err(_) => return false,
                };
                let hdrs = entry.meta.headers.clone();
                let Some(writer) = large
                    .begin_chunk_range(
                        &native_plan.key,
                        200,
                        hdrs,
                        total,
                        run.start,
                        run.end,
                        fresh_secs,
                        swr_secs,
                        fill_chunk_bytes,
                    )
                    .await
                else {
                    return false;
                };
                if !self
                    .fill_origin_body(writer, origin.body, run.start, run.end)
                    .await
                {
                    return false;
                }
            }
            return true;
        }

        // No cache entry yet: fetch one chunk-aligned bounding span, create
        // the sidecar from the origin response and fill it before serving the
        // multipart response from disk.
        let chunk_start = (start / chunk_bytes) * chunk_bytes;
        let chunk_end = ((end / chunk_bytes) + 1)
            .saturating_mul(chunk_bytes)
            .saturating_sub(1)
            .min(total.saturating_sub(1));
        let full_len = chunk_end.saturating_sub(chunk_start).saturating_add(1);
        let cap = large.fill_cap(total, self.state.large_cache_fill_max_bytes);
        if full_len > cap || full_len > large.max_object_bytes() {
            return false;
        }
        let (origin, origin_total, origin_end) = match self
            .open_miss_origin(session, native_plan, chunk_start, Some(chunk_end))
            .await
        {
            Ok(value) => value,
            Err(_) => return false,
        };
        if origin_total != total || origin_end < chunk_end {
            return false;
        }
        let mut cache_headers = header_vec(&origin.headers);
        cache_headers.retain(|(name, _)| {
            !name.eq_ignore_ascii_case("content-range")
                && !name.eq_ignore_ascii_case("content-length")
                && !name.eq_ignore_ascii_case("transfer-encoding")
                && !name.eq_ignore_ascii_case("connection")
                && !name.eq_ignore_ascii_case("age")
                && !name.eq_ignore_ascii_case("x-cache")
                && !name.eq_ignore_ascii_case("x-cache-status")
                && !name.eq_ignore_ascii_case("x-lagran-cache-reason")
                && !name.eq_ignore_ascii_case("x-powered-by")
        });
        let cache_headers = crate::cache::large::LargeCache::prune_uncacheable(&cache_headers);
        let Some(decision) = decide_storage_reason(
            200,
            &cache_headers,
            native_plan.policy,
            self.state.default_ttl_secs,
        )
        .ok() else {
            return false;
        };
        let Some(writer) = large
            .begin_chunk_range(
                &native_plan.key,
                200,
                cache_headers,
                total,
                chunk_start,
                chunk_end,
                decision.ttl_secs,
                decision.swr_secs,
                chunk_bytes,
            )
            .await
        else {
            return false;
        };
        self.fill_origin_body(writer, origin.body, chunk_start, chunk_end)
            .await
    }

    /// Read an origin body into a range writer. The caller already validated
    /// the Content-Range; this only fails when the body ends before the range.
    async fn fill_origin_body(
        &self,
        mut writer: RangeWriter,
        mut body: hyper::body::Incoming,
        start: u64,
        end: u64,
    ) -> bool {
        let idle_timeout =
            Duration::from_millis(self.state.origin_stream_read_timeout_ms.max(1_000));
        let mut pos = start;
        let mut complete = true;
        while pos <= end {
            let frame = match tokio::time::timeout(idle_timeout, body.frame()).await {
                Ok(Some(Ok(frame))) => frame,
                _ => {
                    complete = false;
                    break;
                }
            };
            let Some(data) = frame.into_data().ok() else {
                continue;
            };
            if data.is_empty() {
                continue;
            }
            writer.write_all(&data).await;
            pos = pos.saturating_add(data.len() as u64);
        }
        let committed = writer.commit_partial().await;
        complete && committed
    }

    async fn serve_large_multipart(
        &self,
        session: &mut Session,
        native_plan: &NativePlan,
        ranges: &[(u64, u64)],
        total: u64,
    ) -> bool {
        if ranges.is_empty() {
            return false;
        }
        // Do not fetch the whole min..max envelope for two tiny ranges at
        // opposite ends of a video. Merge only ranges whose gap is at most two
        // chunks; wider gaps are filled as independent chunk-aligned spans.
        let spans = merge_multipart_spans(ranges, self.state.large_cache_chunk_bytes);
        if spans.is_empty() {
            return false;
        }
        for (start, end) in spans {
            if !self
                .fill_large_span(session, native_plan, start, end, total)
                .await
            {
                return false;
            }
        }
        let Some(large) = self.state.large_cache.as_ref() else {
            return false;
        };
        let Some(mut entry) = large.get_any(&native_plan.key).await else {
            return false;
        };
        if entry.content_length() != total
            || !ranges.iter().all(|(start, end)| entry.covers(*start, *end))
        {
            return false;
        }
        let fresh = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() <= entry.meta.fresh_until)
            .unwrap_or(false);
        if !fresh {
            return false;
        }

        let boundary = format!(
            "lagran-{:x}-{:x}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
            self.origin_counter
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let part_content_type = entry
            .meta
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| value.clone())
            .unwrap_or_else(|| "application/octet-stream".to_string());
        let mut part_headers = Vec::with_capacity(ranges.len());
        let mut content_length = 0u64;
        for (start, end) in ranges {
            let header = format!(
                "--{boundary}\r\nContent-Type: {part_content_type}\r\nContent-Range: bytes {start}-{end}/{total}\r\n\r\n"
            )
            .into_bytes();
            content_length = content_length
                .saturating_add(header.len() as u64)
                .saturating_add(end.saturating_sub(*start).saturating_add(1))
                .saturating_add(2);
            part_headers.push((header, *start, *end));
        }
        let final_boundary = format!("--{boundary}--\r\n");
        content_length = content_length.saturating_add(final_boundary.len() as u64);
        if content_length > usize::MAX as u64 {
            return false;
        }
        let Ok(mut response) = ResponseHeader::build(
            StatusCode::PARTIAL_CONTENT.as_u16(),
            Some(content_length as usize),
        ) else {
            return false;
        };
        for (name, value) in &entry.meta.headers {
            if name.eq_ignore_ascii_case(META_HEADER)
                || name.eq_ignore_ascii_case(VALIDATOR_SOURCE_HEADER)
                || name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("content-range")
                || name.eq_ignore_ascii_case("content-type")
                || name.eq_ignore_ascii_case("accept-ranges")
                || name.eq_ignore_ascii_case("age")
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
            .insert_header(
                "content-type",
                format!("multipart/byteranges; boundary={boundary}"),
            )
            .is_err()
            || response
                .insert_header("content-length", content_length.to_string())
                .is_err()
            || response.insert_header("accept-ranges", "bytes").is_err()
            || response.insert_header("x-cache", "HIT").is_err()
            || response.insert_header("x-cache-status", "HIT").is_err()
            || response
                .insert_header("x-lagran-cache-source", "l3")
                .is_err()
            || response
                .insert_header("x-lagran-cache-reason", "range-multipart")
                .is_err()
        {
            return false;
        }
        Self::apply_security_headers(&mut response);
        Self::apply_cors_and_custom(&mut response, &native_plan.domain.response_headers);
        let _ = response.insert_header("x-powered-by", "lagran-edge");
        if entry.meta.stored_at > 0 {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let _ =
                response.insert_header("age", now.saturating_sub(entry.meta.stored_at).to_string());
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
        for (header, start, end) in part_headers {
            if session
                .write_response_body(Some(Bytes::from(header)), false)
                .await
                .is_err()
            {
                return true;
            }
            if !self
                .write_large_body(session, &mut entry, start, end, false)
                .await
            {
                return true;
            }
            if session
                .write_response_body(Some(Bytes::from_static(b"\r\n")), false)
                .await
                .is_err()
            {
                return true;
            }
        }
        let _ = session
            .write_response_body(Some(Bytes::from(final_boundary)), true)
            .await;
        true
    }

    /// Write exactly `[start, end]` from an already-open large entry.
    ///
    /// `last` marks the final chunk of the downstream response. Returning
    /// false after the response header has been sent means the caller should
    /// close the stream rather than append an error body.
    async fn write_large_body(
        &self,
        session: &mut Session,
        entry: &mut LargeEntry,
        start: u64,
        end: u64,
        last: bool,
    ) -> bool {
        if start > end {
            return true;
        }
        const CHUNK: u64 = 8 * 1024 * 1024;
        let mut pos = start;
        while pos <= end {
            let want = (end - pos + 1).min(CHUNK) as usize;
            let Ok(Some(chunk)) = entry.read_at(pos, want).await else {
                return false;
            };
            if chunk.is_empty() {
                return false;
            }
            pos += chunk.len() as u64;
            let done = last && pos > end;
            if session
                .write_response_body(Some(chunk), done)
                .await
                .is_err()
            {
                return false;
            }
            if done {
                break;
            }
        }
        true
    }

    /// Open one origin request for a chunk-aligned run.
    ///
    /// `Err(true)` means the cached representation is invalid (200, ETag or
    /// Content-Range mismatch); the caller should drop the entry. `Err(false)`
    /// is a transient/unsupported response and leaves the cache alone.
    #[allow(clippy::too_many_arguments)]
    /// Origin targets in failover order for manual Range requests.
    ///
    /// `origin_order` applies health, priority and weighted ordering. It returns
    /// URLs only, so re-attach the full OriginTarget (Host/SNI) where possible.
    async fn chunk_origin_targets(&self, domain: &DomainEntry) -> Vec<OriginTarget> {
        let order = self.origin_order(&domain.domain, domain).await;
        let mut targets = Vec::with_capacity(order.len().max(1));
        for url in order {
            if let Some(target) = domain
                .origins
                .iter()
                .find(|target| target.enabled && target.url == url)
            {
                targets.push(target.clone());
            } else {
                targets.push(OriginTarget {
                    url,
                    weight: 100,
                    priority: 0,
                    enabled: true,
                    host_header: None,
                    sni: None,
                });
            }
        }
        if targets.is_empty() {
            if let Some(target) = domain.origins.iter().find(|target| target.enabled) {
                targets.push(target.clone());
            } else if !domain.origin_url.is_empty() {
                targets.push(OriginTarget {
                    url: domain.origin_url.clone(),
                    weight: 100,
                    priority: 0,
                    enabled: true,
                    host_header: None,
                    sni: None,
                });
            }
        }
        targets
    }

    /// Open one chunk-aligned origin range, failing over across origins.
    ///
    /// `Err(false)` means every origin failed transiently and the caller should
    /// fall back to the normal range path. `Err(true)` means an origin returned
    /// a response that cannot be represented as the cached object (wrong ETag,
    /// encoding, or Content-Range); trying another origin would risk mixing
    /// representations, so the caller must abandon the chunk fill.
    async fn open_chunk_origin(
        &self,
        session: &Session,
        native_plan: &NativePlan,
        entry: &LargeEntry,
        run_start: u64,
        run_end: u64,
        total: u64,
    ) -> Result<crate::origin::OriginStreamResponse, bool> {
        let targets = self.chunk_origin_targets(&native_plan.domain).await;
        if targets.is_empty() {
            return Err(false);
        }
        let path_and_query = session
            .req_header()
            .uri
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        let mut base_headers = session.req_header().headers.clone();
        for name in [
            "if-range",
            "if-none-match",
            "if-modified-since",
            "if-match",
            "if-unmodified-since",
        ] {
            base_headers.remove(name);
        }
        let Ok(range) = HeaderValue::from_str(&format!("bytes={run_start}-{run_end}")) else {
            return Err(false);
        };
        base_headers.insert("range", range);
        base_headers.insert("accept-encoding", HeaderValue::from_static("identity"));
        for (name, value) in &entry.meta.headers {
            if (name.eq_ignore_ascii_case("etag") || name.eq_ignore_ascii_case("last-modified"))
                && !value.is_empty()
            {
                if let Ok(value) = HeaderValue::from_str(value) {
                    base_headers.insert("if-range", value);
                }
                break;
            }
        }
        origin_auth::apply(
            &mut base_headers,
            &native_plan.domain.origin_auth_header,
            &native_plan.domain.origin_auth_value,
        );
        let idle_timeout =
            Duration::from_millis(self.state.origin_stream_read_timeout_ms.max(1_000));
        let mut invalid = false;
        for target in targets {
            let mut headers = base_headers.clone();
            if let Some(host) = target
                .host_header
                .clone()
                .or_else(|| target.sni.clone())
                .or_else(|| parse_origin(&target.url).map(|(host, _, _)| host))
            {
                if let Ok(value) = HeaderValue::from_str(&host) {
                    headers.insert(axum::http::header::HOST, value);
                }
            }
            self.state.metrics.record_chunk_origin_attempt();
            let response = match tokio::time::timeout(
                idle_timeout,
                self.state.origin.request_stream_with_sni(
                    &target.url,
                    &Method::GET,
                    &path_and_query,
                    &headers,
                    None,
                    true,
                    target.sni.as_deref(),
                ),
            )
            .await
            {
                Ok(Ok(response)) => response,
                _ => {
                    self.state.metrics.record_chunk_origin_failure();
                    tracing::debug!(origin = %target.url, "chunk origin attempt failed");
                    continue;
                }
            };
            if response.status != StatusCode::PARTIAL_CONTENT {
                tracing::debug!(
                    origin = %target.url,
                    status = response.status.as_u16(),
                    "chunk origin did not return 206"
                );
                // A 200 means the origin ignored Range; another pool member may
                // still support it. Try the next origin before giving up.
                self.state.metrics.record_chunk_origin_failure();
                continue;
            }
            if response
                .headers
                .get("content-encoding")
                .is_some_and(|value| {
                    value
                        .to_str()
                        .map(|v| !v.eq_ignore_ascii_case("identity") && !v.is_empty())
                        .unwrap_or(true)
                })
            {
                self.state.metrics.record_chunk_origin_failure();
                invalid = true;
                continue;
            }
            let Some((origin_start, origin_end, origin_total)) = response
                .headers
                .get("content-range")
                .and_then(|value| value.to_str().ok())
                .and_then(parse_content_range)
            else {
                self.state.metrics.record_chunk_origin_failure();
                invalid = true;
                continue;
            };
            // The chunk executor forwards from the requested run start. A wider
            // origin range would shift every byte; require the exact start.
            if origin_total != total || origin_start != run_start || origin_end < run_end {
                self.state.metrics.record_chunk_origin_failure();
                invalid = true;
                continue;
            }
            if let Some((_, cached_etag)) = entry
                .meta
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("etag"))
            {
                if let Some(origin_etag) = response
                    .headers
                    .get("etag")
                    .and_then(|value| value.to_str().ok())
                {
                    if origin_etag != cached_etag {
                        self.state.metrics.record_chunk_origin_failure();
                        invalid = true;
                        continue;
                    }
                }
            }
            return Ok(response);
        }
        Err(invalid)
    }

    /// Open a cache-independent chunk range (no cached ETag yet), failing over
    /// across origin targets. Returns the origin response, total object length
    /// and the origin's last byte.
    async fn open_miss_origin(
        &self,
        session: &Session,
        native_plan: &NativePlan,
        run_start: u64,
        run_end: Option<u64>,
    ) -> Result<(crate::origin::OriginStreamResponse, u64, u64), bool> {
        let targets = self.chunk_origin_targets(&native_plan.domain).await;
        if targets.is_empty() {
            return Err(false);
        }
        let path_and_query = session
            .req_header()
            .uri
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        let mut base_headers = session.req_header().headers.clone();
        for name in [
            "if-range",
            "if-none-match",
            "if-modified-since",
            "if-match",
            "if-unmodified-since",
        ] {
            base_headers.remove(name);
        }
        let range = match run_end {
            Some(end) => format!("bytes={run_start}-{end}"),
            None => format!("bytes={run_start}-"),
        };
        let Ok(value) = HeaderValue::from_str(&range) else {
            return Err(false);
        };
        base_headers.insert("range", value);
        base_headers.insert("accept-encoding", HeaderValue::from_static("identity"));
        origin_auth::apply(
            &mut base_headers,
            &native_plan.domain.origin_auth_header,
            &native_plan.domain.origin_auth_value,
        );
        let idle_timeout =
            Duration::from_millis(self.state.origin_stream_read_timeout_ms.max(1_000));
        let mut invalid = false;
        for target in targets {
            let mut headers = base_headers.clone();
            if let Some(host) = target
                .host_header
                .clone()
                .or_else(|| target.sni.clone())
                .or_else(|| parse_origin(&target.url).map(|(host, _, _)| host))
            {
                if let Ok(value) = HeaderValue::from_str(&host) {
                    headers.insert(axum::http::header::HOST, value);
                }
            }
            self.state.metrics.record_chunk_origin_attempt();
            let response = match tokio::time::timeout(
                idle_timeout,
                self.state.origin.request_stream_with_sni(
                    &target.url,
                    &Method::GET,
                    &path_and_query,
                    &headers,
                    None,
                    true,
                    target.sni.as_deref(),
                ),
            )
            .await
            {
                Ok(Ok(response)) => response,
                _ => {
                    self.state.metrics.record_chunk_origin_failure();
                    continue;
                }
            };
            if response.status != StatusCode::PARTIAL_CONTENT {
                self.state.metrics.record_chunk_origin_failure();
                continue;
            }
            if response
                .headers
                .get("content-encoding")
                .is_some_and(|value| {
                    value
                        .to_str()
                        .map(|v| !v.eq_ignore_ascii_case("identity") && !v.is_empty())
                        .unwrap_or(true)
                })
            {
                self.state.metrics.record_chunk_origin_failure();
                invalid = true;
                continue;
            }
            let Some((origin_start, origin_end, total)) = response
                .headers
                .get("content-range")
                .and_then(|value| value.to_str().ok())
                .and_then(parse_content_range)
            else {
                self.state.metrics.record_chunk_origin_failure();
                invalid = true;
                continue;
            };
            if origin_start != run_start || origin_end < run_start {
                self.state.metrics.record_chunk_origin_failure();
                invalid = true;
                continue;
            }
            if run_end.is_some_and(|end| origin_end < end) {
                self.state.metrics.record_chunk_origin_failure();
                invalid = true;
                continue;
            }
            return Ok((response, total, origin_end));
        }
        Err(invalid)
    }

    /// Resolve the total object length for a suffix Range (`bytes=-N`).
    ///
    /// HEAD is cheapest and does not pull a body. Some origins reject HEAD, so
    /// fall back to a one-byte `bytes=0-0` GET and read Content-Range.
    async fn probe_origin_total(&self, session: &Session, native_plan: &NativePlan) -> Option<u64> {
        let targets = self.chunk_origin_targets(&native_plan.domain).await;
        if targets.is_empty() {
            return None;
        }
        let path_and_query = session
            .req_header()
            .uri
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        let mut base_headers = session.req_header().headers.clone();
        for name in [
            "range",
            "if-range",
            "if-none-match",
            "if-modified-since",
            "if-match",
            "if-unmodified-since",
        ] {
            base_headers.remove(name);
        }
        base_headers.insert("accept-encoding", HeaderValue::from_static("identity"));
        origin_auth::apply(
            &mut base_headers,
            &native_plan.domain.origin_auth_header,
            &native_plan.domain.origin_auth_value,
        );
        let idle_timeout =
            Duration::from_millis(self.state.origin_stream_read_timeout_ms.max(1_000));
        for target in &targets {
            let mut headers = base_headers.clone();
            if let Some(host) = target
                .host_header
                .clone()
                .or_else(|| target.sni.clone())
                .or_else(|| parse_origin(&target.url).map(|(host, _, _)| host))
            {
                if let Ok(value) = HeaderValue::from_str(&host) {
                    headers.insert(axum::http::header::HOST, value);
                }
            }
            self.state.metrics.record_chunk_origin_attempt();
            let response = match tokio::time::timeout(
                idle_timeout,
                self.state.origin.request_stream_with_sni(
                    &target.url,
                    &Method::HEAD,
                    &path_and_query,
                    &headers,
                    None,
                    true,
                    target.sni.as_deref(),
                ),
            )
            .await
            {
                Ok(Ok(response)) => response,
                _ => {
                    self.state.metrics.record_chunk_origin_failure();
                    continue;
                }
            };
            if response
                .headers
                .get("content-encoding")
                .is_some_and(|value| {
                    value
                        .to_str()
                        .map(|v| !v.eq_ignore_ascii_case("identity") && !v.is_empty())
                        .unwrap_or(true)
                })
            {
                self.state.metrics.record_chunk_origin_failure();
                continue;
            }
            let total = if response.status == StatusCode::OK {
                response
                    .headers
                    .get("content-length")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok())
            } else if response.status == StatusCode::PARTIAL_CONTENT {
                response
                    .headers
                    .get("content-range")
                    .and_then(|value| value.to_str().ok())
                    .and_then(parse_content_range)
                    .map(|(_, _, total)| total)
            } else {
                None
            };
            if let Some(total) = total.filter(|total| *total > 0) {
                return Some(total);
            }
            self.state.metrics.record_chunk_origin_failure();
        }
        // HEAD unsupported or unusable: a one-byte range still gives the total.
        self.open_miss_origin(session, native_plan, 0, Some(0))
            .await
            .ok()
            .map(|(response, total, _)| {
                drop(response);
                total
            })
    }

    /// First request for a large Range: fetch whole chunks starting at the
    /// chunk that contains the client start. The cache therefore never stores
    /// an unaligned first chunk; a later request needs only the chunks that are
    /// still missing.
    #[allow(clippy::too_many_arguments)]
    async fn serve_large_range_miss_chunks(
        &self,
        session: &mut Session,
        native_plan: &NativePlan,
        raw_range: &str,
    ) -> bool {
        let chunk_bytes = self.state.large_cache_chunk_bytes;
        if chunk_bytes == 0 {
            return false;
        }
        let Some(large) = self.state.large_cache.as_ref() else {
            return false;
        };
        let Some(value) = raw_range.trim().strip_prefix("bytes=") else {
            return false;
        };
        if value.contains(',') {
            return false;
        }
        let Some((start_text, end_text)) = value.split_once('-') else {
            return false;
        };
        let start_text = start_text.trim();
        if start_text.is_empty() {
            let Ok(suffix) = end_text.trim().parse::<u64>() else {
                return false;
            };
            if suffix == 0 {
                return false;
            }
            self.state.metrics.record_chunk_origin_runs(1);
            let Some(total) = self.probe_origin_total(session, native_plan).await else {
                return false;
            };
            let client_start = total.saturating_sub(suffix);
            let synthesized = format!("bytes={client_start}-");
            return Box::pin(self.serve_large_range_miss_chunks(
                session,
                native_plan,
                &synthesized,
            ))
            .await;
        }
        self.state.metrics.record_chunk_request();
        let Ok(client_start) = start_text.parse::<u64>() else {
            return false;
        };
        let end_text = end_text.trim();
        let bounded_end = if end_text.is_empty() {
            None
        } else {
            match end_text.parse::<u64>() {
                Ok(value) => Some(value),
                Err(_) => return false,
            }
        };
        let chunk_start = (client_start / chunk_bytes) * chunk_bytes;
        let chunk_end_hint = bounded_end.map(|end| {
            let last = end / chunk_bytes;
            last.saturating_add(1)
                .saturating_mul(chunk_bytes)
                .saturating_sub(1)
        });

        self.state.metrics.record_chunk_origin_runs(1);
        let (origin, total, origin_end) = match self
            .open_miss_origin(session, native_plan, chunk_start, chunk_end_hint)
            .await
        {
            Ok(value) => value,
            Err(_) => return false,
        };
        if total < large.min_object_bytes() {
            // Below the large-cache threshold: let the normal cache/range path
            // handle it instead of taking over every small range request.
            return false;
        }
        if client_start >= total || bounded_end.is_some_and(|end| end >= total) {
            return false;
        }
        let cache_end = chunk_end_hint
            .map(|end| end.min(total.saturating_sub(1)))
            .unwrap_or_else(|| total.saturating_sub(1));
        if cache_end < chunk_start || origin_end < cache_end {
            return false;
        }
        let client_end = bounded_end
            .map(|end| end.min(total.saturating_sub(1)))
            .unwrap_or_else(|| total.saturating_sub(1));
        if client_start > client_end {
            return false;
        }
        let len = client_end.saturating_sub(client_start).saturating_add(1);
        if len == 0 || len > usize::MAX as u64 {
            return false;
        }

        let mut cache_headers = header_vec(&origin.headers);
        cache_headers.retain(|(name, _)| {
            !name.eq_ignore_ascii_case("content-range")
                && !name.eq_ignore_ascii_case("content-length")
                && !name.eq_ignore_ascii_case("transfer-encoding")
                && !name.eq_ignore_ascii_case("connection")
                && !name.eq_ignore_ascii_case("age")
                && !name.eq_ignore_ascii_case("x-cache")
                && !name.eq_ignore_ascii_case("x-cache-status")
                && !name.eq_ignore_ascii_case("x-lagran-cache-reason")
                && !name.eq_ignore_ascii_case("x-powered-by")
        });
        let cache_headers = crate::cache::large::LargeCache::prune_uncacheable(&cache_headers);
        let decision = decide_storage_reason(
            200,
            &cache_headers,
            native_plan.policy,
            self.state.default_ttl_secs,
        )
        .ok();

        let full_len = cache_end.saturating_sub(chunk_start).saturating_add(1);
        let cap = large.fill_cap(total, self.state.large_cache_fill_max_bytes);
        let wanted = full_len
            .min(cap)
            .min(large.max_object_bytes())
            .min(large.available_bytes());
        let fill_len = if wanted >= full_len {
            full_len
        } else {
            (wanted / chunk_bytes) * chunk_bytes
        };
        let fill_len = fill_len
            .min(large.max_object_bytes())
            .min(large.available_bytes());
        let fill_len = if fill_len >= full_len {
            full_len
        } else {
            (fill_len / chunk_bytes) * chunk_bytes
        };
        let fill_end = chunk_start.saturating_add(fill_len).saturating_sub(1);
        let mut fill = if fill_len > 0 {
            if let Some(decision) = decision {
                let hdrs = crate::cache::large::LargeCache::prune_uncacheable(&cache_headers);
                if let Some(writer) = large
                    .begin_chunk_range(
                        &native_plan.key,
                        200,
                        hdrs,
                        total,
                        chunk_start,
                        fill_end,
                        decision.ttl_secs,
                        decision.swr_secs,
                        chunk_bytes,
                    )
                    .await
                {
                    let budget = writer.fill_budget();
                    let (tx, queued, task) = spawn_range_writer(writer, Some(budget.clone()));
                    Some(RangeFillSink {
                        tx: Some(tx),
                        queued,
                        budget,
                        metrics: self.state.metrics.clone(),
                        queue_limit: self.state.large_cache_fill_queue_bytes,
                        offset: chunk_start,
                        end: fill_end,
                        task: Some(task),
                    })
                } else {
                    if fill_len > 0 {
                        self.state.metrics.record_chunk_fill_reject(fill_len);
                    }
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let Ok(mut response) =
            ResponseHeader::build(StatusCode::PARTIAL_CONTENT.as_u16(), Some(len as usize))
        else {
            return false;
        };
        for (name, value) in &cache_headers {
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
            .insert_header(
                "content-range",
                format!("bytes {client_start}-{client_end}/{total}"),
            )
            .is_err()
            || response
                .insert_header("content-length", len.to_string())
                .is_err()
            || response.insert_header("accept-ranges", "bytes").is_err()
            || response.insert_header("x-cache", "MISS").is_err()
            || response.insert_header("x-cache-status", "MISS").is_err()
            || response
                .insert_header("x-lagran-cache-source", "origin")
                .is_err()
            || response
                .insert_header("x-lagran-cache-reason", "range-chunk-fill")
                .is_err()
        {
            return false;
        }
        Self::apply_security_headers(&mut response);
        Self::apply_cors_and_custom(&mut response, &native_plan.domain.response_headers);
        let _ = response.insert_header("x-powered-by", "lagran-edge");
        if session
            .write_response_header(Box::new(response), false)
            .await
            .is_err()
        {
            return false;
        }

        let idle_timeout =
            Duration::from_millis(self.state.origin_stream_read_timeout_ms.max(1_000));
        let mut body = origin.body;
        let mut pos = chunk_start;
        while pos <= cache_end {
            let frame = match tokio::time::timeout(idle_timeout, body.frame()).await {
                Ok(Some(Ok(frame))) => frame,
                _ => {
                    tracing::warn!(key = %native_plan.key, "chunk-fill origin body ended early");
                    return true;
                }
            };
            let Ok(data) = frame.into_data() else {
                continue;
            };
            if data.is_empty() {
                continue;
            }
            let data_start = pos;
            let data_end = pos.saturating_add(data.len() as u64).saturating_sub(1);

            if let Some(fill) = fill.as_mut() {
                let fill_start = data_start.max(chunk_start);
                let fill_end_pos = data_end.min(fill_end);
                if fill_start <= fill_end_pos {
                    let from = (fill_start - data_start) as usize;
                    let to = (fill_end_pos - data_start + 1) as usize;
                    fill.push(&data[from..to]);
                }
            }

            let client_slice_start = data_start.max(client_start);
            let client_slice_end = data_end.min(client_end);
            if client_slice_start <= client_slice_end {
                let from = (client_slice_start - data_start) as usize;
                let to = (client_slice_end - data_start + 1) as usize;
                let done = client_slice_end == client_end;
                if session
                    .write_response_body(Some(Bytes::copy_from_slice(&data[from..to])), done)
                    .await
                    .is_err()
                {
                    return true;
                }
            }

            pos = data_end.saturating_add(1);
            if pos > cache_end {
                break;
            }
        }
        if let Some(fill) = fill.take() {
            fill.finish().await;
        }
        true
    }

    /// Serve a chunk-aligned plan.
    ///
    /// Cached runs are read from disk. Every origin run is exactly the missing
    /// chunk range (not the whole client range), is written back as whole
    /// chunks, and only the bytes inside the client range are sent downstream.
    #[allow(clippy::too_many_arguments)]
    async fn serve_large_range_chunks(
        &self,
        session: &mut Session,
        entry: &mut LargeEntry,
        chunk_plan: &ChunkPlan,
        start: u64,
        end: u64,
        total: u64,
        native_plan: &NativePlan,
    ) -> bool {
        let chunk_bytes = if entry.meta.chunk_bytes > 0 {
            entry.meta.chunk_bytes
        } else {
            self.state.large_cache_chunk_bytes
        };
        if chunk_bytes == 0 {
            return false;
        }
        let Some(large) = self.state.large_cache.as_ref() else {
            return false;
        };
        self.state.metrics.record_chunk_request();
        let origin_run_count = chunk_plan.runs.iter().filter(|run| !run.cached).count() as u64;
        self.state
            .metrics
            .record_chunk_origin_runs(origin_run_count);
        if entry.meta.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("content-encoding")
                && !value.eq_ignore_ascii_case("identity")
                && !value.is_empty()
        }) {
            return false;
        }
        let Some(first_origin) = chunk_plan.runs.iter().position(|run| !run.cached) else {
            return false;
        };
        let first_run = chunk_plan.runs[first_origin];
        let mut preopened = match self
            .open_chunk_origin(
                session,
                native_plan,
                entry,
                first_run.start,
                first_run.end,
                total,
            )
            .await
        {
            Ok(response) => Some(response),
            Err(invalidate) => {
                if invalidate {
                    let _ = large.delete(&native_plan.key).await;
                }
                return false;
            }
        };

        let len = end.saturating_sub(start).saturating_add(1);
        if len == 0 || len > usize::MAX as u64 {
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
                .insert_header("x-lagran-cache-reason", "range-chunks")
                .is_err()
        {
            return false;
        }
        Self::apply_security_headers(&mut response);
        Self::apply_cors_and_custom(&mut response, &native_plan.domain.response_headers);
        let _ = response.insert_header("x-powered-by", "lagran-edge");
        if entry.meta.stored_at > 0 {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let _ =
                response.insert_header("age", now.saturating_sub(entry.meta.stored_at).to_string());
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

        let idle_timeout =
            Duration::from_millis(self.state.origin_stream_read_timeout_ms.max(1_000));
        for (index, run) in chunk_plan.runs.iter().enumerate() {
            let client_start = run.start.max(start);
            let client_end = run.end.min(end);
            if client_start > client_end {
                continue;
            }
            let last_run = client_end == end;
            if run.cached {
                if !self
                    .write_large_body(session, entry, client_start, client_end, last_run)
                    .await
                {
                    return true;
                }
                continue;
            }

            let origin = if index == first_origin {
                match preopened.take() {
                    Some(origin) => origin,
                    None => return true,
                }
            } else {
                match self
                    .open_chunk_origin(session, native_plan, entry, run.start, run.end, total)
                    .await
                {
                    Ok(origin) => origin,
                    Err(invalidate) => {
                        if invalidate {
                            let _ = large.delete(&native_plan.key).await;
                        }
                        return true;
                    }
                }
            };

            let run_len = run.end.saturating_sub(run.start).saturating_add(1);
            let cap = large.fill_cap(total, self.state.large_cache_fill_max_bytes);
            let present = entry.meta.stored_bytes();
            let missing = entry.meta.missing_bytes(run.start, run.end);
            let wanted = if present.saturating_add(missing) <= cap {
                run_len
            } else {
                run_len.min(cap.saturating_sub(present))
            };
            let fill_len = if wanted >= run_len {
                run_len
            } else {
                (wanted / chunk_bytes) * chunk_bytes
            };
            let fill_len = fill_len
                .min(large.max_object_bytes())
                .min(large.available_bytes());
            let fill_len = if fill_len >= run_len {
                run_len
            } else {
                (fill_len / chunk_bytes) * chunk_bytes
            };
            let fill_end = run.start.saturating_add(fill_len).saturating_sub(1);
            let mut fill = if fill_len > 0 {
                let now = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let fresh_secs = entry.meta.fresh_until.saturating_sub(now).max(1);
                let swr_secs = entry
                    .meta
                    .stale_until
                    .saturating_sub(entry.meta.fresh_until);
                let hdrs = entry.meta.headers.clone();
                if let Some(writer) = large
                    .begin_chunk_range(
                        &native_plan.key,
                        200,
                        hdrs,
                        total,
                        run.start,
                        fill_end,
                        fresh_secs,
                        swr_secs,
                        chunk_bytes,
                    )
                    .await
                {
                    let budget = writer.fill_budget();
                    let (tx, queued, task) = spawn_range_writer(writer, Some(budget.clone()));
                    Some(RangeFillSink {
                        tx: Some(tx),
                        queued,
                        budget,
                        metrics: self.state.metrics.clone(),
                        queue_limit: self.state.large_cache_fill_queue_bytes,
                        offset: run.start,
                        end: fill_end,
                        task: Some(task),
                    })
                } else {
                    if fill_len > 0 {
                        self.state.metrics.record_chunk_fill_reject(fill_len);
                    }
                    None
                }
            } else {
                None
            };

            let mut body = origin.body;
            let mut pos = run.start;
            while pos <= run.end {
                let frame = match tokio::time::timeout(idle_timeout, body.frame()).await {
                    Ok(Some(Ok(frame))) => frame,
                    _ => {
                        tracing::warn!(key = %native_plan.key, "range chunk origin body ended early");
                        return true;
                    }
                };
                let Ok(data) = frame.into_data() else {
                    continue;
                };
                if data.is_empty() {
                    continue;
                }
                let data_start = pos;
                let data_end = pos.saturating_add(data.len() as u64).saturating_sub(1);

                if let Some(fill) = fill.as_mut() {
                    let fill_start = data_start.max(run.start);
                    let fill_end_pos = data_end.min(fill_end);
                    if fill_start <= fill_end_pos {
                        let from = (fill_start - data_start) as usize;
                        let to = (fill_end_pos - data_start + 1) as usize;
                        fill.push(&data[from..to]);
                    }
                }

                let client_slice_start = data_start.max(client_start);
                let client_slice_end = data_end.min(client_end);
                if client_slice_start <= client_slice_end {
                    let from = (client_slice_start - data_start) as usize;
                    let to = (client_slice_end - data_start + 1) as usize;
                    let done =
                        client_slice_end == end && index.saturating_add(1) == chunk_plan.runs.len();
                    if session
                        .write_response_body(Some(Bytes::copy_from_slice(&data[from..to])), done)
                        .await
                        .is_err()
                    {
                        return true;
                    }
                }

                pos = data_end.saturating_add(1);
                if pos > run.end {
                    break;
                }
            }
            if pos <= run.end {
                return true;
            }
            if let Some(fill) = fill.take() {
                fill.finish().await;
                // The next missing run needs the segments committed by this
                // run for its fill budget and chunk coverage.
                if let Some(fresh) = large.get_any(&native_plan.key).await {
                    entry.meta = fresh.meta;
                }
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
                let snaps = self.state.metrics.take_snapshots_peek();
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
                // Same exposition as the admin listener: the per-reason fallback
                // counters are what the migration is measured with.
                body.push_str(&self.state.metrics.legacy_fallbacks().prometheus_lines());
                // Origin configuration refusals are counted globally, not per domain:
                // they point at a control-plane input error, not at traffic shape.
                body.push_str(&format!(
                    "# HELP lagran_edge_config_errors_total Requests refused because the domain origin config is unusable\n\
                     # TYPE lagran_edge_config_errors_total counter\n\
                     lagran_edge_config_errors_total {}
",
                    self.state.metrics.config_errors(),
                ));
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
        // HEAD always advertises the length of the representation a GET would
        // return, for HTTP/1.1 as well as HTTP/2; the body itself stays empty.
        // Reporting 0 on H1 made `head-h2.sh` and browser preflights disagree
        // with the cached object they were describing.
        let len = if not_modified { 0 } else { entry.body.len() };
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
        apply_cors_and_custom(&mut headers, &plan.domain.response_headers);
        headers.insert(
            HeaderName::from_static("x-lagran-datapath"),
            HeaderValue::from_static("pingora"),
        );
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
            self.state.metrics.record_hit(&ctx.host, 0);
        } else {
            self.state.metrics.record_miss(&ctx.host, 0);
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

    async fn origin_order(&self, domain: &str, entry: &DomainEntry) -> Vec<String> {
        let mut fallback = Vec::new();
        if entry.origins.is_empty() {
            fallback.push(OriginTarget {
                url: entry.origin_url.clone(),
                weight: 100,
                priority: 0,
                enabled: true,
                host_header: None,
                sni: None,
            });
            if !entry.backup_origin_url.is_empty() {
                fallback.push(OriginTarget {
                    url: entry.backup_origin_url.clone(),
                    weight: 100,
                    priority: 1,
                    enabled: true,
                    host_header: None,
                    sni: None,
                });
            }
        }
        let pool: Vec<&OriginTarget> = if fallback.is_empty() {
            entry
                .origins
                .iter()
                .filter(|origin| origin.enabled)
                .collect()
        } else {
            fallback.iter().filter(|origin| origin.enabled).collect()
        };
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
                healthy.push(*origin);
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
            .map(|origin| origin.priority)
            .min()
            .unwrap_or_default();
        candidates.retain(|origin| origin.priority == min_priority);
        if candidates.is_empty() {
            return Vec::new();
        }

        let total: u64 = candidates
            .iter()
            .map(|origin| u64::from(origin.weight.max(1)))
            .sum();
        let seed = self
            .origin_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut slot = seed % total.max(1);
        let mut start = 0usize;
        for (index, origin) in candidates.iter().enumerate() {
            let weight = u64::from(origin.weight.max(1));
            if slot < weight {
                start = index;
                break;
            }
            slot -= weight;
        }
        (0..candidates.len())
            .map(|offset| candidates[(start + offset) % candidates.len()].url.clone())
            .collect()
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

    async fn handle_in_process(
        &self,
        session: &mut Session,
        preflight_done: bool,
        reason: LegacyFallback,
    ) -> Result<bool> {
        // Counted here, at the hand-off, so the reason is known. The engine itself
        // also counts `datapath_legacy_total`, which additionally covers direct
        // callers (cache diagnostics) that have no reason to report.
        self.state.metrics.record_legacy_fallback(reason);
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
        // The markers in this request were written by the filters above, so the
        // in-process handler must not strip them again.
        axum_req
            .extensions_mut()
            .insert(crate::server::host_util::FromPingora);
        if preflight_done {
            axum_req
                .extensions_mut()
                .insert(crate::server::host_util::PreflightDone);
        }

        let resp = proxy_handler(State(self.state.clone()), axum_req).await;
        write_axum_response(session, resp, is_head, Some(&self.compression)).await;
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

fn head_content_length_for_protocol(_is_h2: bool, body_len: usize) -> String {
    body_len.to_string()
}

/// Write an engine (axum) response straight to the downstream session.
///
/// `compression` is what makes the engine path honour `EDGE_COMPRESSION`. The
/// engine builds the response itself and never reaches `response_filter`, so
/// without this every request that falls back to the engine — an unregistered
/// domain, a rejected host, an error page — was served uncompressed no matter how
/// the edge was configured.
/// gzip a finished engine response body, or `None` to send it as-is.
///
/// Separated from `write_axum_response` so the decision *and* the encoding are
/// testable without a live `Session`. The engine path bypasses `response_filter`,
/// so this is the only place compression can happen for it.
#[allow(clippy::too_many_arguments)]
fn gzip_engine_body(
    cfg: &CompressionConfig,
    is_head: bool,
    version: http::Version,
    method: &http::Method,
    status: u16,
    response_headers: &http::HeaderMap,
    request_headers: &http::HeaderMap,
    body: &Bytes,
) -> Option<Bytes> {
    if is_head || body.is_empty() {
        return None;
    }
    if !should_compress(
        cfg,
        version,
        method,
        status,
        response_headers,
        request_headers,
    ) {
        return None;
    }
    let mut encoder = GzipEncoder::new(cfg.level);
    let head = encoder.write(body);
    let tail = encoder.finish();
    let mut out = BytesMut::with_capacity(head.len() + tail.len());
    out.extend_from_slice(&head);
    out.extend_from_slice(&tail);
    Some(out.freeze())
}

async fn write_axum_response(
    session: &mut Session,
    resp: axum::response::Response,
    is_head: bool,
    compression: Option<&CompressionConfig>,
) {
    let is_h2 = session.downstream_session.is_http2();
    let (mut parts, mut body) = resp.into_parts();
    if !parts.headers.contains_key("x-lagran-datapath") {
        parts.headers.insert(
            HeaderName::from_static("x-lagran-datapath"),
            HeaderValue::from_static("pingora"),
        );
    }
    let no_content =
        parts.status == StatusCode::NOT_MODIFIED || parts.status == StatusCode::NO_CONTENT;
    // Decide *before* touching the body. gzip needs the whole payload (the
    // encoder is one-shot) and HEAD must keep the advertised length, so those
    // stay buffered. Everything else is relayed frame by frame: collecting a
    // large media object here meant a downstream abort could not stop the copy,
    // the whole object was pinned in memory, and the access log billed bytes the
    // client never received (PERF-NEW-04).
    let request_version = session.req_header().version;
    let request_method = session.req_header().method.clone();
    let request_headers = session.req_header().headers.clone();
    let would_compress = compression.is_some_and(|cfg| {
        should_compress(
            cfg,
            request_version,
            &request_method,
            parts.status.as_u16(),
            &parts.headers,
            &request_headers,
        )
    });
    let exact_len = {
        use hyper::body::Body as _;
        body.size_hint().exact()
    };
    let body_is_empty = exact_len == Some(0);
    // HTTP/1.0 has no chunked framing, so an unknown-length body would have to be
    // delimited by closing the connection. Keep the previous buffered behaviour
    // for those clients instead of silently changing keep-alive semantics.
    let http10 = request_version == Version::HTTP_10;
    if !is_head && !no_content && !would_compress && !body_is_empty && !http10 {
        // Pass the known length down: a streamed response that advertises no
        // `Content-Length` can only be delimited by closing the connection, and on
        // a keep-alive session that leaves the client waiting for an EOF that never
        // arrives (this is what hung `waf.sh` on a 403 block page).
        write_engine_response_streamed(session, &parts, &mut body, exact_len).await;
        return;
    }
    let mut bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            tracing::warn!(error = %e, "collect engine response failed");
            let _ = session
                .respond_error_with_body(502, Bytes::from_static(b"engine response error"))
                .await;
            return;
        }
    };
    // gzip in the engine path. `should_compress` applies the same rules the
    // Pingora path uses (status, content type, size floor, Accept-Encoding), so the
    // two data planes agree on what gets compressed.
    if let Some(cfg) = compression {
        if let Some(compressed) = gzip_engine_body(
            cfg,
            is_head,
            request_version,
            &request_method,
            parts.status.as_u16(),
            &parts.headers,
            &request_headers,
            &bytes,
        ) {
            bytes = compressed;
            parts.headers.remove(axum::http::header::CONTENT_LENGTH);
            parts.headers.insert(
                axum::http::header::CONTENT_ENCODING,
                HeaderValue::from_static("gzip"),
            );
            // Caches must key on the encoding they were served.
            if !parts.headers.contains_key(axum::http::header::VARY) {
                parts.headers.insert(
                    axum::http::header::VARY,
                    HeaderValue::from_static("Accept-Encoding"),
                );
            }
        }
    }
    let body_len = bytes.len();
    // HEAD carries the length of the representation a GET would return. The
    // origin HEAD response already has it as a header; a cached GET response
    // stores it too. Only fall back to the buffered body length when the header
    // is absent.
    let representation_len = parts
        .headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(body_len);
    let head_content_length = if is_head {
        head_content_length_for_protocol(is_h2, representation_len)
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

/// Relay an engine response to the downstream without buffering it.
///
/// Used when the body cannot be compressed and its size is unknown: the large
/// media / event-stream case. No `Content-Length` is sent because the length is
/// only known after consuming the body, so HTTP/1.1 gets chunked framing and
/// HTTP/2 gets one DATA frame per chunk.
///
/// A downstream write error stops the copy immediately. That is what makes an
/// aborted download cheap: the origin body is dropped, and the access record
/// written by `StreamedAccess` reports only the bytes actually handed to the
/// client.
async fn write_engine_response_streamed(
    session: &mut Session,
    parts: &axum::http::response::Parts,
    body: &mut Body,
    exact_len: Option<u64>,
) {
    // `ResponseHeader::build` sizes the header from a `usize`; the body hint is a
    // `u64`. A body that does not fit in `usize` cannot be framed here anyway.
    let Ok(mut response) =
        ResponseHeader::build(parts.status.as_u16(), exact_len.map(|len| len as usize))
    else {
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
    if session
        .write_response_header(Box::new(response), false)
        .await
        .is_err()
    {
        return;
    }
    let mut written = 0usize;
    loop {
        let frame = match body.frame().await {
            Some(Ok(frame)) => frame,
            Some(Err(e)) => {
                tracing::debug!(error = %e, "engine response body failed mid-stream");
                break;
            }
            None => break,
        };
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if data.is_empty() {
            continue;
        }
        written += data.len();
        if session
            .write_response_body(Some(data), false)
            .await
            .is_err()
        {
            // The downstream is gone (client aborted). Do not drain the origin:
            // dropping the body lets the stream guard finalise the record with
            // the bytes delivered so far.
            return;
        }
    }
    // A `Content-Length` that does not match what the body produced would leave
    // the client waiting for the missing bytes, so make the mismatch loud.
    if let Some(expected) = exact_len {
        if written as u64 != expected {
            tracing::warn!(
                expected,
                written,
                "engine response body length does not match its size hint"
            );
        }
    }
    let _ = session.write_response_body(None, true).await;
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
        // A bounded Range larger than the cap is filled from its start up to
        // the cap. The client still receives the whole requested range; the
        // tail simply remains uncached until a later pass extends it.
        (
            fill_start,
            fill_start
                .saturating_add(max_fill_bytes)
                .saturating_sub(1)
                .min(total - 1),
        )
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

/// Parse a comma-separated Range request into satisfiable byte ranges.
///
/// Unsatifiable/invalid parts are ignored when at least one part is valid,
/// which matches RFC 9110's handling of a mixed Range set. Returns `None` when
/// no part is usable or the set is too large for the bounded multipart path.
fn parse_multi_ranges(raw: &str, total: u64) -> Option<Vec<(u64, u64)>> {
    if total == 0 {
        return None;
    }
    let value = raw.trim().strip_prefix("bytes=")?;
    if !value.contains(',') {
        return None;
    }
    let mut ranges = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let single = format!("bytes={part}");
        if let Some(range) = parse_single_range(&single, total) {
            ranges.push(range);
        }
    }
    if ranges.is_empty() || ranges.len() > MAX_MULTI_RANGES {
        return None;
    }
    Some(ranges)
}

/// Keep multipart fills narrow: merge overlapping/adjacent ranges and gaps of
/// at most two chunks, but leave wider gaps unfetched.
fn merge_multipart_spans(ranges: &[(u64, u64)], chunk_bytes: u64) -> Vec<(u64, u64)> {
    let mut sorted = ranges.to_vec();
    sorted.sort_unstable_by_key(|(start, _)| *start);
    let merge_gap = chunk_bytes.saturating_mul(2);
    let mut spans: Vec<(u64, u64)> = Vec::with_capacity(sorted.len());
    for (start, end) in sorted {
        if start > end {
            continue;
        }
        if let Some(last) = spans.last_mut() {
            // Merge when the ranges overlap or the gap is within the budget.
            if start <= last.1.saturating_add(merge_gap).saturating_add(1) {
                last.1 = last.1.max(end);
                continue;
            }
        }
        spans.push((start, end));
    }
    spans
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

/// Decide the `x-lagran-cache-source` value for a finished response.
///
/// A hit labelled without a source must say "unknown", not "l1". The previous
/// fallback claimed a local memory hit even when the storage layer was never
/// consulted — for example when the request fell back to the in-process engine —
/// which sent cache debugging down the wrong path.
fn resolve_cache_source(label: &str, header: Option<&str>) -> String {
    if matches!(label, "HIT" | "STALE" | "REVALIDATED") {
        header
            .map(str::to_string)
            .unwrap_or_else(|| CacheSource::Unknown.as_str().to_string())
    } else {
        "origin".to_string()
    }
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

/// Cache key for the pre-compressed variant of one object.
///
/// Embedding the validator means a changed object can never be served from a
/// stale compressed copy: the key changes with the ETag and the old variant
/// simply ages out.
fn compressed_variant_key(cache_key: &str, etag: &str) -> String {
    format!("{cache_key}\u{0}gzip\u{0}{etag}")
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

/// Whether the client asked for a revalidation instead of a cached copy.
///
/// `no-cache`, `max-age=0` and `Pragma: no-cache` all mean "check with the origin
/// before answering". Both the large-object revalidation path and the fallback
/// accounting use this one definition, so the two cannot disagree about which
/// requests are strict.
fn is_strict_revalidation(headers: &HeaderMap) -> bool {
    let cache_control = headers.get("cache-control").and_then(|v| v.to_str().ok());
    let strict_cc = cache_control.is_some_and(|value| {
        value.split(',').any(|part| {
            let part = part.trim();
            part.eq_ignore_ascii_case("no-cache") || part.eq_ignore_ascii_case("max-age=0")
        })
    });
    let strict_pragma = headers
        .get("pragma")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("no-cache"));
    strict_cc || strict_pragma
}

fn is_hop_by_hop(name: &str) -> bool {
    // `alt-svc` is not hop-by-hop by RFC, but this edge has no QUIC listener.
    // Passing the origin's `h3=":443"` through sends browsers to UDP/443, which
    // is closed here; some clients stall before falling back to h2.
    matches!(
        name,
        "connection"
            | "alt-svc"
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
/// A wildcard public bind already accepts loopback on the same port. A
/// concrete public address does not, so an explicit loopback listener is needed
/// for internal prefetch.
fn needs_loopback_listener(public: SocketAddr, local: SocketAddr) -> bool {
    !public.ip().is_unspecified() && public.ip() != local.ip()
}

fn prepare_proxy_headers(
    session: &mut Session,
    trust_proxy: bool,
    trusted: &crate::security::trusted_proxy::TrustedProxies,
    prefetch_token: &str,
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
    // The prefetch worker connects to the loopback listener and sets this
    // marker plus `x-forwarded-proto: https` when the domain enforces HTTPS.
    // It must not depend on TRUST_PROXY_HEADERS: that setting is for a real
    // external SLB, and its default `false` would rewrite the prefetch scheme
    // to http and trigger the 301 redirect this path exists to avoid.
    let internal_prefetch = peer.is_some_and(|addr| addr.ip().is_loopback())
        && req
            .headers
            .get("x-lagran-prefetch")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value == "1")
        && req
            .headers
            .get("x-lagran-prefetch-token")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value == prefetch_token);

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

    let identity = if internal_prefetch {
        // A loopback peer carrying the internal prefetch marker is this Edge's
        // own worker, not a public client. Preserve the HTTPS intent it came
        // with even when external proxy-trust is disabled.
        crate::security::trusted_proxy::ClientIdentity {
            ip: peer.map(|addr| addr.ip()),
            is_https: xfp.is_some_and(|proto| proto.trim().eq_ignore_ascii_case("https")),
            trusted_chain: true,
        }
    } else {
        crate::security::trusted_proxy::resolve(trusted, peer.copied(), xff, xfp, is_https)
    };

    let client_ip = identity.ip.map(|ip| ip.to_string()).unwrap_or_default();
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

    // HTTP/2 `:authority` is the authoritative host source. Synthesizing a
    // `Host` from SNI first would turn an IP SNI into a conflicting header and
    // make the authority guard reject a valid request.
    if !req.headers.contains_key("host") && req.uri.authority().is_none() {
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

    let local_http_addr = state.local_http_addr;
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
            // Reuse is only possible when the variant store has room.
            variant_max_object_bytes: if config.compressed_cache_bytes == 0
                || config.compressed_cache_entries == 0
            {
                0
            } else {
                config.compressed_cache_max_object_bytes
            },
            variant_ttl_secs: 300,
        },
    };
    match std::net::TcpListener::bind(&config.listen_addr) {
        Ok(probe) => drop(probe),
        Err(e) => anyhow::bail!("cannot bind EDGE_LISTEN {}: {e}", config.listen_addr),
    }
    let mut downstream_options = HttpServerOptions::default();
    downstream_options.keepalive_request_limit = Some(config.downstream_keepalive_requests);
    downstream_options.h2_idle_timeout = Some(Duration::from_secs(config.downstream_h2_idle_secs));
    let mut service = ProxyServiceBuilder::new(&server.configuration, proxy)
        .server_options(downstream_options)
        .build();
    service.add_tcp(&config.listen_addr);
    let public_addr: SocketAddr = config.listen_addr.parse()?;
    if needs_loopback_listener(public_addr, local_http_addr) {
        let local = local_http_addr.to_string();
        match std::net::TcpListener::bind(&local) {
            Ok(probe) => {
                drop(probe);
                service.add_tcp(&local);
                tracing::info!(listen = %local, "Pingora internal prefetch listener");
            }
            Err(error) => {
                // Do not abort the public listener if the loopback port is
                // occupied; prefetch will log its own connection failure.
                tracing::warn!(
                    listen = %local,
                    error = %error,
                    "could not bind internal prefetch listener"
                );
            }
        }
    }

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
        DataPlaneProxy, ResponsePolicySlot, cached_response_policy, compressed_variant_key,
        effective_connect_timeout_ms, fill_window, gzip_engine_body,
        head_content_length_for_protocol, is_strict_revalidation, merge_multipart_spans,
        needs_loopback_listener, parse_multi_ranges, parse_single_range,
        range_fill_is_candidate, valid_release_tag, vary_on_accept_encoding, weaken_etag,
    };
    use crate::cache::policy::ResolvedPolicy;
    use crate::server::response_headers::ResponseHeaderOverrides;
    use bytes::Bytes;
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

    /// The revalidation path and the fallback accounting share this predicate, so
    /// a request the edge treats as "check with the origin" is also the one counted
    /// as a strict-revalidation fallback when it cannot finish on Pingora.
    #[test]
    fn strict_revalidation_covers_the_three_client_headers() {
        let mut headers = axum::http::HeaderMap::new();
        assert!(!is_strict_revalidation(&headers), "no header is not strict");

        headers.insert("cache-control", "public, max-age=60".parse().unwrap());
        assert!(!is_strict_revalidation(&headers), "a positive TTL is not strict");

        headers.insert("cache-control", "no-cache".parse().unwrap());
        assert!(is_strict_revalidation(&headers));

        headers.insert("cache-control", "public, max-age=0".parse().unwrap());
        assert!(is_strict_revalidation(&headers));

        // A list may carry the directive anywhere, with any spacing or case.
        headers.insert("cache-control", "public, Max-Age=0, must-revalidate".parse().unwrap());
        assert!(is_strict_revalidation(&headers));

        headers.insert("cache-control", "no-store".parse().unwrap());
        headers.insert("pragma", "no-cache".parse().unwrap());
        assert!(is_strict_revalidation(&headers), "pragma counts on its own");

        headers.remove("pragma");
        assert!(!is_strict_revalidation(&headers), "no-store alone is not a revalidation");
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

    /// Variants are keyed by the identity key plus the validator: a changed
    /// object (new ETag) must never hit a stale compressed copy.
    #[test]
    fn compressed_variant_key_tracks_the_validator() {
        let a = compressed_variant_key("GET:a.test/x", "\"v1\"");
        let b = compressed_variant_key("GET:a.test/x", "\"v2\"");
        let other = compressed_variant_key("GET:b.test/x", "\"v1\"");
        assert_ne!(a, b, "a new ETag must produce a new variant key");
        assert_ne!(a, other, "different objects must not share a variant");
        assert!(a.starts_with("GET:a.test/x"));
        assert_eq!(a, compressed_variant_key("GET:a.test/x", "\"v1\""));
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
        let mut ctx = super::ReqCtx {
            origin_order: vec!["https://one.example".into(), "https://two.example".into()],
            current_addresses: vec![
                "192.0.2.1:443".parse().unwrap(),
                "192.0.2.2:443".parse().unwrap(),
            ],
            ..Default::default()
        };

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
    fn head_length_is_reported_for_both_protocols() {
        assert_eq!(head_content_length_for_protocol(true, 1234), "1234");
        assert_eq!(head_content_length_for_protocol(false, 1234), "1234");
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
            Some((0, max - 1))
        );
        assert_eq!(fill_window("bytes=0-", 0, max - 2, total, max), None);
    }

    #[test]
    fn fill_window_keeps_whole_object_when_cap_allows_it() {
        let total = 100 * 1024 * 1024;
        let cap = 256 * 1024 * 1024;
        assert_eq!(
            fill_window("bytes=0-", 0, total - 1, total, cap),
            Some((0, total - 1))
        );
        assert_eq!(
            fill_window("bytes=1024-", 1024, total - 1, total, cap),
            Some((1024, total - 1))
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
        assert_eq!(
            parse_multi_ranges("bytes=0-1,4-5", 4096),
            Some(vec![(0, 1), (4, 5)])
        );
        assert_eq!(
            parse_multi_ranges("bytes=-2,0-0", 4096),
            Some(vec![(4094, 4095), (0, 0)])
        );
        assert_eq!(
            parse_multi_ranges("bytes=0-1,5000-", 4096),
            Some(vec![(0, 1)])
        );
        assert_eq!(parse_multi_ranges("bytes=5000-,6000-", 4096), None);
        assert_eq!(parse_multi_ranges("bytes=0-1", 4096), None);
    }

    #[test]
    fn response_overrides_apply_in_place() {
        let mut response = ResponseHeader::build(200, None).unwrap();
        response.insert_header("x-origin", "keep").unwrap();
        response
            .insert_header("cache-control", "public, max-age=1")
            .unwrap();
        DataPlaneProxy::apply_browser_ttl(&mut response, Some(60));
        DataPlaneProxy::apply_security_headers(&mut response);
        DataPlaneProxy::apply_cors_and_custom(
            &mut response,
            &ResponseHeaderOverrides::parse("https://cdn.test", "X-Edge: lagran"),
        );

        assert_eq!(header_values(&response, "x-origin"), ["keep"]);
        assert_eq!(
            header_values(&response, "cache-control"),
            ["public, max-age=60"]
        );
        assert_eq!(header_values(&response, "x-frame-options"), ["SAMEORIGIN"]);
        assert_eq!(
            header_values(&response, "access-control-allow-origin"),
            ["https://cdn.test"]
        );
        assert_eq!(header_values(&response, "x-edge"), ["lagran"]);
    }

    #[test]
    fn response_policy_reuses_only_matching_content_type() {
        let policy = ResolvedPolicy {
            ttl_override: Some(42),
            ..Default::default()
        };
        let content_type = axum::http::HeaderValue::from_static("text/html; charset=utf-8");
        let slot = Some(ResponsePolicySlot {
            content_type: Some(content_type.clone()),
            policy,
        });
        assert_eq!(
            cached_response_policy(slot.as_ref(), Some(&content_type)),
            Some(policy)
        );
        let json = axum::http::HeaderValue::from_static("application/json");
        assert!(cached_response_policy(slot.as_ref(), Some(&json)).is_none());
    }

    #[test]
    fn downstream_disconnects_are_classified_as_cancellations() {
        let write =
            pingora::Error::explain(pingora::ErrorType::WriteError, "while writing h2 response")
                .into_down();
        assert!(super::is_downstream_disconnect(&write));

        let upstream =
            pingora::Error::explain(pingora::ErrorType::ReadError, "origin reset").into_up();
        assert!(!super::is_downstream_disconnect(&upstream));
    }
    /// A hit with no recorded source must report `unknown`. The old fallback
    /// claimed `l1`, which made a request that never consulted the storage layer
    /// look like a local memory hit.
    #[test]
    fn cache_source_reports_unknown_when_unrecorded() {
        assert_eq!(super::resolve_cache_source("HIT", None), "unknown");
        assert_eq!(super::resolve_cache_source("STALE", None), "unknown");
        assert_eq!(super::resolve_cache_source("REVALIDATED", None), "unknown");
        // Never claim l1 implicitly.
        assert_ne!(super::resolve_cache_source("HIT", None), "l1");
    }

    /// A recorded source is passed through untouched.
    #[test]
    fn cache_source_passes_through_recorded_value() {
        assert_eq!(super::resolve_cache_source("HIT", Some("l1")), "l1");
        assert_eq!(super::resolve_cache_source("HIT", Some("l2")), "l2");
        assert_eq!(super::resolve_cache_source("HIT", Some("l3")), "l3");
        assert_eq!(super::resolve_cache_source("STALE", Some("l2")), "l2");
    }

    /// Misses and bypasses are attributed to the origin regardless of any
    /// leftover header.
    #[test]
    fn non_hit_labels_report_origin() {
        for label in ["MISS", "BYPASS", "DYNAMIC", "NONE"] {
            assert_eq!(super::resolve_cache_source(label, None), "origin");
            assert_eq!(super::resolve_cache_source(label, Some("l2")), "origin");
        }
    }
    /// The engine path must actually produce gzip bytes, not just decide to.
    ///
    /// `write_axum_response` builds its own response and never reaches
    /// `response_filter`, so compression had to be applied there explicitly — and
    /// was missed, leaving every engine-served response uncompressed regardless of
    /// `EDGE_COMPRESSION`. This exercises the real entry point rather than the
    /// predicate, so deleting the call fails the test.
    #[test]
    fn engine_path_actually_gzips_eligible_bodies() {
        use crate::server::compression::CompressionConfig;

        let cfg = CompressionConfig {
            enabled: true,
            min_bytes: 100,
            level: 4,
            variant_max_object_bytes: 0,
            variant_ttl_secs: 0,
        };
        let body = Bytes::from(vec![b'x'; 8192]);

        let mut resp = http::HeaderMap::new();
        resp.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("text/html; charset=utf-8"),
        );
        resp.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("8192"),
        );
        let mut req = http::HeaderMap::new();
        req.insert(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip"),
        );

        let out = gzip_engine_body(
            &cfg,
            false,
            http::Version::HTTP_11,
            &http::Method::GET,
            200,
            &resp,
            &req,
            &body,
        )
        .expect("an eligible engine response must be gzipped");
        assert!(
            out.len() < body.len() / 10,
            "8192 repeated bytes should compress hard, got {}",
            out.len()
        );
        // gzip magic: 1f 8b
        assert_eq!(&out[..2], &[0x1f, 0x8b], "output must be a gzip stream");

        // A client without gzip gets the identity body.
        assert!(
            gzip_engine_body(
                &cfg,
                false,
                http::Version::HTTP_11,
                &http::Method::GET,
                200,
                &resp,
                &http::HeaderMap::new(),
                &body
            )
            .is_none(),
            "no Accept-Encoding means no compression"
        );

        // HEAD has no body to compress.
        assert!(
            gzip_engine_body(
                &cfg,
                true,
                http::Version::HTTP_11,
                &http::Method::HEAD,
                200,
                &resp,
                &req,
                &body
            )
            .is_none()
        );
    }

    #[test]
    fn multipart_spans_do_not_bridge_wide_gaps() {
        let chunk = 1024u64;
        let ranges = [(0u64, 10u64), (3 * chunk, 3 * chunk + 10)];
        assert_eq!(
            merge_multipart_spans(&ranges, chunk),
            vec![(0, 10), (3 * chunk, 3 * chunk + 10)]
        );
    }

    #[test]
    fn multipart_spans_merge_overlaps_and_small_gaps() {
        let chunk = 1024u64;
        let ranges = [(100u64, 200u64), (0, 50), (2 * chunk, 2 * chunk + 10)];
        assert_eq!(
            merge_multipart_spans(&ranges, chunk),
            vec![(0, 2 * chunk + 10)]
        );
    }

    #[test]
    fn multipart_spans_merge_overlapping_unsorted_ranges() {
        let ranges = [(150u64, 250u64), (0, 50), (100, 200)];
        assert_eq!(merge_multipart_spans(&ranges, 1024), vec![(0, 250)]);
    }

    #[test]
    fn multipart_spans_respect_the_two_chunk_gap() {
        let chunk = 1024u64;
        let end = 10u64;
        let at_limit = [(0u64, end), (end + 2 * chunk + 1, end + 2 * chunk + 20)];
        assert_eq!(
            merge_multipart_spans(&at_limit, chunk),
            vec![(0, end + 2 * chunk + 20)]
        );
        let over_limit = [(0u64, end), (end + 2 * chunk + 2, end + 2 * chunk + 20)];
        assert_eq!(
            merge_multipart_spans(&over_limit, chunk),
            vec![(0, end), (end + 2 * chunk + 2, end + 2 * chunk + 20)]
        );
    }

    #[test]
    fn multipart_spans_are_empty_for_no_ranges() {
        assert!(merge_multipart_spans(&[], 1024).is_empty());
    }

    #[test]
    fn internal_prefetch_listener_is_added_only_for_a_concrete_public_bind() {
        let loopback_v4: std::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let wildcard_v4: std::net::SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let public_v4: std::net::SocketAddr = "203.0.113.10:8080".parse().unwrap();
        let loopback_v6: std::net::SocketAddr = "[::1]:8080".parse().unwrap();
        let wildcard_v6: std::net::SocketAddr = "[::]:8080".parse().unwrap();
        let public_v6: std::net::SocketAddr = "[2001:db8::1]:8080".parse().unwrap();

        assert!(!needs_loopback_listener(wildcard_v4, loopback_v4));
        assert!(!needs_loopback_listener(loopback_v4, loopback_v4));
        assert!(needs_loopback_listener(public_v4, loopback_v4));
        assert!(!needs_loopback_listener(wildcard_v6, loopback_v6));
        assert!(needs_loopback_listener(public_v6, loopback_v6));
    }
}
