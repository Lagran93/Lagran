//! Pingora public listener + native data plane.
//!
//! Pingora owns public HTTP/HTTPS, HTTP/1.1+HTTP/2, TLS and connection
//! management. Cacheable GET/HEAD requests use `pingora-cache` with the
//! existing `SharedCache` as storage and `upstream_peer` for direct origin
//! access. Requests that need the legacy engine (WAF/CC/rate-limit/hotlink,
//! bypass/dynamic traffic, disk/hybrid cache, control endpoints and
//! WebSocket) are handed to the in-process handler.

use crate::cache::policy::{
    cache_key_for_request, compute_etag, decide_storage, has_non_clearance_cookie,
    resolve_rule_policy, resolve_rule_policy_for_response, ResolvedPolicy, RuleAction,
};
use crate::config::registry::DomainEntry;
use crate::config::EdgeConfig;
use crate::server::cert_store::CertStore;
use crate::server::challenge;
use crate::server::default_page::{self, OriginFailure};
use crate::server::handler::{
    apply_browser_ttl, apply_cors_and_custom, apply_security_headers, log_access,
    policy_browser_ttl, preflight_cacheable, proxy_handler, AppState,
};
use crate::server::native_cache::{leak_storage_with_limit, NativeStorage, META_HEADER};
use crate::server::purge;
use async_trait::async_trait;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri};
use axum::Json;
use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt;
use pingora::http::ResponseHeader;
use pingora::listeners::tls::TlsSettings;
use pingora::listeners::{TlsAccept, TlsAcceptCallbacks};
use pingora::protocols::tls::TlsRef;
use pingora::proxy::{http_proxy_service, FailToProxy, ProxyHttp, Session};
use pingora::server::Server;
use pingora::tls::{ext, pkey::PKey, ssl, x509::X509};
use pingora::upstreams::peer::HttpPeer;
use pingora::Result;
use pingora_cache::lock::CacheLock;
use pingora_cache::{
    CacheKey, CacheMeta, CacheOptionOverrides, CachePhase, ForcedFreshness, NoCacheReason,
    RespCacheable,
};

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
    origin_port: u16,
    origin_tls: bool,
    backup_url: String,
    timeout_ms: u64,
    policy: ResolvedPolicy,
    cors: String,
    custom: String,
    cacheable: bool,
    is_head: bool,
    is_websocket: bool,
    label: &'static str,
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
    status: u16,
    attempt: u8,
    response_bypass: bool,
    head_body: BytesMut,
    head_headers: Option<ResponseHeader>,
    head_status: u16,
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
            status: 0,
            attempt: 0,
            response_bypass: false,
            head_body: BytesMut::new(),
            head_headers: None,
            head_status: 0,
        }
    }
}

struct DataPlaneProxy {
    trust_proxy: bool,
    state: Arc<AppState>,
    native_cache: bool,
    storage: Option<&'static NativeStorage>,
    cache_lock: &'static CacheLock,
    management_on_data: bool,
}

#[async_trait]
impl ProxyHttp for DataPlaneProxy {
    type CTX = ReqCtx;

    fn new_ctx(&self) -> Self::CTX {
        ReqCtx::default()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        prepare_proxy_headers(session, self.trust_proxy)?;

        let req = session.req_header();
        ctx.host = request_host(req.headers.get("host").and_then(|v| v.to_str().ok()));
        ctx.path = req.uri.path().to_string();
        ctx.method = req.method.clone();
        ctx.client_ip = req
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
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

        let path = ctx.path.clone();
        let is_https = session
            .req_header()
            .headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("https"))
            .unwrap_or(false);
        if path == "/__lagran/health" {
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

        if let Some(plan) = self.native_plan(session).await {
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
            if let Some(resp) = preflight_cacheable(
                &self.state,
                &plan.domain,
                &ctx.method,
                &ctx.host,
                &ctx.path,
                &path_and_query,
                &headers,
                &ctx.client_ip,
                is_https,
                ctx.start,
            )
            .await
            {
                write_axum_response(session, resp, false).await;
                return Ok(true);
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
            ctx.plan = Some(plan);
            return Ok(false);
        }

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
        let response_policy = resolve_rule_policy_for_response(
            &plan.domain.rules,
            &ctx.path,
            ctx.method.as_str(),
            query,
            content_type,
        );
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
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let plan = ctx
            .plan
            .as_ref()
            .ok_or_else(|| pingora::Error::new_str("native plan missing"))?;
        let healthy = self.state.origin_health.is_healthy(&ctx.host).await;
        if !healthy && !plan.backup_url.is_empty() {
            tracing::warn!(domain = %ctx.host, backup = %plan.backup_url, "primary origin unhealthy; using backup");
            ctx.attempt = ctx.attempt.max(1);
        }
        let url = if ctx.attempt > 0 && !plan.backup_url.is_empty() {
            plan.backup_url.as_str()
        } else {
            if !healthy {
                tracing::warn!(domain = %ctx.host, "primary origin unhealthy; no backup configured");
            }
            // For the primary peer these cached values are already parsed.
            return self
                .peer_for(
                    &plan.origin_host,
                    plan.origin_port,
                    plan.origin_tls,
                    plan.timeout_ms,
                )
                .await;
        };
        let (host, port, tls) = parse_origin(url)
            .ok_or_else(|| pingora::Error::new_str("invalid backup origin URL"))?;
        self.peer_for(&host, port, tls, plan.timeout_ms).await
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
        e: Box<pingora::Error>,
    ) -> Box<pingora::Error> {
        let mut e = e;
        if ctx.attempt == 0 {
            if let Some(plan) = ctx.plan.as_ref() {
                if !plan.backup_url.is_empty() {
                    ctx.attempt = 1;
                    e.set_retry(true);
                }
            }
        }
        e
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora::http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if let Some(plan) = ctx.plan.as_ref() {
            // Keep HTTP Host aligned with the peer actually selected. The
            // previous code always sent the primary origin Host, so a backup
            // virtual host received the wrong site name.
            let host = if ctx.attempt > 0 && !plan.backup_url.is_empty() {
                parse_origin(&plan.backup_url)
                    .map(|(h, _, _)| h)
                    .unwrap_or_else(|| plan.origin_host.clone())
            } else {
                plan.origin_host.clone()
            };
            upstream_request.insert_header("host", host.as_str())?;
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
        let response_policy = resolve_rule_policy_for_response(
            &plan.domain.rules,
            &ctx.path,
            ctx.method.as_str(),
            query,
            content_type,
        );
        if response_policy.action != RuleAction::Cache {
            ctx.response_bypass = true;
            return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(
                "content-type rule",
            )));
        }
        let headers = header_vec(&resp.headers);
        let Some(decision) = decide_storage(
            resp.status.as_u16(),
            &headers,
            response_policy,
            self.state.default_ttl_secs,
        ) else {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(
                "cache policy",
            )));
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
        let content_type = response
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let query = session.req_header().uri.query().unwrap_or("");
        let response_policy = resolve_rule_policy_for_response(
            &plan.domain.rules,
            &ctx.path,
            ctx.method.as_str(),
            query,
            content_type,
        );
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
        response.remove_header(META_HEADER);
        response.insert_header("x-cache", label)?;
        response.insert_header("x-cache-status", label)?;
        response.insert_header("x-powered-by", "lagran-edge")?;

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
        if plan.is_head {
            // HEAD carries no downstream body. Keeping the origin GET's
            // Content-Length makes Pingora's H1 encoder wait for bytes that
            // will never be written; use zero so the header completes.
            let _ = response.remove_header("transfer-encoding");
            let _ = response.insert_header("content-length", "0");
            ctx.head_headers = Some(response.clone());
            ctx.head_status = response.status.as_u16();
        }
        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<Duration>> {
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
        let Some(plan) = ctx.plan.as_ref() else {
            return;
        };
        let status = session
            .response_written()
            .map(|r| r.status.as_u16())
            .unwrap_or(ctx.status);
        let bytes = session.body_bytes_sent() as u64;
        let label = ctx.cache_label;
        if plan.is_head && ctx.head_status == 200 && !ctx.head_body.is_empty() {
            if let Some(headers) = ctx.head_headers.as_ref() {
                let mut hdrs = header_vec(&headers.headers);
                hdrs.retain(|(k, _)| !k.eq_ignore_ascii_case("content-length"));
                hdrs.push((
                    "content-length".to_string(),
                    ctx.head_body.len().to_string(),
                ));
                if let Some(decision) = decide_storage(
                    ctx.head_status,
                    &hdrs,
                    plan.policy,
                    self.state.default_ttl_secs,
                ) {
                    if ctx.head_body.len() <= 8 * 1024 * 1024 {
                        let mut entry = crate::cache::CacheEntry {
                            status: ctx.head_status,
                            headers: hdrs,
                            body: ctx.head_body.clone().freeze(),
                            stored_at_epoch_secs: SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0),
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
            "HIT" => self.state.metrics.record_hit(&ctx.host, bytes).await,
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
        let host = request_host(req.headers.get("host").and_then(|v| v.to_str().ok()));
        if host.is_empty() {
            return None;
        }
        if !self.state.node_control.is_serving() {
            return None;
        }
        let domain = self.state.domains.get(&host).await?;
        let path = req.uri.path().to_string();
        let policy = resolve_rule_policy(
            &domain.rules,
            &path,
            req.method.as_str(),
            req.uri.query().unwrap_or(""),
        );
        let bypasses = request_bypasses(&req.headers, policy.ignore_cookie);
        let is_head = req.method == Method::HEAD && policy.action == RuleAction::Cache && !bypasses;
        let is_websocket = is_websocket_upgrade(&req.headers);
        let cacheable = req.method == Method::GET
            && policy.action == RuleAction::Cache
            && !is_websocket
            && !bypasses;
        let label = if cacheable || is_head {
            "MISS"
        } else if policy.action == RuleAction::Bypass || req.method == Method::GET {
            "BYPASS"
        } else {
            "DYNAMIC"
        };
        let (origin_host, origin_port, origin_tls) = parse_origin(&domain.origin_url)?;
        let ignore_query = policy.ignore_query.unwrap_or(domain.ignore_query_string);
        let lookup_path = if ignore_query {
            path
        } else {
            req.uri
                .path_and_query()
                .map(|p| p.as_str().to_string())
                .unwrap_or_else(|| "/".to_string())
        };
        let key_method = if is_head {
            Method::GET
        } else {
            req.method.clone()
        };
        let key = cache_key_for_request(&key_method, &host, &lookup_path, &req.headers);
        Some(NativePlan {
            domain: domain.clone(),
            key,
            origin_host,
            origin_port,
            origin_tls,
            backup_url: domain.backup_origin_url.clone(),
            timeout_ms: u64::from(if domain.origin_timeout_ms == 0 {
                10_000
            } else {
                domain.origin_timeout_ms
            }),
            policy,
            cors: domain.cors_origins.clone(),
            custom: domain.custom_headers.clone(),
            cacheable,
            is_head,
            is_websocket,
            label,
        })
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
                    Err(_) => {
                        write_plain(
                            session,
                            400,
                            "text/plain; charset=utf-8",
                            Bytes::from_static(b"bad request"),
                        )
                        .await;
                        return Ok(true);
                    }
                };
                let Json(resp) = purge::purge_handler(State(self.state.clone()), Json(req)).await;
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
            ("POST", "/__lagran/config/reload") => {
                crate::agent::config_sync::request_config_reload();
                write_json(session, 200, &serde_json::json!({ "ok": true, "reloading": true })).await;
            }
            ("GET", "/__lagran/metrics") => {
                let snaps = self.state.metrics.take_snapshots_peek().await;
                let mut body = String::from("# TYPE lagran_edge_requests_total counter\n");
                for s in snaps {
                    body.push_str(&format!(
                        "lagran_edge_requests_total{{domain=\"{d}\"}} {v}\nlagran_edge_cache_hits_total{{domain=\"{d}\"}} {h}\nlagran_edge_cache_misses_total{{domain=\"{d}\"}} {m}\n",
                        d = s.domain.replace('"', ""),
                        v = s.requests,
                        h = s.cache_hits,
                        m = s.cache_misses,
                    ));
                }
                write_plain(session, 200, "text/plain; version=0.0.4; charset=utf-8", Bytes::from(body)).await;
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
        let len = if not_modified { 0 } else { entry.body.len() };
        let mut headers = HeaderMap::new();
        for (name, value) in &entry.headers {
            if name.eq_ignore_ascii_case(META_HEADER)
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

    async fn peer_for(
        &self,
        host: &str,
        port: u16,
        tls: bool,
        timeout_ms: u64,
    ) -> Result<Box<HttpPeer>> {
        // HttpPeer::new() unwraps DNS resolution in Pingora 0.9 and panics on
        // NXDOMAIN. Resolve here so a dead/misconfigured origin becomes a
        // normal 502 page instead of taking the Pingora service down.
        let addr = tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| {
                pingora::Error::because(
                    pingora::ErrorType::ConnectError,
                    "resolve origin address",
                    e,
                )
            })?
            .next()
            .ok_or_else(|| pingora::Error::new_str("origin DNS returned no addresses"))?;
        // Passing a resolved SocketAddr avoids the panicking DNS path.
        let mut peer = HttpPeer::new(addr, tls, host.to_string());
        peer.options.connection_timeout = Some(Duration::from_millis(timeout_ms));
        peer.options.read_timeout = Some(Duration::from_millis(timeout_ms));
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

        let resp = proxy_handler(State(self.state.clone()), axum_req).await;
        write_axum_response(session, resp, is_head).await;
        Ok(true)
    }
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

async fn write_axum_response(session: &mut Session, resp: axum::response::Response, is_head: bool) {
    let (parts, body) = resp.into_parts();
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
    let head_content_length = parts
        .headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| "0".to_string());
    let bytes = if is_head { Bytes::new() } else { bytes };
    let end_of_stream = bytes.is_empty();
    let Ok(mut response) = ResponseHeader::build(parts.status.as_u16(), Some(bytes.len())) else {
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
    if is_head || end_of_stream {
        let value = if is_head {
            head_content_length.as_str()
        } else {
            "0"
        };
        if response.insert_header("content-length", value).is_err() {
            return;
        }
    }
    let _ = session
        .write_response_header(Box::new(response), end_of_stream)
        .await;
    if !end_of_stream {
        let _ = session.write_response_body(Some(bytes), true).await;
    }
}

fn request_bypasses(headers: &HeaderMap, ignore_cookie: bool) -> bool {
    if headers.contains_key("authorization")
        || (!ignore_cookie && has_non_clearance_cookie(headers))
    {
        return true;
    }
    // `no-cache`/`max-age=0` mean "revalidate", not "skip the cache". Keep the
    // request cache-eligible so If-None-Match can produce REVALIDATED/304.
    // Only `no-store` genuinely forbids using or storing a cache entry.
    if let Some(cc) = headers.get("cache-control").and_then(|v| v.to_str().ok()) {
        if cc.to_ascii_lowercase().contains("no-store") {
            return true;
        }
    }
    false
}

fn request_host(raw: Option<&str>) -> String {
    let Some(raw) = raw else {
        return String::new();
    };
    let raw = raw.trim();
    if raw.starts_with('[') {
        return raw
            .split_once(']')
            .map(|(h, _)| format!("{h}]"))
            .unwrap_or_else(|| raw.to_string())
            .to_ascii_lowercase();
    }
    raw.split(':').next().unwrap_or(raw).to_ascii_lowercase()
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

fn prepare_proxy_headers(session: &mut Session, trust_proxy: bool) -> Result<()> {
    let client_ip = session
        .client_addr()
        .and_then(|addr| addr.as_inet())
        .map(|addr| addr.ip().to_string())
        .unwrap_or_default();
    let is_https = session
        .digest()
        .and_then(|d| d.ssl_digest.as_ref())
        .is_some();
    let sni = session
        .digest()
        .and_then(|d| d.ssl_digest.as_ref())
        .and_then(|d| d.extension.get::<Sni>())
        .map(|s| s.0.clone());

    let req = session.req_header_mut();
    let has_xff = req.headers.contains_key("x-forwarded-for");
    if !trust_proxy || !has_xff {
        req.remove_header("x-forwarded-for");
        if !client_ip.is_empty() {
            req.insert_header("x-forwarded-for", client_ip.as_str())?;
        }
    }
    if !trust_proxy {
        req.remove_header("x-real-ip");
    }
    if !client_ip.is_empty() && !req.headers.contains_key("x-real-ip") {
        req.insert_header("x-real-ip", client_ip.as_str())?;
    }
    if !trust_proxy || !req.headers.contains_key("x-forwarded-proto") {
        req.remove_header("x-forwarded-proto");
        req.insert_header("x-forwarded-proto", if is_https { "https" } else { "http" })?;
    }
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
    let opt = pingora::server::configuration::Opt::parse_args();
    let mut server = Server::new(Some(opt))?;
    server.bootstrap();

    let storage = Some(leak_storage_with_limit(state.cache.clone(), state.max_cacheable_body));
    let cache_lock: &'static CacheLock = Box::leak(CacheLock::new_boxed(Duration::from_secs(10)));
    let proxy = DataPlaneProxy {
        trust_proxy: config.trust_proxy_headers,
        state,
        native_cache: storage.is_some(),
        storage,
        cache_lock,
        management_on_data: config.admin_listen_addr.is_none(),
    };
    match std::net::TcpListener::bind(&config.listen_addr) {
        Ok(probe) => drop(probe),
        Err(e) => anyhow::bail!("cannot bind EDGE_LISTEN {}: {e}", config.listen_addr),
    }
    let mut service = http_proxy_service(&server.configuration, proxy);
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
