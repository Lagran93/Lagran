//! Pingora public listener + in-process data plane.
//!
//! Pingora owns the public HTTP/HTTPS listeners, HTTP/1.1+HTTP/2 protocol
//! handling, TLS termination and connection management. Normal requests are
//! handed to the existing Lagran engine **in-process** through
//! `handler::proxy_handler`; there is no loopback hop. Only rare control
//! endpoints (health/challenge/ACME/admin) and WebSocket upgrades use a
//! loopback Axum router for compatibility.

use crate::config::EdgeConfig;
use crate::server::cert_store::CertStore;
use crate::server::handler::{proxy_handler, AppState};
use async_trait::async_trait;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{Method, Request, StatusCode, Uri};
use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt;
use pingora::http::ResponseHeader;
use pingora::listeners::tls::TlsSettings;
use pingora::listeners::{TlsAccept, TlsAcceptCallbacks};
use pingora::protocols::tls::TlsRef;
use pingora::proxy::{http_proxy_service, ProxyHttp, Session};
use pingora::server::Server;
use pingora::tls::{ext, pkey::PKey, ssl, x509::X509};
use pingora::upstreams::peer::HttpPeer;
use pingora::Result;
use std::net::SocketAddr;
use std::sync::Arc;

/// Keep in sync with `handler::MAX_PROXY_BODY`.
const MAX_PROXY_BODY: usize = 16 * 1024 * 1024;

/// SNI captured after the TLS handshake and exposed through Pingora's digest.
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

struct DataPlaneProxy {
    /// Loopback Axum fallback for control endpoints and WebSocket upgrades.
    upstream: SocketAddr,
    trust_proxy: bool,
    state: Arc<AppState>,
}

#[async_trait]
impl ProxyHttp for DataPlaneProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        prepare_proxy_headers(session, self.trust_proxy)?;

        if needs_loopback(session) {
            return Ok(false);
        }

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
        let (parts, body) = resp.into_parts();
        let bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                tracing::warn!(error = %e, "collect engine response failed");
                session
                    .respond_error_with_body(502, Bytes::from_static(b"engine response error"))
                    .await?;
                return Ok(true);
            }
        };

        let head_content_length = parts
            .headers
            .get(axum::http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("0")
            .to_string();
        let bytes = if is_head { Bytes::new() } else { bytes };
        let end_of_stream = bytes.is_empty();
        let mut response = ResponseHeader::build(parts.status.as_u16(), Some(bytes.len()))?;
        for (name, value) in parts.headers.iter() {
            if is_hop_by_hop(name.as_str()) || name == axum::http::header::CONTENT_LENGTH {
                continue;
            }
            response.append_header(name.clone(), value.clone())?;
        }
        if is_head || end_of_stream {
            // HEAD has no body, and a bodyless 200 must still carry a length or
            // clients wait for connection close.
            response.insert_header(
                "content-length",
                if is_head {
                    head_content_length.as_str()
                } else {
                    "0"
                },
            )?;
        }
        session
            .write_response_header(Box::new(response), end_of_stream)
            .await?;
        if !end_of_stream {
            session.write_response_body(Some(bytes), true).await?;
        }
        Ok(true)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        Ok(Box::new(HttpPeer::new(
            self.upstream,
            false,
            "lagran-internal".to_string(),
        )))
    }
}

fn needs_loopback(session: &Session) -> bool {
    let req = session.req_header();
    let path = req.uri.path();
    if path.starts_with("/__lagran/") || path.starts_with("/.well-known/acme-challenge/") {
        return true;
    }
    let upgrade = req
        .headers
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    let connection_upgrade = req
        .headers
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

/// Add trusted client addressing before either the in-process engine or the
/// loopback control router sees the request.
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
pub fn run(
    config: EdgeConfig,
    upstream: SocketAddr,
    certs: Arc<CertStore>,
    state: Arc<AppState>,
) -> anyhow::Result<()> {
    let opt = pingora::server::configuration::Opt::parse_args();
    let mut server = Server::new(Some(opt))?;
    server.bootstrap();

    let proxy = DataPlaneProxy {
        upstream,
        trust_proxy: config.trust_proxy_headers,
        state,
    };
    // Fail fast with a useful error instead of Pingora's listener panic.
    match std::net::TcpListener::bind(&config.listen_addr) {
        Ok(probe) => drop(probe),
        Err(e) => anyhow::bail!("cannot bind EDGE_LISTEN {}: {e}", config.listen_addr),
    }
    let mut service = http_proxy_service(&server.configuration, proxy);
    service.add_tcp(&config.listen_addr);

    if let Some(ref https) = config.https_listen_addr {
        // Do not add an HTTPS listener that cannot bind; Pingora treats a bind
        // failure as fatal for the whole service, which would also kill HTTP.
        match std::net::TcpListener::bind(https) {
            Ok(probe) => drop(probe),
            Err(e) => {
                tracing::error!(listen = %https, error = %e, "HTTPS listener unavailable; continuing with HTTP only");
                tracing::info!(listen = %config.listen_addr, upstream = %upstream, "Pingora HTTP listener");
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
    tracing::info!(listen = %config.listen_addr, upstream = %upstream, "Pingora HTTP listener");

    server.add_service(service);
    server.run_forever();
}
