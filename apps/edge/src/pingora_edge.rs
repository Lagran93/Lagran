//! Pingora public listener/proxy.
//!
//! Pingora owns the public HTTP/HTTPS listeners, HTTP/1.1+HTTP/2 protocol
//! handling, TLS termination and connection management. The existing Lagran
//! data-plane engine (cache, WAF, CC, origin failover, ACME, websocket) runs on
//! a loopback-only Axum listener and is reached through Pingora. This keeps the
//! feature set identical while moving the public network edge to Pingora.

use crate::config::EdgeConfig;
use crate::server::cert_store::CertStore;
use async_trait::async_trait;
use pingora::http::RequestHeader;
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

struct InternalProxy {
    upstream: SocketAddr,
    /// Preserve a trusted upstream proxy's X-Forwarded-For instead of
    /// overwriting it with Pingora's peer address.
    trust_proxy: bool,
}

#[async_trait]
impl ProxyHttp for InternalProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

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

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        let client_ip = session
            .client_addr()
            .and_then(|addr| addr.as_inet())
            .map(|addr| addr.ip().to_string())
            .unwrap_or_default();
        // With TRUST_PROXY_HEADERS=true the operator has explicitly placed a
        // trusted proxy in front; preserve its X-Forwarded-For. Otherwise
        // overwrite any client-supplied value with the real peer address.
        let has_xff = upstream_request.headers.contains_key("x-forwarded-for");
        if !self.trust_proxy || !has_xff {
            upstream_request.remove_header("x-forwarded-for");
            if !client_ip.is_empty() {
                upstream_request.insert_header("x-forwarded-for", client_ip.as_str())?;
            }
        }
        if !self.trust_proxy {
            upstream_request.remove_header("x-real-ip");
        }
        if !client_ip.is_empty() && !upstream_request.headers.contains_key("x-real-ip") {
            upstream_request.insert_header("x-real-ip", client_ip.as_str())?;
        }

        let is_https = session
            .digest()
            .and_then(|d| d.ssl_digest.as_ref())
            .is_some();
        if !self.trust_proxy || !upstream_request.headers.contains_key("x-forwarded-proto") {
            upstream_request.remove_header("x-forwarded-proto");
            upstream_request
                .insert_header("x-forwarded-proto", if is_https { "https" } else { "http" })?;
        }
        upstream_request.insert_header("x-lagran-pingora", "1")?;

        // Some HTTP/1.0 clients omit Host. Recover it from SNI.
        if !upstream_request.headers.contains_key("host") {
            let sni = session
                .digest()
                .and_then(|d| d.ssl_digest.as_ref())
                .and_then(|d| d.extension.get::<Sni>())
                .map(|s| s.0.clone());
            if let Some(sni) = sni {
                upstream_request.insert_header("host", sni.as_str())?;
            }
        }
        Ok(())
    }
}

/// Run the Pingora public listener. `upstream` is the loopback Axum engine.
pub fn run(config: EdgeConfig, upstream: SocketAddr, certs: Arc<CertStore>) -> anyhow::Result<()> {
    let opt = pingora::server::configuration::Opt::parse_args();
    let mut server = Server::new(Some(opt))?;
    server.bootstrap();

    let proxy = InternalProxy {
        upstream,
        trust_proxy: config.trust_proxy_headers,
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
