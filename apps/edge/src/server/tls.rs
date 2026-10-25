//! HTTPS terminator with SNI + hot-reloadable cert store

use crate::server::cert_store::CertStore;
use crate::server::host_util::TlsSni;
use anyhow::{anyhow, Context, Result};
use axum::extract::ConnectInfo;
use axum::http::header::HOST;
use axum::http::HeaderValue;
use axum::Router;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as HyperBuilder;
use rustls::ServerConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::Service;

pub fn build_server_config(store: Arc<CertStore>) -> Result<Arc<ServerConfig>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let resolver = store.resolver();
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    // Prefer HTTP/1.1 first — avoids empty Host edge cases with some h2 clients in local test
    config.alpn_protocols = vec![b"http/1.1".to_vec(), b"h2".to_vec()];
    Ok(Arc::new(config))
}

pub async fn serve_https(addr: SocketAddr, app: Router, store: Arc<CertStore>) -> Result<()> {
    let listener = TcpListener::bind(addr).await.context("bind https")?;
    tracing::info!(%addr, "HTTPS terminator listening (SNI + hot-reload)");

    let server_config = build_server_config(store)?;
    let acceptor = TlsAcceptor::from(server_config);
    let app = app.clone();

    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(%peer, error = %e, "TLS handshake failed");
                    return;
                }
            };

            // Capture SNI for domain routing (Host may be IP or missing on some clients)
            let sni = {
                let (_, conn) = tls_stream.get_ref();
                conn.server_name().map(|s| s.to_string())
            };
            if let Some(ref name) = sni {
                tracing::debug!(%peer, sni = %name, "TLS handshake ok");
            }

            let io = TokioIo::new(tls_stream);
            let hyper_service =
                hyper::service::service_fn(move |mut req: hyper::Request<Incoming>| {
                    let mut app = app.clone();
                    let sni = sni.clone();
                    async move {
                        // Expose the peer address to handlers (used for WAF IP ACLs).
                        req.extensions_mut().insert(ConnectInfo(peer));
                        if let Some(ref name) = sni {
                            req.extensions_mut().insert(TlsSni(name.clone()));
                            // If Host is missing or is a bare IP, set Host from SNI
                            // so downstream logic and caches key on the domain name
                            let host_is_bad = req
                                .headers()
                                .get(HOST)
                                .and_then(|v| v.to_str().ok())
                                .map(|h| {
                                    let h = h.trim();
                                    h.is_empty()
                                        || crate::config::registry::is_ip_host(h)
                                })
                                .unwrap_or(true);
                            if host_is_bad {
                                if let Ok(val) = HeaderValue::from_str(name) {
                                    req.headers_mut().insert(HOST, val);
                                }
                            }
                        }
                        app.call(req).await
                    }
                });
            let builder = HyperBuilder::new(TokioExecutor::new());
            if let Err(e) = builder.serve_connection(io, hyper_service).await {
                tracing::debug!(%peer, error = %e, "HTTPS connection error");
            }
        });
    }
}

pub async fn serve_http(addr: SocketAddr, app: Router) -> Result<()> {
    tracing::info!(%addr, "HTTP listening");
    let listener = TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| anyhow!("http server error: {e}"))?;
    Ok(())
}
