//! HTTPS terminator with SNI + hot-reloadable cert store

use crate::server::cert_store::CertStore;
use anyhow::{anyhow, Context, Result};
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

/// Build a rustls ServerConfig that resolves certs via SNI from CertStore.
pub fn build_server_config(store: Arc<CertStore>) -> Result<Arc<ServerConfig>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let resolver = store.resolver();
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Serve HTTPS; cert changes in CertStore apply to **new** connections immediately (no process restart).
pub async fn serve_https(addr: SocketAddr, app: Router, store: Arc<CertStore>) -> Result<()> {
    let listener = TcpListener::bind(addr).await.context("bind https")?;
    tracing::info!(%addr, "HTTPS terminator listening (SNI + hot-reload)");

    // Accept loop: rebuild acceptor from latest ServerConfig each connection is fine —
    // resolver reads store on each handshake so we only need one ServerConfig.
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
            let io = TokioIo::new(tls_stream);
            let hyper_service =
                hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                    let mut app = app.clone();
                    async move { app.call(req).await }
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
    axum::serve(listener, app)
        .await
        .map_err(|e| anyhow!("http server error: {e}"))?;
    Ok(())
}
