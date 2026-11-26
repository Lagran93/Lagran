//! HTTP helper for the optional admin listener.
//!
//! Public TLS is terminated by Pingora (`pingora_edge.rs`); the old
//! rustls/hyper HTTPS terminator has been removed.

use anyhow::{anyhow, bail, Context, Result};
use axum::Router;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

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

/// Serve the management router over TLS.
///
/// The listener owns the socket for the life of the process (the caller treats
/// a stop as an error), so connections are served on detached tasks and a
/// single bad handshake only closes that connection.
pub async fn serve_https(
    addr: SocketAddr,
    app: Router,
    cert_path: &str,
    key_path: &str,
) -> Result<()> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("invalid management TLS certificate/key: {e}"))?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    tracing::info!(%addr, "HTTPS management listener listening");
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (stream, _peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(stream).await else {
                return;
            };
            let service = hyper_util::service::TowerToHyperService::new(app);
            let io = hyper_util::rt::TokioIo::new(tls);
            if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                hyper_util::rt::TokioExecutor::new(),
            )
            .serve_connection_with_upgrades(io, service)
            .await
            {
                tracing::debug!(error = %e, "management TLS connection closed");
            }
        });
    }
}

fn load_certs(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let data = std::fs::read(path).with_context(|| format!("read TLS certificate {path}"))?;
    let mut reader = std::io::BufReader::new(&data[..]);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        bail!("TLS certificate {path} contains no certificates");
    }
    Ok(certs)
}

fn load_private_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let data = std::fs::read(path).with_context(|| format!("read TLS private key {path}"))?;
    let mut reader = std::io::BufReader::new(&data[..]);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("parse TLS private key {path}"))?
        .ok_or_else(|| anyhow!("TLS private key {path} contains no key"))
}
