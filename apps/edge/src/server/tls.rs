//! HTTP helper for the optional admin listener.
//!
//! Public TLS is terminated by Pingora (`pingora_edge.rs`); the old
//! rustls/hyper HTTPS terminator has been removed.

use anyhow::{anyhow, Result};
use axum::Router;
use std::net::SocketAddr;
use tokio::net::TcpListener;

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
