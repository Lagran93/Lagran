//! Resolve request host from Host header, URI authority, SNI extension

use crate::config::registry::{is_ip_host, normalize_host};
use axum::http::Request;

/// Inserted by HTTPS acceptor when TLS SNI is present
#[derive(Clone, Debug)]
pub struct TlsSni(pub String);

/// Best-effort host for domain registry lookup.
pub fn resolve_request_host<B>(req: &Request<B>) -> String {
    // 1) Host header
    if let Some(h) = req
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
    {
        let n = normalize_host(h);
        if !n.is_empty() && !is_ip_host(&n) {
            return n;
        }
        // keep IP for later fallback display, but try better sources first
        if !n.is_empty() && is_ip_host(&n) {
            // continue to SNI / URI
        } else if !n.is_empty() {
            return n;
        }
    }

    // 2) URI authority (common for HTTP/2 :authority)
    if let Some(h) = req.uri().host() {
        let n = normalize_host(h);
        if !n.is_empty() && !is_ip_host(&n) {
            return n;
        }
    }

    // 3) TLS SNI (HTTPS only)
    if let Some(sni) = req.extensions().get::<TlsSni>() {
        let n = normalize_host(&sni.0);
        if !n.is_empty() {
            return n;
        }
    }

    // 4) Fall back to Host even if IP (so error page can show something)
    if let Some(h) = req
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
    {
        return normalize_host(h);
    }

    String::new()
}
