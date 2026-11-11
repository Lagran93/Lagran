//! Resolve request host from Host header, URI authority, SNI extension

use crate::config::registry::{is_ip_host, normalize_host};
use axum::http::Request;

/// Inserted by HTTPS acceptor when TLS SNI is present
#[derive(Clone, Debug)]
pub struct TlsSni(pub String);

/// Marker for an in-process request whose downstream TLS was terminated by the
/// Pingora listener.
///
/// When Pingora hands a request to the legacy handler it does not carry a TLS
/// extension and the socket peer is the real client (not a trusted proxy), so
/// `X-Forwarded-Proto` is deliberately ignored. Without this marker the handler
/// would classify an HTTPS request as plaintext and answer it with an HTTPS
/// redirect to the URL that was already served over TLS.
#[derive(Clone, Copy, Debug)]
pub struct TlsTerminated;

/// Whether this request arrived over TLS, from either data plane.
pub fn request_is_tls<B>(req: &Request<B>) -> bool {
    req.extensions().get::<TlsSni>().is_some()
        || req.extensions().get::<TlsTerminated>().is_some()
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    fn request() -> Request<Body> {
        Request::builder()
            .uri("https://example.com/a.js")
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn tls_is_detected_from_either_data_plane() {
        let mut plain = request();
        assert!(!request_is_tls(&plain));

        // Axum TLS listener.
        plain.extensions_mut().insert(TlsSni("example.com".into()));
        assert!(request_is_tls(&plain));

        // Pingora in-process handoff: no SNI extension is available, but the
        // connection was TLS. Losing this flag made the HTTPS redirect fire on
        // requests that already arrived over HTTPS.
        let mut in_process = request();
        in_process.extensions_mut().insert(TlsTerminated);
        assert!(request_is_tls(&in_process));
    }
}
