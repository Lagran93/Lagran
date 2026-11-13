//! Resolve request host from Host header, URI authority, SNI extension

use crate::config::registry::{is_ip_host, normalize_host};
use axum::http::Request;

/// Host/authority source for registry and cache-key lookups.
///
/// `uri.authority()` is the `:authority` pseudo-header on HTTP/2. It is the
/// authoritative value there, while a reverse proxy may still forward a
/// separate `Host` header. HTTP/1 uses the same precedence only when the target
/// is absolute-form; origin-form H1 requests have no URI authority.
pub fn request_authority<B>(req: &Request<B>) -> Option<&str> {
    req.uri()
        .authority()
        .map(|authority| authority.as_str())
        .or_else(|| {
            req.headers()
                .get(axum::http::header::HOST)
                .and_then(|value| value.to_str().ok())
        })
}

/// Normalize a request authority and Host pair.
///
/// The URI authority is the HTTP/2 `:authority` pseudo-header and takes
/// precedence. `Host` remains the fallback for HTTP/1 requests and for peers
/// that deliberately forward it separately.
pub fn normalized_authority_host(authority: Option<&str>, host: Option<&str>) -> String {
    normalized_host_candidates(authority, host, None)
}

/// Choose a registry host from an HTTP authority, `Host` header and TLS SNI.
///
/// A name is always preferred over an IP literal: CDN origins are commonly
/// addressed by IP while SNI carries the public domain that must select the
/// domain configuration.
pub fn normalized_host_candidates(
    authority: Option<&str>,
    host: Option<&str>,
    tls_sni: Option<&str>,
) -> String {
    let mut ip_fallback = None;
    for candidate in [authority, host, tls_sni] {
        let Some(raw) = candidate else {
            continue;
        };
        let normalized = normalize_host(raw);
        if normalized.is_empty() {
            continue;
        }
        if is_ip_host(&normalized) {
            ip_fallback.get_or_insert(normalized);
        } else {
            return normalized;
        }
    }
    ip_fallback.unwrap_or_default()
}

/// Normalized host for registry lookups, shared by both data planes.
///
/// Picks the first usable non-IP value from HTTP/2 `:authority`, `Host` and TLS
/// SNI, then falls back to the original values for error pages.
pub fn normalized_request_host<B>(req: &Request<B>, tls_sni: Option<&str>) -> String {
    let (authority, host) = request_host_parts(req);
    normalized_host_candidates(authority, host, tls_sni)
}

/// Raw authority sources in precedence order.
///
/// HTTP/2 carries the host in `:authority`; Pingora retains it on `uri` but
/// does not synthesize a `Host` header. Other requests carry `Host` directly.
pub fn request_host_parts<B>(req: &Request<B>) -> (Option<&str>, Option<&str>) {
    (
        req.uri().authority().map(|authority| authority.as_str()),
        req.headers()
            .get(axum::http::header::HOST)
            .and_then(|value| value.to_str().ok()),
    )
}

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

/// Set when the Pingora data plane forwards into the in-process handler.
///
/// The two planes share `proxy_handler`, so it cannot tell them apart on its
/// own. Headers the Pingora filter already sanitised and populated (the signed
/// URL marker in particular) must survive that hand-off, while a request that
/// arrives directly from a client must have them stripped.
#[derive(Clone, Copy, Debug)]
pub struct FromPingora;

/// Set when the Pingora data plane already ran the shared preflight
/// (WAF / CC / rate limit / hotlink / HTTPS redirect) for this request.
///
/// The in-process fallback shares `proxy_handler` with the direct path, and
/// that function runs preflight itself. Without this marker every HEAD request
/// or native-plan fallback would be checked twice, charging CC and rate-limit
/// budget twice for one client request.
#[derive(Clone, Copy, Debug)]
pub struct PreflightDone;

/// Whether this request arrived over TLS, from either data plane.
pub fn request_is_tls<B>(req: &Request<B>) -> bool {
    req.extensions().get::<TlsSni>().is_some() || req.extensions().get::<TlsTerminated>().is_some()
}

/// Best-effort host for domain registry lookup.
pub fn resolve_request_host<B>(req: &Request<B>) -> String {
    if req.version() == axum::http::Version::HTTP_2 {
        let sni = req.extensions().get::<TlsSni>().map(|sni| sni.0.as_str());
        return normalized_request_host(req, sni);
    }
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
    fn h2_authority_is_preferred_and_normalized() {
        let req = Request::builder()
            .version(axum::http::Version::HTTP_2)
            .uri("https://hit.test:18443/small")
            .header(axum::http::header::HOST, "hit.test")
            .body(Body::empty())
            .unwrap();
        assert_eq!(resolve_request_host(&req), "hit.test");

        let absolute = Request::builder()
            .uri("https://cdn.example.com:8443/a")
            .body(Body::empty())
            .unwrap();
        assert_eq!(resolve_request_host(&absolute), "cdn.example.com");
    }

    #[test]
    fn h2_sni_is_used_when_authority_is_an_ip() {
        let mut req = Request::builder()
            .version(axum::http::Version::HTTP_2)
            .uri("https://127.0.0.1:18443/a")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(TlsSni("cdn.example.com".into()));
        assert_eq!(resolve_request_host(&req), "cdn.example.com");
    }

    #[test]
    fn request_authority_prefers_uri_authority() {
        let req = Request::builder()
            .version(axum::http::Version::HTTP_2)
            .uri("https://hit.test:18443/small")
            .header(axum::http::header::HOST, "hit.test")
            .body(Body::empty())
            .unwrap();
        assert_eq!(request_authority(&req), Some("hit.test:18443"));
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
