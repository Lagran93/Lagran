//! Helpers shared by both data planes.
//!
//! Everything here used to live in `server::handler`. The legacy handler and the
//! Pingora data plane both call these, so keeping them next to the legacy code
//! forced `pingora_edge.rs` to import from `server::handler`. Nothing in this
//! module depends on the legacy handler.

use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::cache::policy::{ResolvedPolicy, RuleAction};
use crate::server::access_log::AccessLog;
use crate::server::response_headers::ResponseHeaderOverrides;

pub(crate) fn policy_browser_ttl(policy: &ResolvedPolicy) -> Option<u64> {
    if policy.action == RuleAction::Cache {
        policy.browser_ttl_secs
    } else {
        None
    }
}

pub(crate) fn apply_browser_ttl(headers: &mut HeaderMap, ttl: Option<u64>) {
    let Some(ttl) = ttl.filter(|t| *t > 0) else {
        return;
    };
    // Never override an explicit "do not cache" signal from the origin, and
    // never make a response with Set-Cookie client-cacheable.
    if headers.contains_key(header::SET_COOKIE) {
        return;
    }
    if let Some(cc) = headers
        .get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
    {
        let cc = cc.to_ascii_lowercase();
        if cc.contains("no-store") || cc.contains("private") {
            return;
        }
    }
    if let Ok(v) = HeaderValue::from_str(&format!("public, max-age={ttl}")) {
        headers.insert(header::CACHE_CONTROL, v);
    }
}

/// Parse the host out of a `Referer` header value.
///
/// Returns `None` when there is no usable host: an empty value, a non-http(s)
/// scheme, or a value that is not a URL at all. `about:blank`, `file://` and
/// `data:` referers never grant access.
fn referer_host(referer: &str) -> Option<String> {
    let referer = referer.trim();
    if referer.is_empty() {
        return None;
    }
    // Only absolute http(s) URLs name a site. Bare strings such as
    // `example.com/page` have no scheme and are treated as unusable rather than
    // guessed at.
    let rest = referer
        .strip_prefix("https://")
        .or_else(|| referer.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // Strip userinfo so `https://example.com@evil.test/` cannot pass as
    // `example.com`: the real host is what follows the last `@`.
    let authority = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);
    if authority.is_empty() {
        return None;
    }
    let host = crate::config::registry::normalize_host(authority);
    if host.is_empty() {
        return None;
    }
    Some(host)
}

/// True when `host` equals `pattern` or is one of its subdomains.
///
/// `example.com` matches `example.com` and `www.example.com` but never
/// `evil-example.com` or `example.com.evil.test`. A leading `*.` is accepted and
/// means subdomains only (`*.example.com` matches `a.example.com`).
fn host_matches(pattern: &str, host: &str) -> bool {
    // The operator may type `Example.COM` in the console; the referer host is
    // always lowercase after normalization, so normalize the pattern too.
    let pattern: String = pattern
        .trim()
        .trim_start_matches("*.")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let pattern = pattern.as_str();
    if pattern.is_empty() {
        return false;
    }
    if host == pattern {
        return !pattern.is_empty();
    }
    // Boundary must be a real label separator, not any substring.
    host.len() > pattern.len()
        && host.ends_with(pattern)
        && host.as_bytes()[host.len() - pattern.len() - 1] == b'.'
}

/// Decide whether a request from `referer` may hotlink.
///
/// The previous implementation used `referer.contains(pattern)`, so a page at
/// `https://evil.test/?ref=https://example.com` was granted access to a domain
/// that only whitelisted `example.com`. Matching is now done on the parsed host
/// with label boundaries.
pub(crate) fn hotlink_allowed(allowed_list: &str, referer: &str) -> bool {
    let patterns: Vec<&str> = allowed_list
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if patterns.is_empty() {
        return false;
    }
    // An explicit `*` allows any source, including a missing Referer.
    if patterns.contains(&"*") {
        return true;
    }
    let Some(host) = referer_host(referer) else {
        // No Referer (or an unusable one) never matches a host pattern.
        return false;
    };
    patterns.iter().any(|pattern| host_matches(pattern, &host))
}
/// JS challenges require a top-level HTML document navigation. JSON/XHR
/// requests (login, fetch, API calls) cannot execute the challenge page.
pub(crate) fn challenge_accepts_html(method: &Method, headers: &HeaderMap) -> bool {
    if method != Method::GET && method != Method::HEAD {
        return false;
    }
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("text/html"))
        .unwrap_or(false)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn log_access(
    log: &AccessLog,
    method: &Method,
    host: &str,
    path: &str,
    status: u16,
    start: Instant,
    client_ip: &str,
    user_agent: &str,
    referer: &str,
    bytes: u64,
    cache_status: &str,
    request_id: &str,
) {
    let ms = start.elapsed().as_millis() as u64;
    let rec = log.record(
        client_ip,
        method.as_str(),
        host,
        path,
        status,
        bytes,
        ms,
        cache_status,
        user_agent,
        referer,
        request_id,
    );
    log.write(rec).await;
}

pub(crate) fn uuid_like_request_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("lr-{:x}", nanos)
}

pub(crate) fn apply_security_headers(headers: &mut HeaderMap) {
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("SAMEORIGIN"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
}

pub(crate) fn apply_cors_and_custom(headers: &mut HeaderMap, overrides: &ResponseHeaderOverrides) {
    overrides.apply(headers);
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    #[test]
    fn challenge_only_for_html_document_navigation() {
        let html = Request::builder()
            .method("GET")
            .header("accept", "text/html,application/xhtml+xml")
            .body(())
            .unwrap();
        assert!(challenge_accepts_html(html.method(), html.headers()));

        let api = Request::builder()
            .method("POST")
            .header("accept", "application/json")
            .body(())
            .unwrap();
        assert!(!challenge_accepts_html(api.method(), api.headers()));

        let fetch = Request::builder()
            .method("GET")
            .header("accept", "*/*")
            .body(())
            .unwrap();
        assert!(!challenge_accepts_html(fetch.method(), fetch.headers()));
    }

    #[test]
    fn hotlink_rules() {
        assert!(hotlink_allowed("*", ""));
        assert!(hotlink_allowed(
            "example.com, foo.com",
            "https://example.com/a"
        ));
        assert!(!hotlink_allowed("example.com", "https://evil.test/a"));
        assert!(!hotlink_allowed("example.com", ""));
    }

    /// The whitelist used to be applied with `referer.contains(pattern)`, so a
    /// page on an attacker domain could embed the allowed host in its query
    /// string or path and steal the asset.
    #[test]
    fn hotlink_rejects_pattern_smuggled_in_query_or_path() {
        for referer in [
            "https://evil.test/?ref=https://example.com",
            "https://evil.test/example.com/a.js",
            "https://evil.test/#example.com",
            "https://evil.test/a?next=example.com",
        ] {
            assert!(
                !hotlink_allowed("example.com", referer),
                "{referer} must not be allowed"
            );
        }
    }

    /// A matching suffix is not a matching host: only a real label boundary
    /// counts.
    #[test]
    fn hotlink_requires_label_boundary() {
        assert!(!hotlink_allowed(
            "example.com",
            "https://evil-example.com/a"
        ));
        assert!(!hotlink_allowed(
            "example.com",
            "https://example.com.evil.test/a"
        ));
        assert!(!hotlink_allowed("example.com", "https://notexample.com/a"));
        // Real subdomains are allowed.
        assert!(hotlink_allowed("example.com", "https://www.example.com/a"));
        assert!(hotlink_allowed("example.com", "https://a.b.example.com/x"));
    }

    /// `https://example.com@evil.test/` puts the allowed name in the userinfo.
    #[test]
    fn hotlink_ignores_userinfo() {
        assert!(!hotlink_allowed(
            "example.com",
            "https://example.com@evil.test/a"
        ));
    }

    /// Wildcard entries mean "subdomains of", not "everything".
    #[test]
    fn hotlink_wildcard_prefix_means_subdomains() {
        assert!(hotlink_allowed("*.example.com", "https://a.example.com/x"));
        assert!(!hotlink_allowed("*.example.com", "https://evil.test/x"));
        assert!(!hotlink_allowed(
            "*.example.com",
            "https://evilexample.com/x"
        ));
    }

    /// Only http(s) referers name a site; opaque schemes never grant access.
    #[test]
    fn hotlink_rejects_non_http_referers() {
        for referer in ["about:blank", "file:///etc/passwd", "data:text/html,x"] {
            assert!(
                !hotlink_allowed("example.com", referer),
                "{referer} must not be allowed"
            );
        }
    }

    /// Ports, trailing dots and case must not defeat the match.
    #[test]
    fn hotlink_normalizes_referer_host() {
        assert!(hotlink_allowed("example.com", "https://EXAMPLE.com:8443/a"));
        assert!(hotlink_allowed("example.com", "https://example.com./a"));
        assert!(hotlink_allowed("Example.COM", "https://example.com/a"));
    }

    /// An empty whitelist denies everything; only an explicit `*` opens it up.
    #[test]
    fn hotlink_empty_list_denies() {
        assert!(!hotlink_allowed("", "https://example.com/a"));
        assert!(!hotlink_allowed("  ,  ", "https://example.com/a"));
        assert!(hotlink_allowed("*", "https://anything.test/a"));
    }
}
