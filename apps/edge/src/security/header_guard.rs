//! Strict request-header validation before WAF/cache/origin.
//!
//! Hyper/Pingora already parse HTTP, but enterprise edges must explicitly reject
//! ambiguous framing (CL+TE, duplicate CL, bad TE) and connection-specific
//! headers on HTTP/2. This is defense-in-depth against request smuggling and
//! header-injection differences between hops.

use http::header::{CONNECTION, CONTENT_LENGTH, HOST, TRANSFER_ENCODING};
use http::{HeaderMap, HeaderName, Method, Uri, Version};

use crate::config::registry::normalize_host;

pub const MAX_HEADERS: usize = 128;
pub const MAX_HEADER_BYTES: usize = 64 * 1024;
/// Largest single header value this edge accepts.
///
/// The total cap alone let one header consume the entire budget: a single 64 KiB
/// `Cookie`, `Referer` or custom header was accepted, copied into the access log,
/// into the origin request, and into the cache key when a rule keyed on it. Legal
/// values are far smaller — the largest a real client sends is a cookie or a long
/// referer, both well under 8 KiB — so this bounds one header without rejecting
/// anything real. `MAX_HEADER_BYTES` still bounds the sum.
pub const MAX_HEADER_VALUE_BYTES: usize = 8 * 1024;
const MAX_HOST_LEN: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderViolation {
    pub reason: &'static str,
}

impl HeaderViolation {
    fn new(reason: &'static str) -> Self {
        Self { reason }
    }
}

fn bad_value(value: &str) -> bool {
    value.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f)
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_HOST_LEN
        && !host.chars().any(|c| c.is_whitespace() || c.is_control())
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']'))
}

/// Validate a `host[:port]` value and return the host part.
///
/// Accepts a DNS name (letters, digits, `-`, `_`, dots) or a bracketed IPv6
/// literal, optionally followed by `:` and a numeric port in range. Returns
/// `None` for anything else, including an unbalanced bracket, an empty label, a
/// port with no digits, or a port above 65535.
fn parse_authority_host(value: &str) -> Option<&str> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    // Bracketed IPv6: `[::1]` or `[::1]:8080`.
    if let Some(rest) = value.strip_prefix('[') {
        let (inside, tail) = rest.split_once(']')?;
        if inside.is_empty() || inside.parse::<std::net::Ipv6Addr>().is_err() {
            return None;
        }
        match tail {
            "" => return Some(&value[..value.len()]),
            _ => {
                let port = tail.strip_prefix(':')?;
                return valid_port(port).then(|| &value[..value.len()]);
            }
        }
    }
    // Unbracketed: at most one `:`, and only as a port separator. A bare IPv6
    // literal has several colons and must be bracketed, which is why this split
    // is unambiguous here.
    let (host, port) = match value.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (value, None),
    };
    if host.is_empty() || host.contains(':') {
        return None;
    }
    // Labels must be non-empty and use the hostname character set.
    if host
        .split('.')
        .any(|label| label.is_empty() || !label.chars().all(valid_host_char))
    {
        return None;
    }
    if let Some(port) = port {
        if !valid_port(port) {
            return None;
        }
    }
    Some(host)
}

fn valid_port(port: &str) -> bool {
    !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|b| b.is_ascii_digit())
        && port.parse::<u16>().is_ok()
}

fn valid_host_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_')
}

fn connection_tokens(headers: &HeaderMap) -> Vec<String> {
    let mut out = Vec::new();
    for value in headers.get_all(CONNECTION) {
        if let Ok(value) = value.to_str() {
            out.extend(
                value
                    .split(',')
                    .map(|v| v.trim().to_ascii_lowercase())
                    .filter(|v| !v.is_empty()),
            );
        }
    }
    out
}

/// Validate the raw request headers. Returns a short reason suitable for a
/// 400 response/log; never echo attacker-controlled values.
pub fn validate(
    headers: &HeaderMap,
    uri: &Uri,
    method: &Method,
    version: Version,
) -> Result<(), HeaderViolation> {
    let is_h2 = version == Version::HTTP_2;
    if headers.len() > MAX_HEADERS {
        return Err(HeaderViolation::new("too-many-headers"));
    }
    let mut total = 0usize;
    for (name, value) in headers.iter() {
        total = total.saturating_add(name.as_str().len() + value.as_bytes().len());
        if total > MAX_HEADER_BYTES {
            return Err(HeaderViolation::new("header-bytes"));
        }
        if value.as_bytes().len() > MAX_HEADER_VALUE_BYTES {
            return Err(HeaderViolation::new("header-value-bytes"));
        }
        if value.to_str().map(bad_value).unwrap_or(true) {
            return Err(HeaderViolation::new("bad-header-value"));
        }
    }

    // HTTP/2 forbids connection-specific headers (RFC 9113 §8.2.2).
    if is_h2 {
        for name in [
            "connection",
            "proxy-connection",
            "keep-alive",
            "upgrade",
            "transfer-encoding",
        ] {
            if headers.contains_key(name) {
                return Err(HeaderViolation::new("h2-connection-header"));
            }
        }
    }

    // Host / authority: reject duplicates, whitespace, and mismatched
    // absolute-form authority.
    let hosts: Vec<&http::HeaderValue> = headers.get_all(HOST).iter().collect();
    if hosts.len() > 1 {
        return Err(HeaderViolation::new("multiple-host"));
    }
    let host = hosts
        .first()
        .and_then(|v| v.to_str().ok())
        .filter(|v| valid_host(v));
    if hosts.is_empty() {
        if !is_h2 || uri.authority().is_none() {
            return Err(HeaderViolation::new("missing-host"));
        }
    } else if host.is_none() {
        return Err(HeaderViolation::new("bad-host"));
    }
    if let Some(authority) = uri.authority() {
        let authority = authority.as_str();
        // `http::Uri` keeps userinfo in the authority string. Reject it before
        // comparing Hosts; `valid_host` does not cover this H2 pseudo-header.
        if authority.contains('@') || authority.chars().any(char::is_whitespace) {
            return Err(HeaderViolation::new("bad-authority"));
        }
        if let Some(host) = host {
            // HTTP/2 hosts and `:authority` may differ only by case or by an
            // explicit numeric port (`hit.test` vs `hit.test:443`). Compare the
            // same normalized form used for the domain registry and cache key;
            // do not require byte equality on the pseudo-header.
            if normalize_host(host) != normalize_host(authority) {
                return Err(HeaderViolation::new("host-authority-mismatch"));
            }
        }
    } else if let Some(host) = host {
        // Origin-form: there is no authority to compare against, so `Host` is the
        // only host source and must be structurally valid on its own. It used to
        // be checked only by `valid_host`, which accepts any string built from a
        // loose character set (`:` anywhere, unbalanced brackets, a non-numeric
        // port). The absolute-form branch above rejects a malformed authority;
        // origin-form must be at least as strict, otherwise the two request forms
        // disagree about what a host is and the value flows into the registry
        // lookup and cache key unvalidated.
        if parse_authority_host(host).is_none() {
            return Err(HeaderViolation::new("bad-host"));
        }
    }

    // HTTP/1 connection tokens must not name framing headers.
    for token in connection_tokens(headers) {
        if token == "content-length" || token == "transfer-encoding" {
            return Err(HeaderViolation::new("connection-framing"));
        }
    }

    // Content-Length: exactly one value, digits only.
    let content_lengths: Vec<&http::HeaderValue> = headers.get_all(CONTENT_LENGTH).iter().collect();
    let te_values: Vec<&http::HeaderValue> = headers.get_all(TRANSFER_ENCODING).iter().collect();
    if content_lengths.len() > 1 {
        return Err(HeaderViolation::new("multiple-content-length"));
    }
    if content_lengths.len() == 1 {
        let value = content_lengths[0]
            .to_str()
            .map_err(|_| HeaderViolation::new("bad-content-length"))?;
        if value.is_empty()
            || value.contains(',')
            || value.contains('+')
            || value.contains('-')
            || value.chars().any(|c| !c.is_ascii_digit())
            || value.parse::<u64>().is_err()
        {
            return Err(HeaderViolation::new("bad-content-length"));
        }
    }
    // CL + TE is the canonical request-smuggling ambiguity.
    if !content_lengths.is_empty() && !te_values.is_empty() {
        return Err(HeaderViolation::new("cl-te-conflict"));
    }
    if te_values.len() > 1 {
        return Err(HeaderViolation::new("multiple-transfer-encoding"));
    }
    if let Some(value) = te_values.first() {
        let value = value
            .to_str()
            .map_err(|_| HeaderViolation::new("bad-transfer-encoding"))?;
        let tokens: Vec<&str> = value.split(',').map(str::trim).collect();
        if tokens.len() != 1 || !tokens[0].eq_ignore_ascii_case("chunked") {
            return Err(HeaderViolation::new("bad-transfer-encoding"));
        }
    }

    // A proxy must not accept an absolute-form authority that disagrees with
    // the request target. `CONNECT` targets are authority-form; allow those.
    if method == Method::CONNECT && uri.authority().is_none() {
        return Err(HeaderViolation::new("connect-without-authority"));
    }

    Ok(())
}

/// Header names are already normalized by `http::HeaderMap`; expose the helper
/// for callers that need an explicit canonical name check.
pub fn canonical_name(name: &HeaderName) -> &str {
    name.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(HOST, HeaderValue::from_static("a.test"));
        h
    }

    #[test]
    fn accepts_normal_request() {
        let h = headers();
        assert!(validate(&h, &"/x".parse().unwrap(), &Method::GET, Version::HTTP_11).is_ok());
    }

    #[test]
    fn h2_authority_port_and_case_are_compatible_with_host() {
        let mut h = HeaderMap::new();
        h.insert(HOST, HeaderValue::from_static("HIT.test"));
        let uri: Uri = "https://HIT.test:18443/small".parse().unwrap();
        assert!(validate(&h, &uri, &Method::GET, Version::HTTP_2).is_ok());

        let mut mismatched = HeaderMap::new();
        mismatched.insert(HOST, HeaderValue::from_static("other.test"));
        assert_eq!(
            validate(&mismatched, &uri, &Method::GET, Version::HTTP_2)
                .unwrap_err()
                .reason,
            "host-authority-mismatch"
        );
    }

    #[test]
    fn h2_authority_without_host_is_valid() {
        let uri: Uri = "https://hit.test:18443/small".parse().unwrap();
        assert!(validate(&HeaderMap::new(), &uri, &Method::GET, Version::HTTP_2).is_ok());
    }

    #[test]
    fn rejects_cl_te_conflict() {
        let mut h = headers();
        h.insert(CONTENT_LENGTH, HeaderValue::from_static("4"));
        h.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        assert_eq!(
            validate(&h, &"/x".parse().unwrap(), &Method::POST, Version::HTTP_11)
                .unwrap_err()
                .reason,
            "cl-te-conflict"
        );
    }

    #[test]
    fn rejects_duplicate_and_invalid_content_length() {
        let mut h = headers();
        h.append(CONTENT_LENGTH, HeaderValue::from_static("4"));
        h.append(CONTENT_LENGTH, HeaderValue::from_static("4"));
        assert_eq!(
            validate(&h, &"/x".parse().unwrap(), &Method::POST, Version::HTTP_11)
                .unwrap_err()
                .reason,
            "multiple-content-length"
        );
        let mut h = headers();
        h.insert(CONTENT_LENGTH, HeaderValue::from_static("+4"));
        assert_eq!(
            validate(&h, &"/x".parse().unwrap(), &Method::POST, Version::HTTP_11)
                .unwrap_err()
                .reason,
            "bad-content-length"
        );
    }

    #[test]
    fn rejects_h2_connection_header() {
        let mut h = headers();
        h.insert(CONNECTION, HeaderValue::from_static("keep-alive"));
        assert_eq!(
            validate(&h, &"/x".parse().unwrap(), &Method::GET, Version::HTTP_2)
                .unwrap_err()
                .reason,
            "h2-connection-header"
        );
    }

    #[test]
    fn rejects_bad_transfer_encoding() {
        let mut h = headers();
        h.insert(
            TRANSFER_ENCODING,
            HeaderValue::from_static("chunked, chunked"),
        );
        assert_eq!(
            validate(&h, &"/x".parse().unwrap(), &Method::POST, Version::HTTP_11)
                .unwrap_err()
                .reason,
            "bad-transfer-encoding"
        );
    }
    /// Origin-form requests have no authority to cross-check, so `Host` itself
    /// must be structurally valid. It used to pass on a loose character check,
    /// which let a value the absolute-form branch would reject reach the domain
    /// registry and the cache key.
    #[test]
    fn origin_form_rejects_malformed_host() {
        for bad in [
            "a.test:",
            "a.test:abc",
            "a.test:99999",
            "a.test:80:90",
            "a..test",
            ".a.test",
            "a.test.",
            "[::1",
            "[::1]x",
            "[]",
            "[not-ipv6]",
            "host/evil",
            "user@host",
        ] {
            let mut h = HeaderMap::new();
            h.insert(HOST, HeaderValue::from_str(bad).unwrap());
            let uri: Uri = "/x".parse().unwrap();
            assert_eq!(
                validate(&h, &uri, &Method::GET, Version::HTTP_11)
                    .unwrap_err()
                    .reason,
                "bad-host",
                "{bad:?} should be rejected in origin-form"
            );
        }
    }

    /// Ordinary origin-form hosts, with and without a port, still pass.
    #[test]
    fn origin_form_accepts_valid_host() {
        for good in [
            "a.test",
            "A.TEST",
            "a.test:80",
            "a.test:18443",
            "sub.domain.example.com",
            "my_host.example",
            "[::1]",
            "[::1]:8080",
            "[2001:db8::1]:443",
        ] {
            let mut h = HeaderMap::new();
            h.insert(HOST, HeaderValue::from_str(good).unwrap());
            let uri: Uri = "/x".parse().unwrap();
            assert!(
                validate(&h, &uri, &Method::GET, Version::HTTP_11).is_ok(),
                "{good:?} should be accepted in origin-form"
            );
        }
    }

    /// `parse_authority_host` returns the host without the port.
    #[test]
    fn authority_host_parsing_strips_the_port() {
        assert_eq!(parse_authority_host("a.test:8080"), Some("a.test"));
        assert_eq!(parse_authority_host("a.test"), Some("a.test"));
        assert_eq!(parse_authority_host("[::1]:8080"), Some("[::1]:8080"));
        assert_eq!(parse_authority_host("a.test:"), None);
        assert_eq!(parse_authority_host(""), None);
    }
    /// One header must not be able to consume the whole byte budget.
    #[test]
    fn rejects_an_oversized_single_header() {
        let mut h = HeaderMap::new();
        h.insert(HOST, HeaderValue::from_static("a.test"));
        h.insert(
            HeaderName::from_static("x-big"),
            HeaderValue::from_str(&"a".repeat(MAX_HEADER_VALUE_BYTES + 1)).unwrap(),
        );
        let uri: Uri = "/x".parse().unwrap();
        assert_eq!(
            validate(&h, &uri, &Method::GET, Version::HTTP_11)
                .unwrap_err()
                .reason,
            "header-value-bytes"
        );
    }

    /// A large but legal header still passes.
    #[test]
    fn accepts_a_realistic_large_header() {
        let mut h = HeaderMap::new();
        h.insert(HOST, HeaderValue::from_static("a.test"));
        // A long `Referer`/`Cookie` is the biggest a real client sends.
        h.insert(
            HeaderName::from_static("cookie"),
            HeaderValue::from_str(&"k=v; ".repeat(600)).unwrap(),
        );
        let uri: Uri = "/x".parse().unwrap();
        assert!(validate(&h, &uri, &Method::GET, Version::HTTP_11).is_ok());
    }

    /// Many small headers are still bounded by the total.
    #[test]
    fn total_header_bytes_still_bounded() {
        let mut h = HeaderMap::new();
        h.insert(HOST, HeaderValue::from_static("a.test"));
        let chunk = "a".repeat(4000);
        for i in 0..17 {
            // Each is under the per-header cap; 17 x 4000 exceeds the 64 KiB total.
            h.insert(
                HeaderName::try_from(format!("x-{i}")).unwrap(),
                HeaderValue::from_str(&chunk).unwrap(),
            );
        }
        let uri: Uri = "/x".parse().unwrap();
        assert_eq!(
            validate(&h, &uri, &Method::GET, Version::HTTP_11)
                .unwrap_err()
                .reason,
            "header-bytes"
        );
    }
}
