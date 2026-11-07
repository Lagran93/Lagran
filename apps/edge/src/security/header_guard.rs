//! Strict request-header validation before WAF/cache/origin.
//!
//! Hyper/Pingora already parse HTTP, but enterprise edges must explicitly reject
//! ambiguous framing (CL+TE, duplicate CL, bad TE) and connection-specific
//! headers on HTTP/2. This is defense-in-depth against request smuggling and
//! header-injection differences between hops.

use http::header::{CONNECTION, CONTENT_LENGTH, HOST, TRANSFER_ENCODING};
use http::{HeaderMap, HeaderName, Method, Uri, Version};

pub const MAX_HEADERS: usize = 128;
pub const MAX_HEADER_BYTES: usize = 64 * 1024;
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
    value
        .bytes()
        .any(|b| (b < 0x20 && b != b'\t') || b == 0x7f)
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_HOST_LEN
        && !host.chars().any(|c| c.is_whitespace() || c.is_control())
        && host.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '.' | '-' | '_' | ':' | '[' | ']')
        })
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
        if value.to_str().map(bad_value).unwrap_or(true) {
            return Err(HeaderViolation::new("bad-header-value"));
        }
    }

    // HTTP/2 forbids connection-specific headers (RFC 9113 §8.2.2).
    if is_h2 {
        for name in ["connection", "proxy-connection", "keep-alive", "upgrade", "transfer-encoding"] {
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
    if let (Some(host), Some(authority)) = (host, uri.authority()) {
        if !host.eq_ignore_ascii_case(authority.as_str()) {
            return Err(HeaderViolation::new("host-authority-mismatch"));
        }
    }

    // HTTP/1 connection tokens must not name framing headers.
    for token in connection_tokens(headers) {
        if token == "content-length" || token == "transfer-encoding" {
            return Err(HeaderViolation::new("connection-framing"));
        }
    }

    // Content-Length: exactly one value, digits only.
    let content_lengths: Vec<&http::HeaderValue> =
        headers.get_all(CONTENT_LENGTH).iter().collect();
    let te_values: Vec<&http::HeaderValue> =
        headers.get_all(TRANSFER_ENCODING).iter().collect();
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
    if method == Method::CONNECT {
        if uri.authority().is_none() {
            return Err(HeaderViolation::new("connect-without-authority"));
        }
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
}
