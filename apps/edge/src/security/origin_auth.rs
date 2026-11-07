//! Origin authentication: inject a private header that only Edge and the
//! origin know. The client never receives this header.

use axum::http::{HeaderMap, HeaderName, HeaderValue};

pub fn apply(headers: &mut HeaderMap, header: &str, value: &str) {
    let header = header.trim();
    let value = value.trim();
    if header.is_empty() || value.is_empty() {
        return;
    }
    let Ok(name) = HeaderName::from_bytes(header.as_bytes()) else {
        tracing::warn!(header, "invalid origin auth header name");
        return;
    };
    let Ok(value) = HeaderValue::from_str(value) else {
        tracing::warn!(header, "invalid origin auth header value");
        return;
    };
    headers.insert(name, value);
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injects_configured_header_only() {
        let mut h = HeaderMap::new();
        apply(&mut h, "x-origin-token", "secret");
        assert_eq!(h.get("x-origin-token").unwrap(), "secret");
        apply(&mut h, "", "ignored");
        assert_eq!(h.len(), 1);
    }
}
