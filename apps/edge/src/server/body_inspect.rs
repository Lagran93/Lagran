//! Bounded request-body buffering for WAF inspection.
//!
//! Pingora forwards request bodies as a stream, so a body-dependent verdict
//! must be made before the origin sees any bytes. Reading the body inside
//! `request_filter` with retry buffering enabled makes Pingora send that exact
//! buffer upstream afterwards (the buffer exists for retries), which lets the
//! WAF inspect first and still forward the original bytes.
//!
//! The buffer is limited by Pingora's fixed 64 KiB `BODY_BUF_LIMIT`, so bodies
//! that cannot be replayed are rejected or passed through according to the
//! domain policy instead of being consumed.

use crate::config::registry::DomainEntry;
use crate::waf::body::{BodyFacts, BodyInspection, BodyPolicy};
use axum::http::{HeaderMap, Method, StatusCode};
use bytes::Bytes;
use pingora::proxy::Session;
use std::time::{Duration, Instant};

/// What the request path should do with this body.
#[derive(Debug, Clone)]
pub enum Decision {
    /// Do not read; the proxy streams the body as before.
    Skip { reason: &'static str, log: bool },
    /// Refuse before reading (or after a failed read); nothing is forwarded.
    Reject {
        status: StatusCode,
        reason: &'static str,
    },
    /// Read at most `max_bytes` with an overall `timeout`.
    Inspect { max_bytes: usize, timeout: Duration },
}

/// Decide eligibility from metadata only. Never consumes the body.
pub fn decide(domain: &DomainEntry, method: &Method, headers: &HeaderMap) -> Decision {
    let body = &domain.waf.body;
    if !domain.waf.enabled || !body.enabled {
        return Decision::Skip {
            reason: "disabled",
            log: false,
        };
    }
    let facts = BodyFacts::from_headers(method.as_str(), headers);
    if !body.method_allowed(facts.method) {
        return Decision::Skip {
            reason: "method",
            log: false,
        };
    }
    if facts.upgrade {
        return Decision::Skip {
            reason: "upgrade",
            log: false,
        };
    }
    if !facts.is_identity() {
        return uninspectable(body, "content-encoding");
    }
    if !body.content_type_allowed(facts.content_type) {
        return uninspectable(body, "content-type");
    }
    if facts.expect_continue {
        // A client using `Expect: 100-continue` waits for an interim response
        // before sending the body. This version does not send one, so reading
        // would deadlock until the timeout; skip with the configured policy.
        return uninspectable(body, "expect-continue");
    }
    match facts.content_length {
        None => uninspectable(body, "no-content-length"),
        Some(0) => Decision::Skip {
            reason: "empty",
            log: false,
        },
        Some(length) if length > body.max_bytes => {
            if body.oversize.blocks() {
                Decision::Reject {
                    status: StatusCode::PAYLOAD_TOO_LARGE,
                    reason: "oversize",
                }
            } else {
                Decision::Skip {
                    reason: "oversize",
                    log: body.oversize == BodyPolicy::Log,
                }
            }
        }
        Some(_) => Decision::Inspect {
            max_bytes: body.max_bytes,
            timeout: body.timeout(),
        },
    }
}

fn uninspectable(body: &BodyInspection, reason: &'static str) -> Decision {
    if body.uninspectable.blocks() {
        Decision::Reject {
            status: StatusCode::UNSUPPORTED_MEDIA_TYPE,
            reason,
        }
    } else {
        Decision::Skip {
            reason,
            log: body.uninspectable == BodyPolicy::Log,
        }
    }
}

/// Errors after reading started. Unlike [`Decision`], these are always fatal:
/// part of the body has been consumed, so it can no longer be replayed.
#[derive(Debug)]
pub enum ReadError {
    TooLarge,
    Timeout,
    Io(String),
}

impl ReadError {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Timeout => StatusCode::REQUEST_TIMEOUT,
            Self::Io(_) => StatusCode::BAD_REQUEST,
        }
    }

    pub fn reason(&self) -> &'static str {
        match self {
            Self::TooLarge => "too-large",
            Self::Timeout => "timeout",
            Self::Io(_) => "read-error",
        }
    }
}

/// Read the whole request body into the retry buffer.
///
/// The returned bytes are for inspection only; Pingora forwards its own copy of
/// the retry buffer once the upstream connection is ready.
pub async fn read(
    session: &mut Session,
    max_bytes: usize,
    timeout: Duration,
) -> Result<Bytes, ReadError> {
    session.enable_retry_buffering();
    let deadline = Instant::now() + timeout;
    let mut buf: Vec<u8> = Vec::with_capacity(max_bytes.min(8192));
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ReadError::Timeout);
        }
        match tokio::time::timeout(remaining, session.read_request_body()).await {
            Ok(Ok(Some(chunk))) => {
                if buf.len() + chunk.len() > max_bytes {
                    return Err(ReadError::TooLarge);
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(Ok(None)) => return Ok(Bytes::from(buf)),
            Ok(Err(e)) => return Err(ReadError::Io(e.to_string())),
            Err(_) => return Err(ReadError::Timeout),
        }
    }
}

/// `Content-Length` as an integer, if present and valid.
pub fn content_length(headers: &HeaderMap) -> Option<usize> {
    headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<usize>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::registry::DomainEntry;
    use crate::waf::WafConfig;

    fn domain(body: BodyInspection) -> DomainEntry {
        let mut waf = WafConfig::default();
        waf.enabled = true;
        waf.body = body;
        DomainEntry {
            waf,
            ..DomainEntry::default()
        }
    }

    fn headers(method: &str, content_type: &str, length: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            content_type.parse().unwrap(),
        );
        if let Some(length) = length {
            headers.insert(axum::http::header::CONTENT_LENGTH, length.parse().unwrap());
        }
        let _ = method;
        headers
    }

    #[test]
    fn disabled_waf_skips() {
        let mut d = domain(BodyInspection {
            enabled: true,
            ..BodyInspection::default()
        });
        d.waf.enabled = false;
        match decide(
            &d,
            &Method::POST,
            &headers("POST", "application/json", Some("10")),
        ) {
            Decision::Skip { reason, .. } => assert_eq!(reason, "disabled"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn eligible_json_is_inspected() {
        let d = domain(BodyInspection {
            enabled: true,
            ..BodyInspection::default()
        });
        match decide(
            &d,
            &Method::POST,
            &headers("POST", "application/json; charset=utf-8", Some("10")),
        ) {
            Decision::Inspect { max_bytes, .. } => assert_eq!(max_bytes, 32 * 1024),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn oversize_policy_controls_rejection() {
        let mut body = BodyInspection {
            enabled: true,
            max_bytes: 1024,
            oversize: BodyPolicy::Block,
            ..BodyInspection::default()
        };
        body.finalize();
        let d = domain(body.clone());
        assert!(matches!(
            decide(
                &d,
                &Method::POST,
                &headers("POST", "application/json", Some("2048"))
            ),
            Decision::Reject { status, .. } if status == StatusCode::PAYLOAD_TOO_LARGE
        ));

        body.oversize = BodyPolicy::Log;
        let d = domain(body);
        match decide(
            &d,
            &Method::POST,
            &headers("POST", "application/json", Some("2048")),
        ) {
            Decision::Skip { reason, log } => {
                assert_eq!(reason, "oversize");
                assert!(log);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn missing_length_and_encodings_use_the_uninspectable_policy() {
        let mut body = BodyInspection {
            enabled: true,
            uninspectable: BodyPolicy::Block,
            ..BodyInspection::default()
        };
        body.finalize();
        let d = domain(body);
        assert!(matches!(
            decide(&d, &Method::POST, &headers("POST", "application/json", None)),
            Decision::Reject { status, .. } if status == StatusCode::UNSUPPORTED_MEDIA_TYPE
        ));

        let mut h = headers("POST", "application/json", Some("10"));
        h.insert(
            axum::http::header::CONTENT_ENCODING,
            "gzip".parse().unwrap(),
        );
        assert!(matches!(
            decide(&d, &Method::POST, &h),
            Decision::Reject {
                reason: "content-encoding",
                ..
            }
        ));
    }

    #[test]
    fn get_and_other_types_skip_without_reading() {
        let d = domain(BodyInspection {
            enabled: true,
            ..BodyInspection::default()
        });
        match decide(
            &d,
            &Method::GET,
            &headers("GET", "application/json", Some("10")),
        ) {
            Decision::Skip { reason, .. } => assert_eq!(reason, "method"),
            other => panic!("unexpected {other:?}"),
        }
        match decide(
            &d,
            &Method::POST,
            &headers("POST", "multipart/form-data; boundary=x", Some("10")),
        ) {
            Decision::Skip { reason, .. } => assert_eq!(reason, "content-type"),
            other => panic!("unexpected {other:?}"),
        }
    }
}
