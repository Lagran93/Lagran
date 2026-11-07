//! Signed URL verification (HMAC-SHA256).
//!
//! Canonical string:
//!   METHOD \n host \n path \n sorted(query without expires/signature) \n expires
//!
//! Query parameters are kept in their raw wire form and sorted so clients can
//! reproduce the canonical string without re-encoding. `expires` and the
//! signature are removed before the request reaches the cache/origin.

use crate::config::registry::DomainEntry;
use http::Uri;
use ring::hmac;
use std::time::{SystemTime, UNIX_EPOCH};

pub const EXPIRES_PARAM: &str = "expires";
pub const SIGNATURE_PARAM: &str = "signature";
pub const SIG_PARAM: &str = "sig";
const CLOCK_SKEW_SECS: i64 = 300;
const DEFAULT_TTL_SECS: u64 = 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedUrlError {
    Missing,
    Expired,
    Invalid,
    Config,
}

impl SignedUrlError {
    pub fn reason(self) -> &'static str {
        match self {
            Self::Missing => "signed-url-missing",
            Self::Expired => "signed-url-expired",
            Self::Invalid => "signed-url-invalid",
            Self::Config => "signed-url-config",
        }
    }
}

/// Reject traversal/encoded separators and collapse duplicate slashes before
/// matching or signing. A path that can be interpreted differently by the
/// origin must never be matched as a public path.
pub fn normalize_path(path: &str) -> Result<String, SignedUrlError> {
    if !path.starts_with('/') {
        return Err(SignedUrlError::Invalid);
    }
    let lower = path.to_ascii_lowercase();
    if path.contains('\\')
        || lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%25")
        || path.chars().any(|c| c.is_control())
    {
        return Err(SignedUrlError::Invalid);
    }
    let mut out = String::with_capacity(path.len());
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            return Err(SignedUrlError::Invalid);
        }
        out.push('/');
        out.push_str(segment);
    }
    if out.is_empty() {
        out.push('/');
    }
    if path.ends_with('/') && out != "/" {
        out.push('/');
    }
    Ok(out)
}

pub fn effective_mode(domain: &DomainEntry) -> &str {
    match domain.signed_url_mode.trim().to_ascii_lowercase().as_str() {
        "off" => "off",
        "all" => "all",
        "paths" => "paths",
        _ if domain.signed_url_enabled => "all",
        _ => "off",
    }
}

fn pattern_matches(pattern: &str, path: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        // Only `/prefix/*` is accepted; a bare `*` is rejected by control.
        path.starts_with(prefix)
    } else {
        path == pattern
    }
}

pub fn path_protected(domain: &DomainEntry, path: &str) -> bool {
    match effective_mode(domain) {
        "all" => true,
        "paths" => domain
            .signed_url_paths
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .any(|pattern| pattern_matches(pattern, path)),
        _ => false,
    }
}

pub fn now_epoch_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn query_pairs(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| match part.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (part.to_string(), String::new()),
        })
        .collect()
}

fn canonical_query(query: &str) -> String {
    let mut pairs: Vec<String> = query
        .split('&')
        .filter(|part| {
            let key = part.split('=').next().unwrap_or("");
            !key.eq_ignore_ascii_case(EXPIRES_PARAM)
                && !key.eq_ignore_ascii_case(SIGNATURE_PARAM)
                && !key.eq_ignore_ascii_case(SIG_PARAM)
                && !part.is_empty()
        })
        .map(str::to_string)
        .collect();
    pairs.sort();
    pairs.join("&")
}

fn canonical(
    method: &str,
    host: &str,
    path: &str,
    query: &str,
    expires: &str,
) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        host.to_ascii_lowercase(),
        path,
        canonical_query(query),
        expires
    )
}

fn hex_decode(input: &str) -> Option<Vec<u8>> {
    if input.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    for chunk in bytes.chunks_exact(2) {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

fn verify_with(secret: &str, canonical: &str, signature: &[u8]) -> bool {
    if secret.is_empty() {
        return false;
    }
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    hmac::verify(&key, canonical.as_bytes(), signature).is_ok()
}

#[derive(Debug)]
pub struct VerifiedSignedUrl {
    /// URI with expires/signature removed, suitable for cache key and origin.
    pub uri: Uri,
}

fn rebuild_uri(path: &str, query: &str) -> Result<Uri, SignedUrlError> {
    let raw = if query.is_empty() {
        path.to_string()
    } else {
        format!("{}?{}", path, query)
    };
    Uri::try_from(raw).map_err(|_| SignedUrlError::Invalid)
}

pub fn verify(
    domain: &DomainEntry,
    method: &str,
    host: &str,
    uri: &Uri,
    now: i64,
) -> Result<VerifiedSignedUrl, SignedUrlError> {
    if effective_mode(domain) == "off" {
        return Ok(VerifiedSignedUrl { uri: uri.clone() });
    }
    let normalized_path = normalize_path(uri.path())?;
    if !path_protected(domain, &normalized_path) {
        return Ok(VerifiedSignedUrl {
            uri: rebuild_uri(&normalized_path, uri.query().unwrap_or(""))?,
        });
    }
    if domain.signed_url_secret.is_empty() && domain.signed_url_previous_secret.is_empty() {
        return Err(SignedUrlError::Config);
    }
    let path = normalized_path.as_str();
    let query = uri.query().unwrap_or("");
    let pairs = query_pairs(query);

    let mut expires_values = Vec::new();
    let mut signatures = Vec::new();
    for (key, value) in &pairs {
        if key.eq_ignore_ascii_case(EXPIRES_PARAM) {
            expires_values.push(value.clone());
        } else if key.eq_ignore_ascii_case(SIGNATURE_PARAM)
            || key.eq_ignore_ascii_case(SIG_PARAM)
        {
            signatures.push(value.clone());
        }
    }
    if expires_values.len() != 1 || signatures.len() != 1 {
        return Err(if signatures.is_empty() {
            SignedUrlError::Missing
        } else {
            SignedUrlError::Invalid
        });
    }
    let expires_raw = &expires_values[0];
    let expires: i64 = expires_raw.parse().map_err(|_| SignedUrlError::Invalid)?;
    if expires < now - CLOCK_SKEW_SECS {
        return Err(SignedUrlError::Expired);
    }
    let ttl = if domain.signed_url_ttl_secs == 0 {
        DEFAULT_TTL_SECS
    } else {
        u64::from(domain.signed_url_ttl_secs)
    };
    if expires > now + ttl as i64 + CLOCK_SKEW_SECS {
        return Err(SignedUrlError::Invalid);
    }
    let signature = hex_decode(&signatures[0]).ok_or(SignedUrlError::Invalid)?;
    let canonical = canonical(method, host, path, query, expires_raw);
    // Try current and previous key so rotation does not immediately break
    // outstanding links. Always run both checks to avoid leaking which key
    // matched through timing.
    let current_ok = verify_with(&domain.signed_url_secret, &canonical, &signature);
    let previous_ok =
        verify_with(&domain.signed_url_previous_secret, &canonical, &signature);
    if !current_ok && !previous_ok {
        return Err(SignedUrlError::Invalid);
    }

    let cleaned: Vec<String> = query
        .split('&')
        .filter(|part| {
            let key = part.split('=').next().unwrap_or("");
            !part.is_empty()
                && !key.eq_ignore_ascii_case(EXPIRES_PARAM)
                && !key.eq_ignore_ascii_case(SIGNATURE_PARAM)
                && !key.eq_ignore_ascii_case(SIG_PARAM)
        })
        .map(str::to_string)
        .collect();
    let rebuilt = if cleaned.is_empty() {
        path.to_string()
    } else {
        format!("{}?{}", path, cleaned.join("&"))
    };
    let uri = Uri::try_from(rebuilt).map_err(|_| SignedUrlError::Invalid)?;
    Ok(VerifiedSignedUrl { uri })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::hmac;

    fn domain(secret: &str) -> DomainEntry {
        DomainEntry {
            signed_url_enabled: true,
            signed_url_secret: secret.to_string(),
            signed_url_previous_secret: String::new(),
            signed_url_ttl_secs: 3600,
            ..Default::default()
        }
    }

    fn sign(secret: &str, method: &str, host: &str, path: &str, query: &str, expires: &str) -> String {
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        let tag = hmac::sign(&key, canonical(method, host, path, query, expires).as_bytes());
        tag.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn valid_signature_is_accepted_and_cleaned() {
        let d = domain("secret");
        let now = now_epoch_secs();
        let expires = (now + 60).to_string();
        let sig = sign("secret", "GET", "a.test", "/x", "b=2&a=1", &expires);
        let uri: Uri = format!("/x?b=2&a=1&expires={expires}&sig={sig}").parse().unwrap();
        let out = verify(&d, "GET", "a.test", &uri, now).unwrap();
        assert_eq!(out.uri.to_string(), "/x?b=2&a=1");
    }

    #[test]
    fn path_mode_only_protects_matching_paths() {
        let d = DomainEntry {
            signed_url_enabled: true,
            signed_url_mode: "paths".into(),
            signed_url_paths: "/private/*\n/downloads/exact.zip".into(),
            signed_url_secret: "secret".into(),
            signed_url_ttl_secs: 3600,
            ..Default::default()
        };
        let now = now_epoch_secs();
        assert!(!path_protected(&d, "/public/app.js"));
        assert!(!path_protected(&d, "/private2/app.js"));
        assert!(path_protected(&d, "/private/app.js"));
        let public: Uri = "/public/app.js".parse().unwrap();
        assert_eq!(verify(&d, "GET", "a.test", &public, now).unwrap().uri, public);
        let private: Uri = "/private/app.js".parse().unwrap();
        assert_eq!(
            verify(&d, "GET", "a.test", &private, now).unwrap_err(),
            SignedUrlError::Missing
        );
        let expires = (now + 60).to_string();
        let sig = sign("secret", "GET", "a.test", "/private/app.js", "", &expires);
        let signed: Uri = format!("/private/app.js?expires={expires}&sig={sig}")
            .parse()
            .unwrap();
        assert_eq!(
            verify(&d, "GET", "a.test", &signed, now)
                .unwrap()
                .uri
                .to_string(),
            "/private/app.js"
        );
    }

    #[test]
    fn traversal_paths_are_rejected() {
        assert!(normalize_path("/private/../public").is_err());
        assert!(normalize_path("/private/%2e%2e/public").is_err());
        assert!(normalize_path("/private/%2Fpublic").is_err());
        assert_eq!(normalize_path("//private//a").unwrap(), "/private/a");
    }

    #[test]
    fn expired_signature_is_rejected() {
        let d = domain("secret");
        let now = now_epoch_secs();
        let expires = (now - 3600).to_string();
        let sig = sign("secret", "GET", "a.test", "/x", "", &expires);
        let uri: Uri = format!("/x?expires={expires}&sig={sig}").parse().unwrap();
        assert_eq!(verify(&d, "GET", "a.test", &uri, now).unwrap_err(), SignedUrlError::Expired);
    }
}
