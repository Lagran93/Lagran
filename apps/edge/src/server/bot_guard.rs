//! Lightweight behavioural bot scoring.
//!
//! This is intentionally a heuristic layer, not a browser fingerprinting
//! service. It only produces a score; the caller decides whether to issue the
//! existing proof-of-work challenge. The feature is opt-in because some API
//! clients omit browser-only headers.

use axum::http::{header, HeaderMap};
use std::sync::OnceLock;

struct Settings {
    enabled: bool,
    threshold: u8,
}

fn settings() -> &'static Settings {
    static SETTINGS: OnceLock<Settings> = OnceLock::new();
    SETTINGS.get_or_init(|| Settings {
        enabled: std::env::var("CC_BEHAVIOR_ENABLED")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false),
        threshold: std::env::var("CC_BEHAVIOR_SCORE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4)
            .clamp(1, 20),
    })
}

pub fn enabled() -> bool {
    settings().enabled
}

pub fn threshold() -> u8 {
    settings().threshold
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Score a document request from headers that are cheap to inspect.
pub fn score(headers: &HeaderMap) -> u8 {
    let ua = header(headers, "user-agent").unwrap_or("");
    let ua_lower = ua.to_ascii_lowercase();
    let mut score = 0u8;
    if ua.trim().is_empty() {
        score += 3;
    } else if ua.len() < 16 {
        score += 1;
    }
    if [
        "curl/",
        "wget/",
        "python-requests",
        "python-urllib",
        "go-http-client",
        "java/",
        "okhttp",
        "axios/",
        "node-fetch",
        "scrapy",
        "httpclient",
    ]
    .iter()
    .any(|needle| ua_lower.contains(needle))
    {
        score += 3;
    }
    if header(headers, "accept").is_none() {
        score += 1;
    }
    if header(headers, "accept-language").is_none() {
        score += 1;
    }
    if header(headers, "sec-ch-ua").is_none() {
        score += 1;
    }
    if header(headers, "sec-fetch-mode").is_none() {
        score += 1;
    }
    if header(headers, header::COOKIE.as_str()).is_none() {
        score += 1;
    }
    if headers.len() < 5 {
        score += 1;
    }
    score
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_like_headers_score_low() {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36".parse().unwrap());
        headers.insert("accept", "text/html,application/xhtml+xml".parse().unwrap());
        headers.insert("accept-language", "zh-CN,zh;q=0.9".parse().unwrap());
        headers.insert("sec-ch-ua", "\"Chromium\";v=\"130\"".parse().unwrap());
        headers.insert("sec-fetch-mode", "navigate".parse().unwrap());
        headers.insert("cookie", "session=abc".parse().unwrap());
        headers.insert("referer", "https://example.com/".parse().unwrap());
        assert!(score(&headers) < 2);
    }

    #[test]
    fn automation_headers_score_high() {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "curl/8.0".parse().unwrap());
        headers.insert("accept", "text/html".parse().unwrap());
        assert!(score(&headers) >= 4);
    }
}
