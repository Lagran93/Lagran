//! Lightweight behavioural bot scoring.
//!
//! This is a heuristic layer, not a browser fingerprinting service. It only
//! produces a score and machine-readable reasons; the caller decides whether to
//! issue the existing proof-of-work challenge. The feature is opt-in because
//! some API clients omit browser-only headers.

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

#[derive(Debug, Default)]
pub struct BehaviorAnalysis {
    pub score: u8,
    pub reasons: Vec<&'static str>,
}

impl BehaviorAnalysis {
    fn add(&mut self, points: u8, reason: &'static str) {
        self.score = self.score.saturating_add(points);
        self.reasons.push(reason);
    }
}

/// Score a document request and explain why it looks automated.
pub fn analyze(headers: &HeaderMap) -> BehaviorAnalysis {
    let mut out = BehaviorAnalysis::default();
    let ua = header(headers, "user-agent").unwrap_or("");
    let ua_lower = ua.to_ascii_lowercase();

    if ua.trim().is_empty() {
        out.add(3, "empty-ua");
    } else {
        if ua.len() < 16 {
            out.add(1, "short-ua");
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
            out.add(3, "automation-ua");
        }
        if [
            "headlesschrome",
            "headless",
            "phantomjs",
            "playwright",
            "puppeteer",
            "selenium",
        ]
        .iter()
        .any(|needle| ua_lower.contains(needle))
        {
            out.add(3, "headless-ua");
        }
        let chrome = ua_lower.contains("chrome/")
            || ua_lower.contains("chromium/")
            || ua_lower.contains("edg/");
        let firefox = ua_lower.contains("firefox/");
        if chrome && firefox {
            out.add(2, "conflicting-ua");
        }
        if chrome && header(headers, "sec-ch-ua").is_none() {
            out.add(1, "missing-client-hints");
        }
    }

    if header(headers, "accept").is_none() {
        out.add(1, "missing-accept");
    }
    if header(headers, "accept-language").is_none() {
        out.add(1, "missing-accept-language");
    }
    if header(headers, "accept-encoding").is_none() {
        out.add(1, "missing-accept-encoding");
    }
    if header(headers, "sec-ch-ua").is_none() {
        out.add(1, "missing-sec-ch-ua");
    }
    match header(headers, "sec-fetch-mode") {
        None => out.add(1, "missing-sec-fetch-mode"),
        Some(mode) => {
            let mode = mode.trim().to_ascii_lowercase();
            if !matches!(
                mode.as_str(),
                "navigate" | "cors" | "no-cors" | "same-origin" | "websocket"
            ) {
                out.add(1, "invalid-sec-fetch-mode");
            }
            if mode == "navigate" {
                if let Some(dest) = header(headers, "sec-fetch-dest") {
                    if !dest.trim().eq_ignore_ascii_case("document") {
                        out.add(1, "navigate-dest-mismatch");
                    }
                }
            }
        }
    }
    if header(headers, header::COOKIE.as_str()).is_none() {
        out.add(1, "missing-cookie");
    }
    if headers.len() < 5 {
        out.add(1, "few-headers");
    }
    out
}

/// Backwards-compatible numeric score.
pub fn score(headers: &HeaderMap) -> u8 {
    analyze(headers).score
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
        headers.insert("accept-encoding", "gzip, br".parse().unwrap());
        headers.insert("sec-ch-ua", "\"Chromium\";v=\"130\"".parse().unwrap());
        headers.insert("sec-fetch-mode", "navigate".parse().unwrap());
        headers.insert("sec-fetch-dest", "document".parse().unwrap());
        headers.insert("cookie", "session=abc".parse().unwrap());
        headers.insert("referer", "https://example.com/".parse().unwrap());
        let analysis = analyze(&headers);
        assert!(analysis.score < 2);
        assert!(analysis.reasons.is_empty());
    }

    #[test]
    fn automation_headers_score_high() {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "curl/8.0".parse().unwrap());
        headers.insert("accept", "text/html".parse().unwrap());
        assert!(score(&headers) >= 4);
        assert!(analyze(&headers).reasons.contains(&"automation-ua"));
    }

    #[test]
    fn headless_and_inconsistent_fetch_headers_are_flagged() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "user-agent",
            "Mozilla/5.0 HeadlessChrome/130.0.0.0".parse().unwrap(),
        );
        headers.insert("accept", "text/html".parse().unwrap());
        headers.insert("accept-language", "en".parse().unwrap());
        headers.insert("accept-encoding", "gzip".parse().unwrap());
        headers.insert("sec-ch-ua", "\"Chromium\";v=\"130\"".parse().unwrap());
        headers.insert("sec-fetch-mode", "navigate".parse().unwrap());
        headers.insert("sec-fetch-dest", "image".parse().unwrap());
        headers.insert("cookie", "a=1".parse().unwrap());
        let analysis = analyze(&headers);
        assert!(analysis.reasons.contains(&"headless-ua"));
        assert!(analysis.reasons.contains(&"navigate-dest-mismatch"));
        assert!(analysis.score >= 4);
    }
}
