//! Browser challenge (Cloudflare-style interstitial) with a proof-of-work and a
//! signed clearance cookie.
//!
//! Flow:
//! 1. A WAF rule returns action `challenge` and the client has no clearance
//!    cookie, so the edge renders an interstitial at the requested URL.
//! 2. The inline script brute-forces `sha256(nonce:counter)` until it has the
//!    configured number of leading hex zeroes, then calls
//!    `/__lagran/challenge/verify?n=…&a=…&next=…`.
//! 3. The edge verifies the HMAC-signed nonce and the PoW, sets an HttpOnly
//!    clearance cookie and redirects back to `next`.
//!
//! The nonce and cookie are HMAC-SHA256 signed with a process secret
//! (`CHALLENGE_SECRET`, falling back to a random value), so no server-side
//! state is required.

use crate::server::handler::AppState;
use crate::server::host_util::{self, TlsSni};
use axum::{
    body::Body,
    extract::{Query, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Request, StatusCode},
    response::{Html, IntoResponse, Response},
};
use ring::hmac;
use ring::rand::SecureRandom;
use serde::Deserialize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub const CLEARANCE_COOKIE: &str = "lagran_clearance";
const NONCE_TTL_SECS: u64 = 300;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn hmac_hex(secret: &str, message: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let tag = hmac::sign(&key, message.as_bytes());
    hex(&tag.as_ref()[..16])
}

fn hmac_ok(secret: &str, message: &str, signature: &str) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let expected = hmac::sign(&key, message.as_bytes());
    hex(&expected.as_ref()[..16]) == signature
}

fn random_hex() -> String {
    let mut buf = [0u8; 8];
    if ring::rand::SystemRandom::new().fill(&mut buf).is_ok() {
        hex(&buf)
    } else {
        // Extremely unlikely; still keep nonces unique enough for verification.
        format!("{:016x}", now_secs())
    }
}

/// SHA-256 hex digest, matching the JS implementation embedded in the page.
pub fn sha256_hex(input: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, input.as_bytes());
    hex(digest.as_ref())
}

pub fn pow_ok(nonce: &str, answer: &str, difficulty: u8) -> bool {
    let difficulty = difficulty.clamp(1, 6);
    let prefix = "0".repeat(difficulty as usize);
    sha256_hex(&format!("{nonce}:{answer}")).starts_with(&prefix)
}

pub fn issue_nonce(host: &str, secret: &str) -> String {
    let ts = now_secs();
    let rnd = random_hex();
    let sig = hmac_hex(secret, &format!("challenge|{host}|{ts}|{rnd}"));
    format!("{ts}.{rnd}.{sig}")
}

pub fn verify_nonce(host: &str, nonce: &str, secret: &str) -> bool {
    let parts: Vec<&str> = nonce.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    let Ok(ts) = parts[0].parse::<u64>() else {
        return false;
    };
    if now_secs().saturating_sub(ts) > NONCE_TTL_SECS {
        return false;
    }
    let message = format!("challenge|{host}|{ts}|{}", parts[1]);
    hmac_ok(secret, &message, parts[2])
}

fn clearance_signature(host: &str, ts: u64, secret: &str) -> String {
    hmac_hex(secret, &format!("clearance|{host}|{ts}"))
}

pub fn clearance_value(host: &str, ttl_secs: u64, secret: &str) -> (String, u64) {
    let ts = now_secs();
    let ttl = ttl_secs.clamp(60, 86_400);
    (
        format!("{ts}.{}", clearance_signature(host, ts, secret)),
        ttl,
    )
}

fn cookie_from_headers<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k.trim() == name {
                return Some(v.trim());
            }
        }
    }
    None
}

pub fn has_clearance(headers: &HeaderMap, host: &str, ttl_secs: u64, secret: &str) -> bool {
    let Some(value) = cookie_from_headers(headers, CLEARANCE_COOKIE) else {
        return false;
    };
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 2 {
        return false;
    }
    let Ok(ts) = parts[0].parse::<u64>() else {
        return false;
    };
    let ttl = ttl_secs.clamp(60, 86_400);
    if now_secs() > ts.saturating_add(ttl) {
        return false;
    }
    hmac_ok(secret, &format!("clearance|{host}|{ts}"), parts[1])
}

fn secure_request(req: &Request<Body>, headers: &HeaderMap) -> bool {
    if req.extensions().get::<TlsSni>().is_some() {
        return true;
    }
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("https"))
        .unwrap_or(false)
}

fn safe_next(next: &str) -> String {
    let next = next.trim();
    if next.starts_with('/') && !next.starts_with("//") && !next.contains(['\r', '\n']) {
        next.to_string()
    } else {
        "/".to_string()
    }
}

/// The interstitial served at the original URL.
pub fn page(host: &str, nonce: &str, next: &str, difficulty: u8, secure: bool) -> Response {
    let nonce_json = serde_json::to_string(nonce).unwrap_or_else(|_| "\"\"".into());
    let next_json = serde_json::to_string(&safe_next(next)).unwrap_or_else(|_| "\"/\"".into());
    let difficulty = difficulty.clamp(1, 6);
    let host_html = host
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let html = PAGE_TEMPLATE
        .replace("__NONCE_JSON__", &nonce_json)
        .replace("__NEXT_JSON__", &next_json)
        .replace("__DIFFICULTY__", &difficulty.to_string())
        .replace("__HOST__", &host_html);

    let mut response = (
        StatusCode::FORBIDDEN,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(html),
    )
        .into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'self'",
        ),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        "x-lagran-challenge",
        HeaderValue::from_static(if secure { "1; secure" } else { "1" }),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

#[derive(Deserialize)]
pub struct VerifyQuery {
    pub n: String,
    pub a: String,
    pub next: Option<String>,
}

/// `/__lagran/challenge/verify` — validate PoW + nonce, mint the clearance cookie.
pub async fn verify(
    State(state): State<Arc<AppState>>,
    Query(q): Query<VerifyQuery>,
    req: Request<Body>,
) -> Response {
    let headers = req.headers().clone();
    let host = host_util::resolve_request_host(&req);
    let entry = state.domains.get(&host).await;

    let (difficulty, ttl) = match entry {
        Some(entry) => (
            entry.waf.challenge_difficulty.clamp(1, 6),
            entry.waf.challenge_ttl_secs,
        ),
        None => (4, 1800),
    };

    if !verify_nonce(&host, &q.n, &state.challenge_secret) {
        return error_page("验证已过期", "质询已过期，请返回原页面刷新后重试。");
    }
    if !pow_ok(&q.n, &q.a, difficulty) {
        return error_page("验证未通过", "工作量证明不正确，请返回原页面重试。");
    }

    let (value, ttl) = clearance_value(&host, ttl, &state.challenge_secret);
    let mut cookie =
        format!("{CLEARANCE_COOKIE}={value}; Path=/; Max-Age={ttl}; HttpOnly; SameSite=Lax");
    if secure_request(&req, &headers) {
        cookie.push_str("; Secure");
    }

    let next = safe_next(q.next.as_deref().unwrap_or("/"));
    let mut response = StatusCode::SEE_OTHER.into_response();
    let headers = response.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&next) {
        headers.insert(header::LOCATION, v);
    }
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        headers.insert(header::SET_COOKIE, v);
    }
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Direct verification used by the native Pingora path.
pub async fn verify_direct(
    state: &Arc<AppState>,
    host: &str,
    headers: &HeaderMap,
    n: &str,
    a: &str,
    next: Option<&str>,
    secure: bool,
) -> Response {
    let entry = state.domains.get(host).await;
    let (difficulty, ttl) = match entry {
        Some(entry) => (
            entry.waf.challenge_difficulty.clamp(1, 6),
            entry.waf.challenge_ttl_secs,
        ),
        None => (4, 1800),
    };
    if !verify_nonce(host, n, &state.challenge_secret) {
        return error_page("验证已过期", "质询已过期，请返回原页面刷新后重试。");
    }
    if !pow_ok(n, a, difficulty) {
        return error_page("验证未通过", "工作量证明不正确，请返回原页面重试。");
    }

    let (value, ttl) = clearance_value(host, ttl, &state.challenge_secret);
    let mut cookie =
        format!("{CLEARANCE_COOKIE}={value}; Path=/; Max-Age={ttl}; HttpOnly; SameSite=Lax");
    if secure {
        cookie.push_str("; Secure");
    }
    let next = safe_next(next.unwrap_or("/"));
    let mut response = StatusCode::SEE_OTHER.into_response();
    let out = response.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&next) {
        out.insert(header::LOCATION, v);
    }
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        out.insert(header::SET_COOKIE, v);
    }
    out.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    let _ = headers;
    response
}

fn error_page(title: &str, message: &str) -> Response {
    let html = format!(
        r#"<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{title} | Lagran CDN</title>
<style>body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f5f7fa;font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;color:#1d2129}}
.card{{max-width:440px;padding:32px;background:#fff;border:1px solid #e5e6eb;border-radius:12px;box-shadow:0 8px 24px rgba(29,33,41,.08);text-align:center}}
h1{{font-size:18px;margin:0 0 8px}}p{{color:#4e5969;font-size:14px;line-height:1.7;margin:0}}</style></head>
<body><div class="card"><h1>{title}</h1><p>{message}</p></div></body></html>"#
    );
    let mut response = (StatusCode::FORBIDDEN, Html(html)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

const PAGE_TEMPLATE: &str = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>安全验证 | __HOST__</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: #f5f7fa; color: #1d2129;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif; }
  .card { width: min(460px, calc(100vw - 32px)); padding: 32px; background: #fff;
    border: 1px solid #e5e6eb; border-radius: 12px; box-shadow: 0 8px 24px rgba(29,33,41,.08); text-align: center; }
  .logo { width: 48px; height: 48px; margin: 0 auto 16px; border-radius: 12px;
    background: linear-gradient(135deg,#1677ff,#52a8ff); color: #fff; font-weight: 700; font-size: 20px;
    display: flex; align-items: center; justify-content: center; }
  h1 { font-size: 18px; margin: 0 0 8px; font-weight: 600; }
  p { margin: 0 0 18px; color: #4e5969; font-size: 14px; line-height: 1.7; }
  .progress { height: 6px; background: #f2f3f5; border-radius: 3px; overflow: hidden; margin: 18px 0 10px; }
  .bar { height: 100%; width: 8%; background: #1677ff; border-radius: 3px; transition: width .2s ease; }
  .status { font-size: 12px; color: #86909c; }
  .foot { margin-top: 18px; font-size: 12px; color: #86909c; }
  noscript { display: block; margin-top: 16px; color: #f53f3f; font-size: 13px; }
</style>
</head>
<body>
  <div class="card">
    <div class="logo">L</div>
    <h1>正在进行安全验证</h1>
    <p>正在确认你的浏览器，完成后会自动跳转。通常只需要几秒钟。</p>
    <div class="progress"><div class="bar" id="bar"></div></div>
    <div class="status" id="status">计算中…</div>
    <div class="foot">Lagran CDN · 由 WAF 质询保护</div>
    <noscript>当前浏览器禁用了 JavaScript，无法完成安全验证。请启用后刷新页面。</noscript>
  </div>
<script>
(function () {
  var nonce = __NONCE_JSON__;
  var next = __NEXT_JSON__;
  var difficulty = __DIFFICULTY__;
  var target = new Array(difficulty + 1).join('0');

  /* Compact SHA-256 (hex output), shared by all modern browsers. */
  function sha256(ascii) {
    function rightRotate(value, amount) { return (value >>> amount) | (value << (32 - amount)); }
    var mathPow = Math.pow, maxWord = mathPow(2, 32), result = '', words = [], i, j;
    var asciiBitLength = ascii.length * 8;
    var hash = sha256.h = sha256.h || [];
    var k = sha256.k = sha256.k || [];
    var primeCounter = k.length, isComposite = {};
    for (var candidate = 2; primeCounter < 64; candidate++) {
      if (!isComposite[candidate]) {
        for (i = 0; i < 313; i += candidate) isComposite[i] = candidate;
        hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
        k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
      }
    }
    ascii += '\x80';
    while (ascii.length % 64 - 56) ascii += '\x00';
    for (i = 0; i < ascii.length; i++) {
      j = ascii.charCodeAt(i);
      if (j >> 8) return '';
      words[i >> 2] |= j << ((3 - i) % 4) * 8;
    }
    words[words.length] = (asciiBitLength / maxWord) | 0;
    words[words.length] = asciiBitLength;
    for (j = 0; j < words.length;) {
      var w = words.slice(j, j += 16);
      var oldHash = hash;
      hash = hash.slice(0, 8);
      for (i = 0; i < 64; i++) {
        var w15 = w[i - 15], w2 = w[i - 2];
        var a = hash[0], e = hash[4];
        var temp1 = hash[7]
          + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25))
          + ((e & hash[5]) ^ ((~e) & hash[6]))
          + k[i]
          + (w[i] = (i < 16) ? w[i] : (
              w[i - 16]
              + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3))
              + w[i - 7]
              + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))
            ) | 0
          );
        var temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22))
          + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));
        hash = [(temp1 + temp2) | 0].concat(hash);
        hash[4] = (hash[4] + temp1) | 0;
      }
      for (i = 0; i < 8; i++) hash[i] = (hash[i] + oldHash[i]) | 0;
    }
    for (i = 0; i < 8; i++) {
      for (j = 3; j + 1; j--) {
        var b = (hash[i] >> (j * 8)) & 255;
        result += ((b < 16) ? '0' : '') + b.toString(16);
      }
    }
    return result;
  }

  var counter = 0;
  var bar = document.getElementById('bar');
  var statusEl = document.getElementById('status');
  var started = Date.now();

  function solve() {
    var deadline = Date.now() + 250;
    while (Date.now() < deadline) {
      var h = sha256(nonce + ':' + counter);
      if (h.slice(0, difficulty) === target) {
        statusEl.textContent = '验证通过，正在跳转…';
        window.location.href = '/__lagran/challenge/verify?n=' + encodeURIComponent(nonce)
          + '&a=' + encodeURIComponent(counter) + '&next=' + encodeURIComponent(next);
        return;
      }
      counter += 1;
    }
    var elapsed = (Date.now() - started) / 1000;
    var pct = Math.min(92, 8 + elapsed * 6);
    bar.style.width = pct + '%';
    statusEl.textContent = '计算中… 已尝试 ' + counter.toLocaleString() + ' 次';
    setTimeout(solve, 0);
  }
  solve();
})();
</script>
</body>
</html>"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_roundtrip_and_expiry() {
        let host = "cdn.test";
        let nonce = issue_nonce(host, "secret");
        assert!(verify_nonce(host, &nonce, "secret"));
        assert!(!verify_nonce(host, &nonce, "other-secret"));
        assert!(!verify_nonce("evil.test", &nonce, "secret"));

        // Tampered timestamp is rejected.
        let mut parts: Vec<&str> = nonce.split('.').collect();
        parts[0] = "1";
        assert!(!verify_nonce(host, &parts.join("."), "secret"));
    }

    #[test]
    fn pow_matches_sha256() {
        let nonce = "123.abc";
        let mut answer = 0u64;
        while !pow_ok(nonce, &answer.to_string(), 2) {
            answer += 1;
            assert!(answer < 10_000, "difficulty 2 should be found quickly");
        }
        assert!(pow_ok(nonce, &answer.to_string(), 2));
        assert!(!pow_ok(nonce, &answer.to_string(), 6));
    }

    #[test]
    fn clearance_cookie_roundtrip() {
        let host = "cdn.test";
        let (value, ttl) = clearance_value(host, 300, "secret");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("a=1; {CLEARANCE_COOKIE}={value}")).unwrap(),
        );
        assert!(has_clearance(&headers, host, ttl, "secret"));
        assert!(!has_clearance(&headers, host, ttl, "other-secret"));
        assert!(!has_clearance(&headers, "evil.test", ttl, "secret"));
        assert!(!has_clearance(&HeaderMap::new(), host, ttl, "secret"));
    }

    #[test]
    fn next_redirect_is_sanitised() {
        assert_eq!(safe_next("/a?b=1"), "/a?b=1");
        assert_eq!(safe_next("//evil.test"), "/");
        assert_eq!(safe_next("https://evil.test"), "/");
        assert_eq!(safe_next("/ok\r\nX: y"), "/");
    }
}
