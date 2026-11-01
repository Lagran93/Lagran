//! Shared Control → Edge agent HTTP client.
//!
//! One pooled client for purge/reload/cert/challenge callbacks, with a bounded
//! per-attempt timeout and one retry for transport/5xx failures.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::http::HeaderMap;
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::OnceLock;
use std::time::Duration;

type EdgeClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
const ATTEMPTS: usize = 2;

pub fn client() -> &'static EdgeClient {
    static CLIENT: OnceLock<EdgeClient> = OnceLock::new();
    CLIENT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut http = HttpConnector::new();
        http.set_nodelay(true);
        http.set_connect_timeout(Some(Duration::from_secs(3)));
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http);
        Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(60))
            .pool_max_idle_per_host(16)
            .build(https)
    })
}

async fn send_once(
    method: &str,
    url: &str,
    body: Bytes,
    token: &str,
) -> Result<(u16, Bytes), String> {
    send_once_timeout(method, url, body, token, ATTEMPT_TIMEOUT).await
}

async fn send_once_timeout(
    method: &str,
    url: &str,
    body: Bytes,
    token: &str,
    timeout: Duration,
) -> Result<(u16, Bytes), String> {
    let req = Request::builder()
        .method(method)
        .uri(url)
        .header("content-type", "application/json")
        .header("x-lagran-agent-token", token)
        .body(Full::new(body))
        .map_err(|e| format!("build callback request {url}: {e}"))?;
    let response = tokio::time::timeout(timeout, client().request(req))
        .await
        .map_err(|_| format!("callback timeout after {timeout:?}: {url}"))?
        .map_err(|e| format!("callback transport error {url}: {e}"))?;
    let status = response.status().as_u16();
    let bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("callback body error {url}: {e}"))?
        .to_bytes();
    Ok((status, bytes))
}

/// Send a JSON body with an explicit method; ignore the response body. Retries once.
pub async fn request_ok<B: Serialize>(
    method: &str,
    url: &str,
    body: &B,
    token: &str,
) -> Result<(), String> {
    let bytes = Bytes::from(serde_json::to_vec(body).map_err(|e| e.to_string())?);
    let mut last = String::new();
    for attempt in 0..ATTEMPTS {
        match send_once(method, url, bytes.clone(), token).await {
            Ok((status, _body)) if (200..300).contains(&status) => return Ok(()),
            Ok((status, body)) if status >= 500 && attempt + 1 < ATTEMPTS => {
                last = format!("HTTP {status}: {}", preview(&body));
            }
            Ok((status, body)) => return Err(format!("HTTP {status}: {}", preview(&body))),
            Err(e) if attempt + 1 < ATTEMPTS => last = e,
            Err(e) => return Err(e),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(if last.is_empty() {
        "callback failed".into()
    } else {
        last
    })
}

pub async fn post_json_ok<B: Serialize>(url: &str, body: &B, token: &str) -> Result<(), String> {
    request_ok("POST", url, body, token).await
}

pub async fn put_json_ok<B: Serialize>(url: &str, body: &B, token: &str) -> Result<(), String> {
    request_ok("PUT", url, body, token).await
}

/// Send a JSON body and decode a JSON response. Retries once.
pub async fn request_json<T: DeserializeOwned, B: Serialize>(
    method: &str,
    url: &str,
    body: &B,
    token: &str,
) -> Result<T, String> {
    let bytes = Bytes::from(serde_json::to_vec(body).map_err(|e| e.to_string())?);
    let mut last = String::new();
    for attempt in 0..ATTEMPTS {
        match send_once(method, url, bytes.clone(), token).await {
            Ok((status, body)) if (200..300).contains(&status) => {
                return serde_json::from_slice(&body)
                    .map_err(|e| format!("invalid callback JSON from {url}: {e}"));
            }
            Ok((status, body)) if status >= 500 && attempt + 1 < ATTEMPTS => {
                last = format!("HTTP {status}: {}", preview(&body));
            }
            Ok((status, body)) => return Err(format!("HTTP {status}: {}", preview(&body))),
            Err(e) if attempt + 1 < ATTEMPTS => last = e,
            Err(e) => return Err(e),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(if last.is_empty() {
        "callback failed".into()
    } else {
        last
    })
}

/// Same as `request_json`, but with a caller-supplied deadline and no retry.
/// Cache diagnostics may legitimately wait for a slow origin/range probe.
pub async fn request_json_timeout<T: DeserializeOwned, B: Serialize>(
    method: &str,
    url: &str,
    body: &B,
    token: &str,
    timeout: Duration,
) -> Result<T, String> {
    let bytes = Bytes::from(serde_json::to_vec(body).map_err(|e| e.to_string())?);
    let (status, response) = send_once_timeout(method, url, bytes, token, timeout).await?;
    if !(200..300).contains(&status) {
        return Err(format!("HTTP {status}: {}", preview(&response)));
    }
    serde_json::from_slice(&response).map_err(|e| format!("invalid callback JSON from {url}: {e}"))
}

/// Public callback helper for alert notifications. The caller supplies all
/// headers; this does not attach an edge agent token.
pub async fn post_json_with_headers<B: Serialize>(
    url: &str,
    body: &B,
    headers: &[(&str, &str)],
) -> Result<(u16, Bytes), String> {
    let bytes = Bytes::from(serde_json::to_vec(body).map_err(|e| e.to_string())?);
    let mut builder = Request::builder()
        .method("POST")
        .uri(url)
        .header("content-type", "application/json");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let req = builder
        .body(Full::new(bytes))
        .map_err(|e| format!("build notification request {url}: {e}"))?;
    let response = tokio::time::timeout(Duration::from_secs(10), client().request(req))
        .await
        .map_err(|_| format!("notification timeout: {url}"))?
        .map_err(|e| format!("notification transport error {url}: {e}"))?;
    let status = response.status().as_u16();
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("notification body error {url}: {e}"))?
        .to_bytes();
    Ok((status, body))
}

/// Diagnostic GET: returns status/headers/body for cache troubleshooting.
pub async fn get_response(
    url: &str,
    headers: &[(&str, &str)],
) -> Result<(u16, HeaderMap, Bytes), String> {
    let mut builder = Request::builder().method("GET").uri(url);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let req = builder
        .body(Full::new(Bytes::new()))
        .map_err(|e| format!("build diagnostic request: {e}"))?;
    let response = tokio::time::timeout(Duration::from_secs(15), client().request(req))
        .await
        .map_err(|_| "diagnostic request timed out".to_string())?
        .map_err(|e| format!("diagnostic request failed: {e}"))?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("diagnostic body error: {e}"))?
        .to_bytes();
    Ok((status, headers, body))
}

fn preview(bytes: &Bytes) -> String {
    String::from_utf8_lossy(bytes).chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    #[tokio::test]
    async fn retries_a_transient_5xx_once() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_srv = attempts.clone();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let n = attempts_srv.fetch_add(1, Ordering::Relaxed) + 1;
                let mut stream = stream;
                thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf);
                    let (status, body) = if n == 1 {
                        ("500 Internal Server Error", "temporary")
                    } else {
                        ("200 OK", "{}")
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes());
                });
            }
        });

        let url = format!("http://127.0.0.1:{port}/__lagran/config/reload");
        post_json_ok(&url, &serde_json::json!({}), "token")
            .await
            .unwrap();
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
    }
}
