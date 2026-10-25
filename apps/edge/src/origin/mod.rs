//! Origin client — HTTP/HTTPS via hyper-rustls, with request method/body
//! forwarding and connection pooling.

use anyhow::{anyhow, Context, Result};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use lagran_cache::CacheEntry;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

type HttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Upstream response as returned by the origin.
pub struct OriginResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl OriginResponse {
    pub fn into_entry(self) -> CacheEntry {
        let headers = self
            .headers
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|s| (k.as_str().to_string(), s.to_string()))
            })
            .collect();
        CacheEntry::new(self.status.as_u16(), headers, self.body)
    }
}

#[derive(Clone)]
pub struct OriginClient {
    client: Arc<HttpsClient>,
    /// Fallback default origin (legacy single-origin)
    base_url: Arc<RwLock<String>>,
}

/// Headers worth replaying to the origin for a cacheable GET/HEAD.
fn cacheable_forward_headers(headers: &HeaderMap) -> Vec<(&'static str, HeaderValue)> {
    const ALLOW: &[&str] = &["accept", "accept-language", "user-agent", "referer"];
    let mut out = Vec::with_capacity(ALLOW.len());
    for name in ALLOW {
        if let Some(v) = headers.get(*name) {
            out.push((*name, v.clone()));
        }
    }
    out
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
            | "expect"
    )
}

impl OriginClient {
    pub fn new(base_url: String) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_nodelay(true);
        http.set_connect_timeout(Some(Duration::from_secs(5)));

        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http);

        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(64)
            .build(https);

        Self {
            client: Arc::new(client),
            base_url: Arc::new(RwLock::new(base_url)),
        }
    }

    pub async fn set_base_url(&self, url: String) {
        let mut w = self.base_url.write().await;
        if *w != url {
            tracing::info!(old = %*w, new = %url, "default origin base_url changed");
            *w = url;
        }
    }

    pub async fn base_url(&self) -> String {
        self.base_url.read().await.clone()
    }

    pub async fn fetch(
        &self,
        path_and_query: &str,
        headers: &HeaderMap,
    ) -> Result<(StatusCode, HeaderMap, Bytes)> {
        let base = self.base_url.read().await.clone();
        let resp = self
            .request(&base, &Method::GET, path_and_query, headers, None, false)
            .await?;
        Ok((resp.status, resp.headers, resp.body))
    }

    pub async fn fetch_from(
        &self,
        base_url: &str,
        path_and_query: &str,
        headers: &HeaderMap,
    ) -> Result<(StatusCode, HeaderMap, Bytes)> {
        let resp = self
            .request(base_url, &Method::GET, path_and_query, headers, None, false)
            .await?;
        Ok((resp.status, resp.headers, resp.body))
    }

    pub async fn fetch_as_entry(
        &self,
        path_and_query: &str,
        headers: &HeaderMap,
    ) -> Result<CacheEntry> {
        let base = self.base_url.read().await.clone();
        self.fetch_as_entry_from(&base, path_and_query, headers)
            .await
    }

    pub async fn fetch_as_entry_from(
        &self,
        base_url: &str,
        path_and_query: &str,
        headers: &HeaderMap,
    ) -> Result<CacheEntry> {
        Ok(self
            .request(base_url, &Method::GET, path_and_query, headers, None, false)
            .await?
            .into_entry())
    }

    /// Proxy one request to the origin.
    ///
    /// `forward_sensitive` selects between the cacheable GET allow-list (false)
    /// and replaying all end-to-end headers, including cookies/authorization
    /// and conditional headers, for bypass/dynamic traffic (true).
    pub async fn request(
        &self,
        base_url: &str,
        method: &Method,
        path_and_query: &str,
        headers: &HeaderMap,
        body: Option<Bytes>,
        forward_sensitive: bool,
    ) -> Result<OriginResponse> {
        let url = build_url(base_url, path_and_query)?;

        let mut builder = Request::builder().method(method.clone()).uri(&url);

        if forward_sensitive {
            for (name, value) in headers.iter() {
                let n = name.as_str();
                if is_hop_by_hop(n) || n.eq_ignore_ascii_case("accept-encoding") {
                    continue;
                }
                builder = builder.header(name.clone(), value.clone());
            }
            // Replay the client's encoding preferences for pass-through traffic.
            if let Some(v) = headers.get("accept-encoding") {
                builder = builder.header("accept-encoding", v.clone());
            }
        } else {
            for (name, value) in cacheable_forward_headers(headers) {
                builder = builder.header(name, value);
            }
            // Force identity so the stored body is directly reusable.
            builder = builder.header("accept-encoding", "identity");
        }

        // Preserve the client address for origin-side logging/policies.
        if let Some(xff) = headers.get("x-forwarded-for") {
            builder = builder.header("x-forwarded-for", xff.clone());
        }

        let req = builder
            .body(Full::new(body.unwrap_or_default()))
            .with_context(|| format!("build origin request: {url}"))?;

        let resp = self
            .client
            .request(req)
            .await
            .with_context(|| format!("origin request failed: {url}"))?;

        let status = StatusCode::from_u16(resp.status().as_u16())
            .map_err(|e| anyhow!("invalid status: {e}"))?;

        let mut out_headers = HeaderMap::new();
        for (k, v) in resp.headers().iter() {
            if is_hop_by_hop(k.as_str()) || k.as_str().eq_ignore_ascii_case("content-length") {
                continue;
            }
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(k.as_ref()),
                HeaderValue::from_bytes(v.as_bytes()),
            ) {
                out_headers.insert(name, val);
            }
        }

        let body = resp
            .into_body()
            .collect()
            .await
            .context("read origin body")?
            .to_bytes();

        Ok(OriginResponse {
            status,
            headers: out_headers,
            body,
        })
    }
}

fn build_url(base_url: &str, path_and_query: &str) -> Result<String> {
    let base = base_url.trim_end_matches('/');
    if !(base.starts_with("http://") || base.starts_with("https://")) {
        return Err(anyhow!(
            "origin url must start with http:// or https://: {base}"
        ));
    }
    let path = if path_and_query.starts_with('/') {
        path_and_query.to_string()
    } else {
        format!("/{path_and_query}")
    };
    Ok(format!("{base}{path}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_base_and_path() {
        assert_eq!(
            build_url("http://origin.test:8080/", "/a?b=1").unwrap(),
            "http://origin.test:8080/a?b=1"
        );
        assert_eq!(
            build_url("https://origin.test", "a").unwrap(),
            "https://origin.test/a"
        );
        assert!(build_url("origin.test", "/a").is_err());
    }

    #[test]
    fn hop_by_hop_detection() {
        assert!(is_hop_by_hop("connection"));
        assert!(is_hop_by_hop("transfer-encoding"));
        assert!(!is_hop_by_hop("content-type"));
        assert!(!is_hop_by_hop("set-cookie"));
    }
}
