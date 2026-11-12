//! Origin client — HTTP/HTTPS via hyper-rustls, with request method/body
//! forwarding and connection pooling.

use crate::cache::policy::{compute_etag, VALIDATOR_SOURCE_HEADER};
use anyhow::{anyhow, Context, Result};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::Request;
use hyper_util::client::legacy::connect::dns::Name;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use lagran_cache::CacheEntry;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::sync::RwLock;
use tower::Service;

type DefaultHttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Resolver for IP origins with a DNS certificate: connect to the configured
/// IP while the HTTP/2 `:authority` remains the SNI hostname. This keeps
/// virtual-host selection and TLS verification correct without forcing
/// HTTP/1.1.
#[derive(Clone)]
struct FixedResolver {
    addr: SocketAddr,
}

impl Service<Name> for FixedResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = std::io::Error;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _name: Name) -> Self::Future {
        std::future::ready(Ok(vec![self.addr].into_iter()))
    }
}

type SniHttpsClient =
    Client<hyper_rustls::HttpsConnector<HttpConnector<FixedResolver>>, Full<Bytes>>;

/// Upstream response as returned by the origin.
pub struct OriginResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
    /// Operator-facing cache diagnostic, set by the handler when a response is
    /// served but not stored.
    pub cache_reason: Option<&'static str>,
}

/// Streaming origin response: status/headers are available before the body is
/// consumed. Used by legacy bypass/video paths so large media is never
/// accumulated in memory.
pub struct OriginStreamResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Incoming,
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
        let mut entry = CacheEntry::new(self.status.as_u16(), headers, self.body);
        let has_etag = entry.header("etag").is_some();
        let has_last_modified = entry.header("last-modified").is_some();
        entry
            .headers
            .retain(|(name, _)| !name.eq_ignore_ascii_case(VALIDATOR_SOURCE_HEADER));
        if has_etag {
            entry
                .headers
                .push((VALIDATOR_SOURCE_HEADER.to_string(), "etag".to_string()));
        } else if has_last_modified {
            entry.headers.push((
                VALIDATOR_SOURCE_HEADER.to_string(),
                "last-modified".to_string(),
            ));
        } else {
            entry
                .headers
                .push(("etag".to_string(), compute_etag(&entry)));
            entry
                .headers
                .push((VALIDATOR_SOURCE_HEADER.to_string(), "computed".to_string()));
        }
        entry
    }
}

#[derive(Clone)]
pub struct OriginClient {
    client: Arc<DefaultHttpsClient>,
    /// SNI clients keyed by `sni|ip:port`.
    sni_clients: Arc<RwLock<HashMap<String, Arc<SniHttpsClient>>>>,
    /// Fallback default origin (legacy single-origin)
    base_url: Arc<RwLock<String>>,
    /// TCP connect timeout applied to every connector this client builds.
    connect_timeout: Duration,
}

/// Headers worth replaying to the origin for a cacheable GET/HEAD.
fn cacheable_forward_headers(headers: &HeaderMap) -> Vec<(&'static str, HeaderValue)> {
    const ALLOW: &[&str] = &[
        "accept",
        "accept-language",
        "user-agent",
        "referer",
        "if-none-match",
        "if-modified-since",
    ];
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

#[allow(deprecated)]
fn build_client(connect_timeout: Duration) -> DefaultHttpsClient {
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_nodelay(true);
    http.set_connect_timeout(Some(connect_timeout));

    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http);
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(64)
        .build(https)
}

#[allow(deprecated)]
fn build_sni_client(addr: SocketAddr, connect_timeout: Duration) -> SniHttpsClient {
    let mut http = HttpConnector::new_with_resolver(FixedResolver { addr });
    http.enforce_http(false);
    http.set_nodelay(true);
    http.set_connect_timeout(Some(connect_timeout));

    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http);
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(64)
        .build(https)
}

impl OriginClient {
    pub fn new(base_url: String) -> Self {
        Self::with_connect_timeout(base_url, Duration::from_secs(5))
    }

    /// Build a client with an explicit TCP connect timeout.
    ///
    /// The connect timeout is independent of how long the origin may take to
    /// send the response: a dead or unreachable origin should fail over in
    /// seconds instead of consuming the per-domain request budget.
    pub fn with_connect_timeout(base_url: String, connect_timeout: Duration) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = build_client(connect_timeout);
        Self {
            client: Arc::new(client),
            sni_clients: Arc::new(RwLock::new(HashMap::new())),
            base_url: Arc::new(RwLock::new(base_url)),
            connect_timeout,
        }
    }

    pub fn connect_timeout_ms(&self) -> u64 {
        self.connect_timeout.as_millis().min(u128::from(u64::MAX)) as u64
    }

    async fn client_for(&self, sni: Option<&str>, addr: Option<SocketAddr>) -> Arc<SniHttpsClient> {
        let sni = sni
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("")
            .to_ascii_lowercase();
        let addr = addr.map(|a| a.to_string()).unwrap_or_default();
        let key = format!("{sni}|{addr}");
        if let Some(client) = self.sni_clients.read().await.get(&key) {
            return client.clone();
        }
        let client = Arc::new(build_sni_client(
            addr.parse().expect("fixed resolver address"),
            self.connect_timeout,
        ));
        self.sni_clients.write().await.insert(key, client.clone());
        client
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
        self.fetch_from_with_sni(base_url, path_and_query, headers, None)
            .await
    }

    pub async fn fetch_from_with_sni(
        &self,
        base_url: &str,
        path_and_query: &str,
        headers: &HeaderMap,
        sni: Option<&str>,
    ) -> Result<(StatusCode, HeaderMap, Bytes)> {
        let resp = self
            .request_with_sni(
                base_url,
                &Method::GET,
                path_and_query,
                headers,
                None,
                false,
                sni,
            )
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
        self.fetch_as_entry_from_with_sni(base_url, path_and_query, headers, None)
            .await
    }

    pub async fn fetch_as_entry_from_with_sni(
        &self,
        base_url: &str,
        path_and_query: &str,
        headers: &HeaderMap,
        sni: Option<&str>,
    ) -> Result<CacheEntry> {
        Ok(self
            .request_with_sni(
                base_url,
                &Method::GET,
                path_and_query,
                headers,
                None,
                false,
                sni,
            )
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
        self.request_with_sni(
            base_url,
            method,
            path_and_query,
            headers,
            body,
            forward_sensitive,
            None,
        )
        .await
    }

    // Origin request dimensions are intentionally explicit here: callers
    // independently control forwarding, body, and TLS identity.
    #[allow(clippy::too_many_arguments)]
    async fn send_with_sni(
        &self,
        base_url: &str,
        method: &Method,
        path_and_query: &str,
        headers: &HeaderMap,
        body: Option<Bytes>,
        forward_sensitive: bool,
        sni: Option<&str>,
    ) -> Result<(StatusCode, HeaderMap, Incoming)> {
        let fixed = sni
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|name| split_ip_base(base_url).map(|addr| (name, addr)));
        let (effective_base, sni_client) = match fixed {
            Some((name, (ip, port))) => (
                base_with_host(base_url, name),
                Some(
                    self.client_for(Some(name), Some(SocketAddr::new(ip, port)))
                        .await,
                ),
            ),
            None => (base_url.to_string(), None),
        };
        let url = build_url(&effective_base, path_and_query)?;

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

        // Preserve a configured upstream Host override. `host` is normally
        // derived from the URI; for IP origins with a DNS certificate this is
        // the virtual-host name.
        if let Some(host) = headers.get(header::HOST) {
            builder = builder.header(header::HOST, host.clone());
        }

        // Preserve the client address for origin-side logging/policies.
        if let Some(xff) = headers.get("x-forwarded-for") {
            builder = builder.header("x-forwarded-for", xff.clone());
        }

        let req = builder
            .body(Full::new(body.unwrap_or_default()))
            .with_context(|| format!("build origin request: {url}"))?;

        let resp = match sni_client {
            Some(client) => client
                .request(req)
                .await
                .with_context(|| format!("origin request failed: {url}"))?,
            None => self
                .client
                .request(req)
                .await
                .with_context(|| format!("origin request failed: {url}"))?,
        };

        let status = StatusCode::from_u16(resp.status().as_u16())
            .map_err(|e| anyhow!("invalid status: {e}"))?;

        let mut out_headers = HeaderMap::new();
        for (k, v) in resp.headers().iter() {
            if is_hop_by_hop(k.as_str()) {
                continue;
            }
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(k.as_ref()),
                HeaderValue::from_bytes(v.as_bytes()),
            ) {
                out_headers.insert(name, val);
            }
        }

        Ok((status, out_headers, resp.into_body()))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn request_with_sni(
        &self,
        base_url: &str,
        method: &Method,
        path_and_query: &str,
        headers: &HeaderMap,
        body: Option<Bytes>,
        forward_sensitive: bool,
        sni: Option<&str>,
    ) -> Result<OriginResponse> {
        self.request_with_sni_limit(
            base_url,
            method,
            path_and_query,
            headers,
            body,
            forward_sensitive,
            sni,
            64 * 1024 * 1024,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn request_with_sni_limit(
        &self,
        base_url: &str,
        method: &Method,
        path_and_query: &str,
        headers: &HeaderMap,
        body: Option<Bytes>,
        forward_sensitive: bool,
        sni: Option<&str>,
        max_body: usize,
    ) -> Result<OriginResponse> {
        let (status, headers, body) = self
            .send_with_sni(
                base_url,
                method,
                path_and_query,
                headers,
                body,
                forward_sensitive,
                sni,
            )
            .await?;
        let body = Limited::new(body, max_body)
            .collect()
            .await
            .map_err(|e| anyhow!("read origin body: {e}"))?
            .to_bytes();
        Ok(OriginResponse {
            status,
            headers,
            body,
            cache_reason: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn request_stream_with_sni(
        &self,
        base_url: &str,
        method: &Method,
        path_and_query: &str,
        headers: &HeaderMap,
        body: Option<Bytes>,
        forward_sensitive: bool,
        sni: Option<&str>,
    ) -> Result<OriginStreamResponse> {
        let (status, headers, body) = self
            .send_with_sni(
                base_url,
                method,
                path_and_query,
                headers,
                body,
                forward_sensitive,
                sni,
            )
            .await?;
        Ok(OriginStreamResponse {
            status,
            headers,
            body,
        })
    }
}

fn split_ip_base(base_url: &str) -> Option<(IpAddr, u16)> {
    let uri: Uri = base_url.parse().ok()?;
    let host = uri.host()?;
    let ip: IpAddr = host.parse().ok()?;
    let port = uri.port_u16().unwrap_or_else(|| {
        if uri.scheme_str() == Some("http") {
            80
        } else {
            443
        }
    });
    Some((ip, port))
}

fn base_with_host(base_url: &str, host: &str) -> String {
    let Ok(uri) = base_url.parse::<Uri>() else {
        return base_url.to_string();
    };
    let scheme = uri.scheme_str().unwrap_or("https");
    match uri.port_u16() {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
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
    fn ip_base_is_split_and_rewritten_to_sni_host() {
        assert_eq!(
            split_ip_base("https://45.63.84.225:443"),
            Some(("45.63.84.225".parse().unwrap(), 443))
        );
        assert_eq!(
            base_with_host("https://45.63.84.225", "test-origin.akgo.net"),
            "https://test-origin.akgo.net"
        );
        assert_eq!(
            base_with_host("https://45.63.84.225:8443", "test-origin.akgo.net"),
            "https://test-origin.akgo.net:8443"
        );
        assert_eq!(split_ip_base("https://origin.test"), None);
    }

    #[test]
    fn origin_entry_gets_computed_etag_when_origin_omits_it() {
        let entry = OriginResponse {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"hello"),
            cache_reason: None,
        }
        .into_entry();
        assert!(entry.header("etag").is_some());
    }

    #[test]
    fn hop_by_hop_detection() {
        assert!(is_hop_by_hop("connection"));
        assert!(is_hop_by_hop("transfer-encoding"));
        assert!(!is_hop_by_hop("content-type"));
        assert!(!is_hop_by_hop("set-cookie"));
    }

    #[test]
    fn connect_timeout_is_configurable_and_reported() {
        let client = OriginClient::with_connect_timeout(
            "https://origin.test".into(),
            Duration::from_millis(2_500),
        );
        assert_eq!(client.connect_timeout_ms(), 2_500);
    }
}
