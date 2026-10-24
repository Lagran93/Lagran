//! Origin client — supports HTTP and HTTPS via hyper-rustls

use anyhow::{anyhow, Context, Result};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use lagran_cache::CacheEntry;
use std::sync::Arc;
use tokio::sync::RwLock;

type HttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

#[derive(Clone)]
pub struct OriginClient {
    client: Arc<HttpsClient>,
    base_url: Arc<RwLock<String>>,
}

impl OriginClient {
    pub fn new(base_url: String) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_nodelay(true);

        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http);

        let client = Client::builder(TokioExecutor::new()).build(https);

        Self {
            client: Arc::new(client),
            base_url: Arc::new(RwLock::new(base_url)),
        }
    }

    pub async fn set_base_url(&self, url: String) {
        let mut w = self.base_url.write().await;
        if *w != url {
            tracing::info!(old = %*w, new = %url, "origin base_url changed");
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
        let url = format!(
            "{}{}",
            base.trim_end_matches('/'),
            if path_and_query.starts_with('/') {
                path_and_query.to_string()
            } else {
                format!("/{path_and_query}")
            }
        );

        let mut builder = Request::builder().method("GET").uri(&url);
        for name in ["accept", "accept-language", "user-agent"] {
            if let Some(val) = headers.get(name) {
                builder = builder.header(name, val);
            }
        }
        builder = builder.header("accept-encoding", "identity");

        let req = builder
            .body(Full::new(Bytes::new()))
            .context("build origin request")?;

        let resp = self
            .client
            .request(req)
            .await
            .with_context(|| format!("origin request failed: {url}"))?;

        let status = StatusCode::from_u16(resp.status().as_u16())
            .map_err(|e| anyhow!("invalid status: {e}"))?;

        let mut out_headers = HeaderMap::new();
        for (k, v) in resp.headers().iter() {
            let name = k.as_str();
            if matches!(
                name,
                "connection"
                    | "keep-alive"
                    | "transfer-encoding"
                    | "content-length"
                    | "content-encoding"
                    | "proxy-authenticate"
                    | "proxy-authorization"
                    | "te"
                    | "trailers"
                    | "upgrade"
            ) {
                continue;
            }
            if let Ok(name) = HeaderName::from_bytes(k.as_ref()) {
                if let Ok(val) = HeaderValue::from_bytes(v.as_bytes()) {
                    out_headers.insert(name, val);
                }
            }
        }

        let body = resp
            .into_body()
            .collect()
            .await
            .context("read origin body")?
            .to_bytes();

        Ok((status, out_headers, body))
    }

    pub async fn fetch_as_entry(
        &self,
        path_and_query: &str,
        headers: &HeaderMap,
    ) -> Result<CacheEntry> {
        let (status, headers, body) = self.fetch(path_and_query, headers).await?;
        let headers_vec: Vec<(String, String)> = headers
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|s| (k.as_str().to_string(), s.to_string()))
            })
            .collect();
        Ok(CacheEntry {
            status: status.as_u16(),
            headers: headers_vec,
            body,
        })
    }
}
