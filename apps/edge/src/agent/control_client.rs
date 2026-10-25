//! Shared HTTP(S) client for edge → control-plane calls.
//!
//! Supports `http://` and `https://` control URLs, reuses connections, adds the
//! agent token header, and applies a request timeout.

use crate::config::EdgeConfig;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;
use std::time::Duration;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

type HttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

#[derive(Clone)]
pub struct ControlClient {
    client: Arc<HttpsClient>,
    base: Arc<String>,
    token: Arc<String>,
}

impl ControlClient {
    pub fn new(config: &EdgeConfig) -> Self {
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
            .pool_max_idle_per_host(16)
            .build(https);

        Self {
            client: Arc::new(client),
            base: Arc::new(config.control_url.trim_end_matches('/').to_string()),
            token: Arc::new(config.agent_token.clone()),
        }
    }

    pub fn endpoint(&self, path: &str) -> String {
        let path = path.trim_start_matches('/');
        format!("{}/{}", self.base, path)
    }

    pub fn has_https(&self) -> bool {
        self.base.starts_with("https://")
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<Bytes>,
        content_type: Option<&str>,
    ) -> Result<Bytes, String> {
        let url = self.endpoint(path);
        let mut builder = Request::builder().method(method).uri(&url);
        if let Some(ct) = content_type {
            builder = builder.header("content-type", ct);
        }
        if !self.token.is_empty() {
            builder = builder.header("x-lagran-agent-token", self.token.as_str());
        }
        let req = builder
            .body(Full::new(body.unwrap_or_default()))
            .map_err(|e| format!("build request {url}: {e}"))?;

        let send = async {
            let resp = self.client.request(req).await.map_err(|e| e.to_string())?;
            let status = resp.status();
            let bytes = resp
                .into_body()
                .collect()
                .await
                .map_err(|e| e.to_string())?
                .to_bytes();
            if !status.is_success() {
                return Err(format!(
                    "HTTP {status}: {}",
                    String::from_utf8_lossy(&bytes)
                        .chars()
                        .take(200)
                        .collect::<String>()
                ));
            }
            Ok(bytes)
        };

        tokio::time::timeout(REQUEST_TIMEOUT, send)
            .await
            .map_err(|_| format!("timeout after {REQUEST_TIMEOUT:?}: {url}"))?
    }

    pub async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, String> {
        let bytes = self.send("GET", path, None, None).await?;
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid JSON from {path}: {e}"))
    }

    pub async fn post_json<B: Serialize>(&self, path: &str, body: &B) -> Result<(), String> {
        let bytes = serde_json::to_vec(body).map_err(|e| e.to_string())?;
        self.send(
            "POST",
            path,
            Some(Bytes::from(bytes)),
            Some("application/json"),
        )
        .await
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(control_url: &str, token: &str) -> EdgeConfig {
        EdgeConfig {
            control_url: control_url.to_string(),
            agent_token: token.to_string(),
            ..EdgeConfig::default()
        }
    }

    #[test]
    fn endpoint_joins_without_double_slash() {
        let c = ControlClient::new(&config("http://control.test:8080/", ""));
        assert_eq!(
            c.endpoint("/api/v1/config"),
            "http://control.test:8080/api/v1/config"
        );
        assert_eq!(
            c.endpoint("api/v1/config"),
            "http://control.test:8080/api/v1/config"
        );
        assert!(!c.has_https());

        let c = ControlClient::new(&config("https://control.test", "secret"));
        assert!(c.has_https());
    }
}
