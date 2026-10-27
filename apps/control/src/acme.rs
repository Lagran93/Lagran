//! Minimal Let's Encrypt ACME v2 client (HTTP-01) used by certificate issuance.
//!
//! It intentionally implements only what the console needs:
//! account registration, newOrder, http-01, finalize and certificate download.

use crate::repository;
use crate::service::agent_http;
use crate::state::AppState;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::HeaderMap;
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use ring::digest;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair as RingKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::OnceLock;
use std::time::Duration;

pub struct IssuedCert {
    pub cert_pem: String,
    pub key_pem: String,
    pub issuer: String,
}

#[derive(Debug, Deserialize)]
struct Directory {
    #[serde(rename = "newNonce")]
    new_nonce: String,
    #[serde(rename = "newAccount")]
    new_account: String,
    #[serde(rename = "newOrder")]
    new_order: String,
}

#[derive(Debug, Deserialize)]
struct Order {
    status: String,
    finalize: String,
    authorizations: Vec<String>,
    certificate: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Authz {
    status: String,
    challenges: Vec<Challenge>,
}

#[derive(Debug, Deserialize)]
struct Challenge {
    #[serde(rename = "type")]
    kind: String,
    url: String,
    /// Some newer challenge types (e.g. `dns-persist-01`) have no token.
    token: Option<String>,
}

type AcmeHttp = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

struct HttpReply {
    status: u16,
    headers: HeaderMap,
    body: Vec<u8>,
}

fn acme_http() -> &'static AcmeHttp {
    static C: OnceLock<AcmeHttp> = OnceLock::new();
    C.get_or_init(|| {
        // Defensive for callers/tests that did not go through main().
        let _ = rustls::crypto::ring::default_provider().install_default();
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .build();
        Client::builder(TokioExecutor::new()).build(https)
    })
}

async fn http_request(
    method: &str,
    url: &str,
    body: Option<Vec<u8>>,
    headers: &[(&str, &str)],
) -> Result<HttpReply, String> {
    let mut builder = Request::builder().method(method).uri(url);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let payload = body.unwrap_or_default();
    let req = builder
        .body(Full::new(Bytes::from(payload)))
        .map_err(|e| format!("build ACME request: {e}"))?;
    let resp = tokio::time::timeout(Duration::from_secs(30), acme_http().request(req))
        .await
        .map_err(|_| format!("ACME request {url}: timed out"))?
        .map_err(|e| format!("ACME request {url}: {e}"))?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("read ACME response: {e}"))?
        .to_bytes()
        .to_vec();
    Ok(HttpReply {
        status,
        headers,
        body,
    })
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn reply_error(reply: &HttpReply) -> String {
    if let Ok(v) = serde_json::from_slice::<Value>(&reply.body) {
        if let Some(detail) = v.get("detail").and_then(|d| d.as_str()) {
            return format!("ACME HTTP {}: {detail}", reply.status);
        }
        if let Some(typ) = v.get("type").and_then(|d| d.as_str()) {
            return format!("ACME HTTP {}: {typ}", reply.status);
        }
    }
    format!(
        "ACME HTTP {}: {}",
        reply.status,
        String::from_utf8_lossy(&reply.body)
            .chars()
            .take(200)
            .collect::<String>()
    )
}

fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

struct AccountKey {
    pair: EcdsaKeyPair,
    x: String,
    y: String,
    thumbprint: String,
}

impl AccountKey {
    fn generate() -> Result<(Self, String), String> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| "generate ACME account key".to_string())?;
        let stored = STANDARD.encode(pkcs8.as_ref());
        let key = Self::from_pkcs8(pkcs8.as_ref())?;
        Ok((key, stored))
    }

    fn from_stored(stored: &str) -> Result<Self, String> {
        let der = STANDARD
            .decode(stored.trim())
            .map_err(|e| format!("decode ACME account key: {e}"))?;
        Self::from_pkcs8(&der)
    }

    fn from_pkcs8(der: &[u8]) -> Result<Self, String> {
        let rng = SystemRandom::new();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der, &rng)
            .map_err(|_| "load ACME account key".to_string())?;
        let point = pair.public_key().as_ref();
        let (x, y) = if point.len() == 65 && point[0] == 4 {
            (&point[1..33], &point[33..65])
        } else if point.len() == 64 {
            (&point[..32], &point[32..])
        } else {
            return Err("unexpected ACME public key length".into());
        };
        let x = b64url(x);
        let y = b64url(y);
        let canonical = format!("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}");
        let thumbprint = b64url(digest::digest(&digest::SHA256, canonical.as_bytes()).as_ref());
        Ok(Self {
            pair,
            x,
            y,
            thumbprint,
        })
    }

    fn jwk(&self) -> Value {
        json!({
            "crv": "P-256",
            "kty": "EC",
            "x": self.x,
            "y": self.y,
        })
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        let rng = SystemRandom::new();
        let sig = self
            .pair
            .sign(&rng, message)
            .map_err(|_| "ACME JWS signature failed".to_string())?;
        Ok(sig.as_ref().to_vec())
    }
}

struct Session {
    dir: Directory,
    key: AccountKey,
    kid: String,
}

impl Session {
    async fn nonce(&self) -> Result<String, String> {
        let reply = http_request("HEAD", &self.dir.new_nonce, None, &[]).await?;
        if !(200..300).contains(&reply.status) {
            return Err(reply_error(&reply));
        }
        header(&reply.headers, "replay-nonce")
            .map(|s| s.to_string())
            .ok_or_else(|| "ACME newNonce returned no Replay-Nonce".to_string())
    }

    fn signed_body(
        &self,
        url: &str,
        payload: Option<&Value>,
        use_jwk: bool,
        nonce: &str,
    ) -> Result<Vec<u8>, String> {
        let mut protected = json!({
            "alg": "ES256",
            "nonce": nonce,
            "url": url,
        });
        if use_jwk {
            protected["jwk"] = self.key.jwk();
        } else {
            protected["kid"] = json!(self.kid);
        }
        let protected_b64 =
            b64url(&serde_json::to_vec(&protected).map_err(|e| format!("encode JWS header: {e}"))?);
        let payload_bytes = match payload {
            Some(v) => serde_json::to_vec(v).map_err(|e| format!("encode ACME payload: {e}"))?,
            None => Vec::new(),
        };
        let payload_b64 = b64url(&payload_bytes);
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let signature = self.key.sign(signing_input.as_bytes())?;
        let body = json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": b64url(&signature),
        });
        serde_json::to_vec(&body).map_err(|e| format!("encode JWS body: {e}"))
    }

    async fn post(
        &self,
        url: &str,
        payload: Option<&Value>,
        use_jwk: bool,
        accept: Option<&str>,
    ) -> Result<HttpReply, String> {
        let nonce = self.nonce().await?;
        let body = self.signed_body(url, payload, use_jwk, &nonce)?;
        let mut headers: Vec<(&str, &str)> = vec![("content-type", "application/jose+json")];
        if let Some(accept) = accept {
            headers.push(("accept", accept));
        }
        http_request("POST", url, Some(body), &headers).await
    }

    async fn post_as_get(&self, url: &str) -> Result<HttpReply, String> {
        self.post(url, None, false, None).await
    }
}

fn parse_json<T: for<'de> Deserialize<'de>>(reply: &HttpReply) -> Result<T, String> {
    serde_json::from_slice(&reply.body).map_err(|e| format!("parse ACME response: {e}"))
}

async fn ensure_account(
    state: &AppState,
    directory_url: &str,
    contact: Option<&str>,
) -> Result<Session, String> {
    let reply = http_request("GET", directory_url, None, &[]).await?;
    if !(200..300).contains(&reply.status) {
        return Err(reply_error(&reply));
    }
    let dir: Directory = parse_json(&reply)?;

    let stored = repository::get_acme_account(&state.pool, directory_url)
        .await
        .map_err(|e| format!("read ACME account: {e}"))?;
    let (key, key_stored, mut kid) = match stored {
        Some((stored, kid)) => (AccountKey::from_stored(&stored)?, stored, kid),
        None => {
            let (key, stored) = AccountKey::generate()?;
            repository::save_acme_account(&state.pool, directory_url, &stored, "")
                .await
                .map_err(|e| format!("save ACME account: {e}"))?;
            (key, stored, String::new())
        }
    };

    let mut session = Session {
        dir,
        key,
        kid: String::new(),
    };

    if kid.is_empty() {
        let mut payload = json!({ "termsOfServiceAgreed": true });
        if let Some(email) = contact.filter(|e| !e.trim().is_empty()) {
            payload["contact"] = json!([format!("mailto:{}", email.trim())]);
        }
        let reply = session
            .post(&session.dir.new_account, Some(&payload), true, None)
            .await?;
        if !(200..300).contains(&reply.status) {
            return Err(reply_error(&reply));
        }
        kid = header(&reply.headers, "location")
            .map(|s| s.to_string())
            .ok_or_else(|| "ACME newAccount returned no Location".to_string())?;
        repository::save_acme_account(&state.pool, directory_url, &key_stored, &kid)
            .await
            .map_err(|e| format!("save ACME account kid: {e}"))?;
    }
    session.kid = kid;
    Ok(session)
}

async fn publish_challenge(
    state: &AppState,
    domain: &str,
    token: &str,
    key_auth: &str,
) -> Result<usize, String> {
    repository::put_acme_challenge(&state.pool, token, key_auth, domain)
        .await
        .map_err(|e| format!("store ACME challenge: {e}"))?;

    let nodes = repository::list_online_nodes_with_agent(&state.pool)
        .await
        .unwrap_or_default();
    if nodes.is_empty() {
        return Err("没有在线边缘节点，无法完成 HTTP-01 校验".into());
    }
    let mut ok = 0usize;
    for node in &nodes {
        let url = format!(
            "{}/__lagran/acme/challenge",
            node.agent_url.trim_end_matches('/')
        );
        let body = json!({
            "token": token,
            "key_authorization": key_auth,
        });
        let token_header = if node.auth_token.is_empty() {
            &state.config.agent_token
        } else {
            &node.auth_token
        };
        match agent_http::put_json_ok(&url, &body, token_header).await {
            Ok(()) => ok += 1,
            Err(e) => tracing::warn!(node = %node.name, error = %e, "ACME challenge push failed"),
        }
    }
    if ok == 0 {
        return Err(
            "ACME challenge 推送失败：没有可达的边缘节点（检查 AGENT_URL/AGENT_TOKEN）".into(),
        );
    }
    // Give the edge a moment to install the token before triggering validation.
    tokio::time::sleep(Duration::from_secs(1)).await;
    Ok(ok)
}

async fn wait_authz(session: &Session, url: &str) -> Result<Authz, String> {
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let reply = session.post_as_get(url).await?;
        if !(200..300).contains(&reply.status) {
            return Err(reply_error(&reply));
        }
        let authz: Authz = parse_json(&reply)?;
        match authz.status.as_str() {
            "valid" => return Ok(authz),
            "invalid" => {
                let detail = String::from_utf8_lossy(&reply.body);
                return Err(format!("ACME authorization invalid: {detail}"));
            }
            _ => {}
        }
    }
    Err("ACME authorization timed out".into())
}

async fn wait_order(session: &Session, url: &str) -> Result<Order, String> {
    for _ in 0..30 {
        let reply = session.post_as_get(url).await?;
        if !(200..300).contains(&reply.status) {
            return Err(reply_error(&reply));
        }
        let order: Order = parse_json(&reply)?;
        match order.status.as_str() {
            "valid" | "ready" => return Ok(order),
            "invalid" => {
                let detail = String::from_utf8_lossy(&reply.body);
                return Err(format!("ACME order invalid: {detail}"));
            }
            _ => tokio::time::sleep(Duration::from_secs(1)).await,
        }
    }
    Err("ACME order timed out".into())
}

async fn wait_order_valid(session: &Session, url: &str) -> Result<Order, String> {
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let reply = session.post_as_get(url).await?;
        if !(200..300).contains(&reply.status) {
            return Err(reply_error(&reply));
        }
        let order: Order = parse_json(&reply)?;
        match order.status.as_str() {
            "valid" => return Ok(order),
            "invalid" => {
                let detail = String::from_utf8_lossy(&reply.body);
                return Err(format!("ACME order invalid: {detail}"));
            }
            _ => {}
        }
    }
    Err("ACME order did not become valid".into())
}

pub async fn issue_letsencrypt(
    state: &AppState,
    domain: &str,
    directory_url: &str,
    contact: Option<&str>,
) -> Result<IssuedCert, String> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() || domain.contains('*') {
        return Err("Let's Encrypt HTTP-01 不支持空域名或泛域名".into());
    }
    let session = ensure_account(state, directory_url, contact).await?;

    // 1) New order
    let reply = session
        .post(
            &session.dir.new_order,
            Some(&json!({
                "identifiers": [{ "type": "dns", "value": domain }]
            })),
            false,
            None,
        )
        .await?;
    if !(200..300).contains(&reply.status) {
        return Err(reply_error(&reply));
    }
    let order_url = header(&reply.headers, "location")
        .map(|s| s.to_string())
        .ok_or_else(|| "ACME newOrder returned no Location".to_string())?;
    let order: Order = parse_json(&reply)?;

    // 2) HTTP-01 challenges
    for authz_url in &order.authorizations {
        let reply = session.post_as_get(authz_url).await?;
        if !(200..300).contains(&reply.status) {
            return Err(reply_error(&reply));
        }
        let authz: Authz = parse_json(&reply)?;
        if authz.status == "valid" {
            continue;
        }
        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.kind == "http-01")
            .ok_or_else(|| "ACME authorization has no http-01 challenge".to_string())?;
        let token = challenge
            .token
            .as_deref()
            .ok_or_else(|| "ACME http-01 challenge has no token".to_string())?;
        let key_auth = format!("{}.{}", token, session.key.thumbprint);
        let pushed = publish_challenge(state, &domain, token, &key_auth).await?;
        tracing::info!(domain = %domain, pushed, "ACME HTTP-01 challenge published");
        let reply = session
            .post(&challenge.url, Some(&json!({})), false, None)
            .await?;
        if !(200..300).contains(&reply.status) {
            return Err(reply_error(&reply));
        }
        wait_authz(&session, authz_url).await?;
    }

    // 3) Wait until the order is ready, then finalize with a fresh CSR.
    let ready = wait_order(&session, &order_url).await?;
    if ready.status != "ready" && ready.status != "valid" {
        return Err(format!("ACME order not ready: {}", ready.status));
    }

    let key_pair = KeyPair::generate().map_err(|e| format!("generate certificate key: {e}"))?;
    let mut params = CertificateParams::new(vec![domain.clone()])
        .map_err(|e| format!("build certificate params: {e}"))?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, domain.clone());
    if let Ok(dns) = domain.as_str().try_into() {
        params.subject_alt_names = vec![SanType::DnsName(dns)];
    }
    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| format!("build CSR: {e}"))?;
    let csr_b64 = b64url(csr.der().as_ref());

    let reply = session
        .post(
            &ready.finalize,
            Some(&json!({ "csr": csr_b64 })),
            false,
            None,
        )
        .await?;
    if !(200..300).contains(&reply.status) {
        return Err(reply_error(&reply));
    }
    let finalized = wait_order_valid(&session, &order_url).await?;
    if finalized.status != "valid" {
        return Err(format!(
            "ACME order finalize did not become valid: {}",
            finalized.status
        ));
    }
    let cert_url = finalized
        .certificate
        .as_deref()
        .ok_or_else(|| "ACME order has no certificate URL".to_string())?;
    let reply = session
        .post(
            cert_url,
            None,
            false,
            Some("application/pem-certificate-chain"),
        )
        .await?;
    if !(200..300).contains(&reply.status) {
        return Err(reply_error(&reply));
    }
    let cert_pem = String::from_utf8(reply.body)
        .map_err(|_| "ACME certificate response is not UTF-8 PEM".to_string())?;
    if !cert_pem.contains("BEGIN CERTIFICATE") {
        return Err("ACME certificate response does not contain a certificate".into());
    }

    Ok(IssuedCert {
        cert_pem,
        key_pem: key_pair.serialize_pem(),
        issuer: "Let's Encrypt".into(),
    })
}

/// Push a certificate to every online edge. Returns how many accepted it.
pub async fn push_certificate_to_edges(
    state: &AppState,
    domain: &str,
    cert_pem: &str,
    key_pem: &str,
) -> u32 {
    let nodes = repository::list_online_nodes_with_agent(&state.pool)
        .await
        .unwrap_or_default();
    let mut pushed = 0u32;
    for node in &nodes {
        let url = format!(
            "{}/__lagran/certs/load",
            node.agent_url.trim_end_matches('/')
        );
        let body = json!({
            "names": [domain],
            "cert_pem": cert_pem,
            "key_pem": key_pem,
        });
        let token = if node.auth_token.is_empty() {
            &state.config.agent_token
        } else {
            &node.auth_token
        };
        match agent_http::post_json_ok(&url, &body, token).await {
            Ok(()) => pushed += 1,
            Err(e) => tracing::warn!(node = %node.name, error = %e, "cert push failed"),
        }
    }
    pushed
}

/// Renew Let's Encrypt certificates that expire within 30 days.
pub async fn renew_due(state: &AppState) -> u32 {
    let certs = match repository::list_certs(&state.pool).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "renewal: list certs failed");
            return 0;
        }
    };
    let now = chrono::Utc::now();
    let mut conn = match state.pool.acquire().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "renewal: acquire connection failed");
            return 0;
        }
    };
    let locked: (bool,) =
        match sqlx::query_as("SELECT pg_try_advisory_lock(hashtext('lagran-acme-renew')::bigint)")
            .fetch_one(&mut *conn)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "renewal: advisory lock failed");
                return 0;
            }
        };
    if !locked.0 {
        return 0;
    }
    let mut renewed = 0u32;
    for cert in certs {
        if !cert.auto_renew || cert.status != "active" || cert.issuer != "Let's Encrypt" {
            continue;
        }
        if let Some(not_after) = cert.not_after {
            if not_after > now + chrono::Duration::days(30) {
                continue;
            }
        }
        let contact = state.config.acme_contact_email.trim();
        let contact = if contact.is_empty() {
            None
        } else {
            Some(contact)
        };
        match issue_letsencrypt(
            state,
            &cert.domain_name,
            &state.config.acme_directory_url,
            contact,
        )
        .await
        {
            Ok(issued) => {
                let not_before = chrono::Utc::now();
                let not_after = not_before + chrono::Duration::days(90);
                if let Err(e) = repository::update_cert_material(
                    &state.pool,
                    cert.id,
                    &issued.cert_pem,
                    &issued.key_pem,
                    &issued.issuer,
                    not_before,
                    not_after,
                )
                .await
                {
                    tracing::warn!(domain = %cert.domain_name, error = %e, "renewal: store failed");
                    continue;
                }
                let pushed = push_certificate_to_edges(
                    state,
                    &cert.domain_name,
                    &issued.cert_pem,
                    &issued.key_pem,
                )
                .await;
                tracing::info!(
                    domain = %cert.domain_name,
                    pushed,
                    "Let's Encrypt certificate renewed"
                );
                renewed += 1;
            }
            Err(e) => {
                tracing::warn!(domain = %cert.domain_name, error = %e, "renewal: issue failed")
            }
        }
    }
    let _ = sqlx::query("SELECT pg_advisory_unlock(hashtext('lagran-acme-renew')::bigint)")
        .execute(&mut *conn)
        .await;
    renewed
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ring::signature::UnparsedPublicKey;

    #[test]
    fn account_key_produces_verifiable_es256_jws() {
        let (key, _stored) = AccountKey::generate().expect("generate key");
        assert_eq!(key.x.len(), 43);
        assert_eq!(key.y.len(), 43);
        assert_eq!(key.thumbprint.len(), 43);

        let session = Session {
            dir: Directory {
                new_nonce: "https://example.test/nonce".into(),
                new_account: "https://example.test/account".into(),
                new_order: "https://example.test/order".into(),
            },
            key,
            kid: "https://example.test/acct/1".into(),
        };
        let body = session
            .signed_body(
                "https://example.test/order",
                Some(&json!({ "identifiers": [] })),
                false,
                "nonce-1",
            )
            .expect("sign");
        let jws: Value = serde_json::from_slice(&body).expect("jws json");
        let protected = jws["protected"].as_str().unwrap();
        let payload = jws["payload"].as_str().unwrap();
        let signature = URL_SAFE_NO_PAD
            .decode(jws["signature"].as_str().unwrap())
            .expect("signature b64");
        assert_eq!(signature.len(), 64);

        let signed = format!("{protected}.{payload}");
        let public_key = session.key.pair.public_key().as_ref();
        let point = public_key;
        let mut expected = Vec::with_capacity(65);
        if point.len() == 65 {
            expected.extend_from_slice(point);
        } else {
            expected.push(4);
            expected.extend_from_slice(&URL_SAFE_NO_PAD.decode(&session.key.x).unwrap());
            expected.extend_from_slice(&URL_SAFE_NO_PAD.decode(&session.key.y).unwrap());
        }
        assert_eq!(expected, point, "JWK coordinates match public key");
        let verifier =
            UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, public_key);
        verifier
            .verify(signed.as_bytes(), &signature)
            .expect("valid ES256 signature");

        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(protected).unwrap()).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "https://example.test/acct/1");
        assert_eq!(header["nonce"], "nonce-1");
    }

    #[test]
    fn parses_authz_with_tokenless_challenge_types() {
        let body = r#"{
            "status": "pending",
            "challenges": [
                {"type":"http-01","url":"https://acme.test/chall/1","status":"pending","token":"tok"},
                {"type":"dns-persist-01","url":"https://acme.test/chall/2","status":"pending"}
            ]
        }"#;
        let authz: Authz = serde_json::from_str(body).expect("authz");
        let http = authz
            .challenges
            .iter()
            .find(|c| c.kind == "http-01")
            .expect("http-01");
        assert_eq!(http.token.as_deref(), Some("tok"));
        assert!(authz
            .challenges
            .iter()
            .any(|c| c.kind == "dns-persist-01" && c.token.is_none()));
    }
}
