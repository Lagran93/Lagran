//! Certificate auto-issuance (dev: rcgen; challenge fan-out to edges)

use crate::middleware::authz::Actor;
use crate::repository;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct IssueRequest {
    pub domain_name: String,
    pub push_to_edges: Option<bool>,
    pub auto_renew: Option<bool>,
}

#[derive(Serialize)]
pub struct IssueResponse {
    pub success: bool,
    pub cert_id: String,
    pub domain_name: String,
    pub issuer: String,
    pub message: String,
    pub edges_pushed: u32,
}

#[derive(Serialize)]
pub struct ErrorBody {
    pub error: String,
}

fn http_client() -> &'static Client<HttpConnector, Full<Bytes>> {
    static C: OnceLock<Client<HttpConnector, Full<Bytes>>> = OnceLock::new();
    C.get_or_init(|| {
        let mut c = HttpConnector::new();
        c.set_nodelay(true);
        Client::builder(TokioExecutor::new()).build(c)
    })
}

pub async fn issue(
    State(state): State<AppState>,
    actor: Actor,
    Json(req): Json<IssueRequest>,
) -> Result<Json<IssueResponse>, (StatusCode, Json<ErrorBody>)> {
    if req.domain_name.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "domain_name required".into(),
            }),
        ));
    }
    if !actor.can_write_domain_name(&state, req.domain_name.trim()).await {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorBody {
                error: "forbidden".into(),
            }),
        ));
    }

    let domain = req.domain_name.trim().to_string();
    let token = Uuid::new_v4().to_string().replace('-', "");
    let key_auth = format!("{token}.lagran-acme-dev");
    let _ = repository::put_acme_challenge(&state.pool, &token, &key_auth, &domain).await;

    let nodes = repository::list_online_nodes_with_agent(&state.pool)
        .await
        .unwrap_or_default();

    for node in &nodes {
        let url = format!(
            "{}/__lagran/acme/challenge",
            node.agent_url.trim_end_matches('/')
        );
        let body = serde_json::json!({
            "token": token,
            "key_authorization": key_auth,
        });
        let _ = request_json(
            http_client(),
            "PUT",
            &url,
            &body,
            if node.auth_token.is_empty() {
                &state.config.agent_token
            } else {
                &node.auth_token
            },
        )
        .await;
    }

    let (cert_pem, key_pem) = issue_dev_cert(&domain).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: format!("issue failed: {e}"),
            }),
        )
    })?;

    let domain_id = repository::get_domain_by_name(&state.pool, &domain)
        .await
        .ok()
        .flatten()
        .map(|d| d.id);

    let row = repository::create_cert(
        &state.pool,
        domain_id,
        &domain,
        &cert_pem,
        &key_pem,
        "Lagran Dev CA (rcgen)",
        req.auto_renew.unwrap_or(true),
    )
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: format!("store cert: {e}"),
            }),
        )
    })?;

    let mut edges_pushed = 0u32;
    if req.push_to_edges.unwrap_or(true) {
        for node in &nodes {
            let url = format!(
                "{}/__lagran/certs/load",
                node.agent_url.trim_end_matches('/')
            );
            let body = serde_json::json!({
                "names": [domain],
                "cert_pem": cert_pem,
                "key_pem": key_pem,
            });
            let token = if node.auth_token.is_empty() {
                &state.config.agent_token
            } else {
                &node.auth_token
            };
            if request_json(http_client(), "POST", &url, &body, token)
                .await
                .is_ok()
            {
                edges_pushed += 1;
            }
        }
    }

    Ok(Json(IssueResponse {
        success: true,
        cert_id: row.id.to_string(),
        domain_name: domain,
        issuer: "Lagran Dev CA (rcgen)".into(),
        message: "certificate issued; hot-reloaded on reachable edges".into(),
        edges_pushed,
    }))
}

fn issue_dev_cert(domain: &str) -> Result<(String, String), String> {
    let mut params = CertificateParams::new(vec![domain.to_string()]).map_err(|e| e.to_string())?;
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, domain);
    // SAN
    if let Ok(dns) = domain.try_into() {
        params.subject_alt_names = vec![SanType::DnsName(dns)];
    }

    let key_pair = KeyPair::generate().map_err(|e| e.to_string())?;
    let cert = params.self_signed(&key_pair).map_err(|e| e.to_string())?;
    Ok((cert.pem(), key_pair.serialize_pem()))
}

async fn request_json(
    client: &Client<HttpConnector, Full<Bytes>>,
    method: &str,
    url: &str,
    body: &serde_json::Value,
    token: &str,
) -> Result<(), String> {
    let bytes = Bytes::from(serde_json::to_vec(body).map_err(|e| e.to_string())?);
    let req = Request::builder()
        .method(method)
        .uri(url)
        .header("content-type", "application/json")
        .header("x-lagran-agent-token", token)
        .body(Full::new(bytes))
        .map_err(|e| e.to_string())?;
    let resp = client.request(req).await.map_err(|e| e.to_string())?;
    let status = resp.status();
    let _ = resp.into_body().collect().await;
    if status.is_success() || status.as_u16() == 204 {
        Ok(())
    } else {
        Err(format!("HTTP {status}"))
    }
}

pub async fn challenge(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<String, StatusCode> {
    match repository::get_acme_challenge(&state.pool, &token).await {
        Ok(Some(v)) => Ok(v),
        _ => Err(StatusCode::NOT_FOUND),
    }
}
