//! Certificate auto-issuance: Let's Encrypt (ACME v2) or local dev CA.

use crate::acme as acme_client;
use crate::middleware::authz::Actor;
use crate::repository;
use crate::service::agent_http;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize)]
pub struct IssueRequest {
    pub domain_name: String,
    pub push_to_edges: Option<bool>,
    pub auto_renew: Option<bool>,
    /// `letsencrypt` (default), `letsencrypt-staging`, or `dev`.
    pub provider: Option<String>,
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
    if !actor
        .can_write_domain_name(&state, req.domain_name.trim())
        .await
    {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorBody {
                error: "forbidden".into(),
            }),
        ));
    }

    let domain = req.domain_name.trim().trim_end_matches('.').to_string();
    let provider = req
        .provider
        .as_deref()
        .unwrap_or("letsencrypt")
        .trim()
        .to_ascii_lowercase();

    let nodes = repository::list_online_nodes_with_agent(&state.pool)
        .await
        .unwrap_or_default();

    let (cert_pem, key_pem, mut issuer) = match provider.as_str() {
        "dev" => {
            let token = Uuid::new_v4().to_string().replace('-', "");
            let key_auth = format!("{token}.lagran-acme-dev");
            let _ = repository::put_acme_challenge(&state.pool, &token, &key_auth, &domain).await;

            for node in &nodes {
                let url = format!(
                    "{}/__lagran/acme/challenge",
                    node.agent_url.trim_end_matches('/')
                );
                let body = serde_json::json!({
                    "token": token,
                    "key_authorization": key_auth,
                });
                let _ = agent_http::put_json_ok(
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
            (cert_pem, key_pem, "Lagran Dev CA (rcgen)".to_string())
        }
        "letsencrypt" | "letsencrypt-staging" => {
            let directory = if provider == "letsencrypt-staging" {
                &state.config.acme_staging_directory_url
            } else {
                &state.config.acme_directory_url
            };
            if directory.trim().is_empty() {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ErrorBody {
                        error: "ACME directory is not configured".into(),
                    }),
                ));
            }
            let contact = state.config.acme_contact_email.trim();
            let contact = if contact.is_empty() {
                None
            } else {
                Some(contact)
            };
            let issued = acme_client::issue_letsencrypt(&state, &domain, directory, contact)
                .await
                .map_err(|e| {
                    tracing::warn!(domain = %domain, error = %e, "Let's Encrypt issuance failed");
                    (
                        StatusCode::BAD_GATEWAY,
                        Json(ErrorBody {
                            error: format!("Let's Encrypt 签发失败: {e}"),
                        }),
                    )
                })?;
            (issued.cert_pem, issued.key_pem, issued.issuer)
        }
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: format!("unsupported provider: {other}"),
                }),
            ))
        }
    };

    if provider == "letsencrypt-staging" {
        issuer = "Let's Encrypt (Staging)".to_string();
    }

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
        &issuer,
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
            if agent_http::post_json_ok(&url, &body, token)
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
        issuer,
        message: format!("certificate issued via {provider}; hot-reloaded on reachable edges"),
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

pub async fn challenge(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<String, StatusCode> {
    match repository::get_acme_challenge(&state.pool, &token).await {
        Ok(Some(v)) => Ok(v),
        _ => Err(StatusCode::NOT_FOUND),
    }
}
