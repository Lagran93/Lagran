//! Certificate auto-issuance: Let's Encrypt (ACME v2) or local dev CA.
//!
//! Issuance is asynchronous. A Let's Encrypt order needs an account, an HTTP-01
//! challenge round trip and two polling loops, so it takes tens of seconds at
//! best and minutes when the CA is slow. Holding an HTTP request open that long
//! parked a browser connection and the console's reverse proxy on every click.
//!
//! `POST /certs/issue` therefore validates synchronously (permission, provider,
//! configuration) and then answers `202 Accepted` with a job id. The work runs in
//! a spawned task tracked by [`CertJobs`], and the caller polls
//! `GET /certs/jobs/:id` until the status is `succeeded` or `failed`.

use crate::acme as acme_client;
use crate::config::AppConfig;
use crate::middleware::authz::Actor;
use crate::repository;
use crate::service::agent_http;
use crate::service::cert_jobs::{CertJobs, JobGuard, JobSnapshot, Start, StartError};
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct IssueRequest {
    pub domain_name: String,
    pub push_to_edges: Option<bool>,
    pub auto_renew: Option<bool>,
    /// `letsencrypt` (default), `letsencrypt-staging`, or `dev`.
    pub provider: Option<String>,
}

/// `202 Accepted`: the issuance is queued, poll `poll_url` for the outcome.
#[derive(Serialize)]
pub struct IssueAccepted {
    pub success: bool,
    pub job_id: String,
    pub status: &'static str,
    pub domain_name: String,
    pub provider: String,
    /// Relative path of the poll endpoint, so the console need not build it.
    pub poll_url: String,
    /// True when an identical job was already in flight and this request only
    /// returned its id.
    pub reused: bool,
    pub message: String,
}

#[derive(Serialize)]
pub struct JobsResponse {
    pub jobs: Vec<JobSnapshot>,
}

#[derive(Serialize)]
pub struct ErrorBody {
    pub error: String,
}

/// Result of resolving the `provider` request field.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Provider {
    Dev,
    LetsEncrypt { directory: String, staging: bool },
}

impl Provider {
    /// Canonical name used in job keys, so `Dev` and `dev` dedupe together.
    fn name(&self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::LetsEncrypt { staging: true, .. } => "letsencrypt-staging",
            Self::LetsEncrypt { staging: false, .. } => "letsencrypt",
        }
    }

    /// Resolve and validate the provider before queueing the job.
    ///
    /// An unsupported name is a client error and a missing ACME directory is a
    /// configuration error; both are answered synchronously so the operator sees
    /// them immediately instead of as a failed job seconds later.
    fn resolve(requested: &str, config: &AppConfig) -> Result<Self, (StatusCode, String)> {
        match requested {
            "dev" => Ok(Self::Dev),
            "letsencrypt" | "letsencrypt-staging" => {
                let directory = if requested == "letsencrypt-staging" {
                    config.acme_staging_directory_url.trim()
                } else {
                    config.acme_directory_url.trim()
                };
                if directory.is_empty() {
                    return Err((
                        StatusCode::SERVICE_UNAVAILABLE,
                        "ACME directory is not configured".into(),
                    ));
                }
                Ok(Self::LetsEncrypt {
                    directory: directory.to_string(),
                    staging: requested == "letsencrypt-staging",
                })
            }
            other => Err((
                StatusCode::BAD_REQUEST,
                format!("unsupported provider: {other}"),
            )),
        }
    }
}

fn error(status: StatusCode, message: impl Into<String>) -> (StatusCode, Json<ErrorBody>) {
    (
        status,
        Json(ErrorBody {
            error: message.into(),
        }),
    )
}

/// Queue an issuance and return `202 Accepted`.
///
/// Everything a client can get wrong (empty domain, missing permission,
/// unsupported provider, missing ACME directory) is still answered
/// synchronously; only the CA interaction moves to the background.
pub async fn issue(
    State(state): State<AppState>,
    actor: Actor,
    Json(req): Json<IssueRequest>,
) -> Result<(StatusCode, Json<IssueAccepted>), (StatusCode, Json<ErrorBody>)> {
    let domain = req.domain_name.trim().trim_end_matches('.').to_string();
    if domain.is_empty() {
        return Err(error(StatusCode::BAD_REQUEST, "domain_name required"));
    }
    if !actor.can_write_domain_name(&state, &domain).await {
        return Err(error(StatusCode::FORBIDDEN, "forbidden"));
    }
    let requested = req
        .provider
        .as_deref()
        .unwrap_or("letsencrypt")
        .trim()
        .to_ascii_lowercase();
    let provider = Provider::resolve(&requested, &state.config)
        .map_err(|(status, message)| error(status, message))?;

    // Queue first: an identical issuance already in flight is reused instead of
    // opening a second ACME order, which would also burn the CA's rate limit.
    let (job_id, reused) = match state.cert_jobs.start(&domain, provider.name()) {
        Ok(Start::Started { id }) => (id, false),
        Ok(Start::AlreadyActive { id }) => (id, true),
        Err(StartError::TooManyActive) => {
            return Err(error(
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "too many issuances in flight (max {}); retry shortly",
                    crate::service::cert_jobs::MAX_ACTIVE_JOBS
                ),
            ))
        }
    };

    if !reused {
        let task = IssueTask {
            domain: domain.clone(),
            provider,
            push_to_edges: req.push_to_edges.unwrap_or(true),
            auto_renew: req.auto_renew.unwrap_or(true),
        };
        let worker_state = state.clone();
        let jobs = Arc::clone(&state.cert_jobs);
        tokio::spawn(async move { run_issue(worker_state, jobs, job_id, task).await });
    }

    let message = if reused {
        format!("an issuance for {domain} is already in progress")
    } else {
        format!("issuance queued via {requested}")
    };
    Ok((
        StatusCode::ACCEPTED,
        Json(IssueAccepted {
            success: true,
            job_id: job_id.to_string(),
            status: "pending",
            domain_name: domain,
            provider: requested,
            poll_url: format!("/api/v1/certs/jobs/{job_id}"),
            reused,
            message,
        }),
    ))
}

/// Active issuance jobs the caller may see.
///
/// The console calls this on mount so a page reload does not lose an issuance
/// that is still running.
pub async fn list_jobs(
    State(state): State<AppState>,
    actor: Actor,
) -> Result<Json<JobsResponse>, (StatusCode, Json<ErrorBody>)> {
    let mut visible = Vec::new();
    for job in state.cert_jobs.active() {
        if actor.can_write_domain_name(&state, &job.domain_name).await {
            visible.push(job);
        }
    }
    Ok(Json(JobsResponse { jobs: visible }))
}

/// Poll one issuance job.
///
/// A job the caller may not manage answers `404`, not `403`: the existence of an
/// issuance for somebody else's domain is itself information.
pub async fn job_status(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<Uuid>,
) -> Result<Json<JobSnapshot>, (StatusCode, Json<ErrorBody>)> {
    let not_found = || error(StatusCode::NOT_FOUND, "job not found");
    let Some(job) = state.cert_jobs.snapshot(id) else {
        return Err(not_found());
    };
    if !actor.can_write_domain_name(&state, &job.domain_name).await {
        return Err(not_found());
    }
    Ok(Json(job))
}

/// Immutable description of one queued issuance.
struct IssueTask {
    domain: String,
    provider: Provider,
    push_to_edges: bool,
    auto_renew: bool,
}

struct IssueOutcome {
    cert_id: Uuid,
    issuer: String,
    edges_pushed: u32,
}

/// Background worker for one job.
///
/// The guard is created before the first await so a panic, an abort or a stray
/// `?` still finalises the job instead of leaving it `running` forever.
async fn run_issue(state: AppState, jobs: Arc<CertJobs>, job_id: Uuid, task: IssueTask) {
    let mut guard = JobGuard::new(Arc::clone(&jobs), job_id);
    jobs.mark_running(job_id, "starting issuance");
    match issue_certificate(&state, jobs.as_ref(), job_id, &task).await {
        Ok(outcome) => {
            let message = format!(
                "certificate issued via {}; hot-reloaded on {} edge(s)",
                task.provider.name(),
                outcome.edges_pushed
            );
            guard.succeed(
                outcome.cert_id,
                &outcome.issuer,
                outcome.edges_pushed,
                &message,
            );
        }
        Err(message) => {
            tracing::warn!(
                domain = %task.domain,
                provider = task.provider.name(),
                error = %message,
                "certificate issuance failed"
            );
            guard.fail(&message);
        }
    }
}

/// The actual issuance, shared by the API worker.
///
/// Errors are returned as operator-facing text; the caller records them on the
/// job. Nothing here touches the response, which was already sent as `202`.
async fn issue_certificate(
    state: &AppState,
    jobs: &CertJobs,
    job_id: Uuid,
    task: &IssueTask,
) -> Result<IssueOutcome, String> {
    let domain = task.domain.as_str();
    // Snapshot the online nodes once: both the dev challenge and the certificate
    // push fan out to the same set.
    let nodes = repository::list_online_nodes_with_agent(&state.pool)
        .await
        .unwrap_or_default();

    let (cert_pem, key_pem, mut issuer) = match &task.provider {
        Provider::Dev => {
            jobs.mark_running(job_id, "publishing dev ACME challenge");
            let token = Uuid::new_v4().to_string().replace('-', "");
            let key_auth = format!("{token}.lagran-acme-dev");
            let _ = repository::put_acme_challenge(&state.pool, &token, &key_auth, domain).await;

            // Bounded fan-out. The dev provider ignores per-node errors (the
            // certificate is self-signed below), but must still not serialise.
            let targets = agent_http::owned_nodes(&nodes, &state.config.agent_token);
            let body = serde_json::json!({
                "token": token,
                "key_authorization": key_auth,
            });
            let _ = agent_http::fan_out_edge(&targets, move |node| {
                let url = node.endpoint("/__lagran/acme/challenge");
                let body = body.clone();
                async move { agent_http::put_json_ok(&url, &body, &node.token).await }
            })
            .await;

            let (cert_pem, key_pem) =
                issue_dev_cert(domain).map_err(|e| format!("issue failed: {e}"))?;
            (cert_pem, key_pem, "Lagran Dev CA (rcgen)".to_string())
        }
        Provider::LetsEncrypt { directory, .. } => {
            jobs.mark_running(job_id, "requesting certificate from the ACME CA");
            let contact = state.config.acme_contact_email.trim();
            let contact = if contact.is_empty() {
                None
            } else {
                Some(contact)
            };
            let issued = acme_client::issue_letsencrypt(state, domain, directory, contact)
                .await
                .map_err(|e| format!("Let's Encrypt 签发失败: {e}"))?;
            (issued.cert_pem, issued.key_pem, issued.issuer)
        }
    };

    if matches!(task.provider, Provider::LetsEncrypt { staging: true, .. }) {
        issuer = "Let's Encrypt (Staging)".to_string();
    }

    jobs.mark_running(job_id, "storing certificate");
    let domain_id = repository::get_domain_by_name(&state.pool, domain)
        .await
        .ok()
        .flatten()
        .map(|d| d.id);

    let row = repository::create_cert(
        &state.pool,
        domain_id,
        domain,
        &cert_pem,
        &key_pem,
        &issuer,
        task.auto_renew,
    )
    .await
    .map_err(|e| format!("store cert: {e}"))?;

    let mut edges_pushed = 0u32;
    if task.push_to_edges {
        jobs.mark_running(job_id, "pushing certificate to edges");
        // Serial pushes to 20 nodes with a few slow ones blocked the request past
        // the reverse proxy's timeout; fan out with a bound instead.
        let targets = agent_http::owned_nodes(&nodes, &state.config.agent_token);
        let body = serde_json::json!({
            "names": [domain],
            "cert_pem": cert_pem,
            "key_pem": key_pem,
        });
        let (pushed, failures) = agent_http::fan_out_edge(&targets, move |node| {
            let url = node.endpoint("/__lagran/certs/load");
            let body = body.clone();
            async move { agent_http::post_json_ok(&url, &body, &node.token).await }
        })
        .await;
        for (node, error) in failures {
            tracing::warn!(node = %node, error = %error, "cert push failed");
        }
        edges_pushed = pushed;
    }

    Ok(IssueOutcome {
        cert_id: row.id,
        issuer,
        edges_pushed,
    })
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
