//! System settings helpers: donation addresses and release updates.

use crate::middleware::authz::Actor;
use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;

const DEFAULT_REPO: &str = "Lagran93/Lagran";
const DEFAULT_REQUEST: &str = "/var/lib/lagran/update.request";
const DEFAULT_STATUS: &str = "/var/lib/lagran/update.status";

fn forbidden() -> (StatusCode, Json<Value>) {
    (StatusCode::FORBIDDEN, Json(json!({"error": "forbidden"})))
}

fn internal(message: impl Into<String>) -> (StatusCode, Json<Value>) {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": message.into()})))
}

fn bad_request(message: impl Into<String>) -> (StatusCode, Json<Value>) {
    (StatusCode::BAD_REQUEST, Json(json!({"error": message.into()})))
}

fn update_repo() -> String {
    std::env::var("LAGRAN_UPDATE_REPO")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_REPO.to_string())
}

fn request_path() -> PathBuf {
    std::env::var("LAGRAN_UPDATE_REQUEST_PATH")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_REQUEST))
}

fn status_path() -> PathBuf {
    std::env::var("LAGRAN_UPDATE_STATUS_PATH")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATUS))
}

fn updater_available() -> bool {
    let helper = std::env::var("LAGRAN_UPDATE_HELPER")
        .unwrap_or_else(|_| "/opt/lagran/bin/lagran-update".to_string());
    std::path::Path::new(&helper).is_file()
}

#[derive(Serialize)]
pub struct DonationEntry {
    pub network: &'static str,
    pub asset: &'static str,
    pub address: &'static str,
}

#[derive(Serialize)]
pub struct DonationResponse {
    pub entries: Vec<DonationEntry>,
    pub notice: &'static str,
}

pub async fn donation() -> Json<DonationResponse> {
    let entries = vec![
        DonationEntry {
            network: "Bitcoin",
            asset: "BTC",
            address: "bc1qgh9dvqa4d0skn82n7t423jnxy7mh3prgxcxc0z",
        },
        DonationEntry {
            network: "Ethereum",
            asset: "ETH / ERC-20 USDT / USDC",
            address: "0xCFf627A0D499e898b209300cA7192F55f01bAB2F",
        },
        DonationEntry {
            network: "TRON",
            asset: "TRX / TRC-20 USDT",
            address: "TFRZmHNyp54fg9BsCXaJH2UVq1B2yUNN8S",
        },
        DonationEntry {
            network: "Solana",
            asset: "SOL / SPL USDC",
            address: "AkpkuUTaReYb4QSgwFfbHZv6CwoesqfGAKPodDxa6x3T",
        },
        DonationEntry {
            network: "BNB Smart Chain",
            asset: "BNB / BEP-20 USDT",
            address: "0xCFf627A0D499e898b209300cA7192F55f01bAB2F",
        },
        DonationEntry {
            network: "Polygon",
            asset: "POL / polygon USDT",
            address: "0xCFf627A0D499e898b209300cA7192F55f01bAB2F",
        },
    ];
    Json(DonationResponse {
        entries,
        notice: "仅向对应网络地址转账；链上交易不可逆，请仔细核对地址和网络。",
    })
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    #[serde(default)]
    html_url: Option<String>,
    #[serde(default)]
    published_at: Option<String>,
    #[serde(default)]
    body: Option<String>,
}

async fn fetch_latest(repo: &str) -> Result<GithubRelease, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let response = client
        .get(&url)
        .header("User-Agent", format!("lagran-control/{}", crate::version::VERSION))
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| format!("GitHub request failed: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("GitHub returned HTTP {}", response.status()));
    }
    response
        .json::<GithubRelease>()
        .await
        .map_err(|e| format!("invalid GitHub release response: {e}"))
}

fn parse_version(raw: &str) -> Option<(u64, u64, u64)> {
    let core = raw
        .trim()
        .trim_start_matches('v')
        .split(['+', '-'])
        .next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some((major, minor, patch))
}

fn version_gt(latest: &str, current: &str) -> bool {
    match (parse_version(latest), parse_version(current)) {
        (Some(latest), Some(current)) => latest > current,
        _ => false,
    }
}

#[derive(Serialize)]
pub struct UpdateCheckResponse {
    pub current_version: String,
    pub latest_version: Option<String>,
    pub update_available: bool,
    pub release_url: Option<String>,
    pub published_at: Option<String>,
    pub notes: Option<String>,
    pub updater_available: bool,
    pub error: Option<String>,
}

pub async fn check_update(
    actor: Actor,
) -> Result<Json<UpdateCheckResponse>, (StatusCode, Json<Value>)> {
    if !actor.admin() {
        return Err(forbidden());
    }
    let repo = update_repo();
    let available = updater_available();
    match fetch_latest(&repo).await {
        Ok(release) => {
            let latest = release.tag_name.trim_start_matches('v').to_string();
            Ok(Json(UpdateCheckResponse {
                current_version: crate::version::VERSION.to_string(),
                update_available: version_gt(&latest, crate::version::VERSION),
                latest_version: Some(latest),
                release_url: release.html_url,
                published_at: release.published_at,
                notes: release.body.map(|b| b.chars().take(2000).collect()),
                updater_available: available,
                error: None,
            }))
        }
        Err(error) => Ok(Json(UpdateCheckResponse {
            current_version: crate::version::VERSION.to_string(),
            latest_version: None,
            update_available: false,
            release_url: None,
            published_at: None,
            notes: None,
            updater_available: available,
            error: Some(error),
        })),
    }
}

#[derive(Deserialize)]
pub struct ApplyUpdateRequest {
    #[serde(default)]
    pub version: Option<String>,
}

#[derive(Serialize)]
pub struct ApplyUpdateResponse {
    pub queued: bool,
    pub version: String,
    pub message: String,
}

fn validate_tag(raw: &str) -> Option<String> {
    let tag = if raw.trim_start().starts_with('v') {
        raw.trim().to_string()
    } else {
        format!("v{}", raw.trim())
    };
    let rest = tag.strip_prefix('v')?;
    if rest.is_empty() || rest.len() > 64 {
        return None;
    }
    if !rest
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '+')
    {
        return None;
    }
    let core = rest.split(['+', '-']).next()?;
    let mut parts = core.split('.');
    let major = parts.next()?;
    let minor = parts.next()?;
    let patch = parts.next()?;
    if parts.next().is_some()
        || major.is_empty()
        || minor.is_empty()
        || patch.is_empty()
        || !major.chars().all(|c| c.is_ascii_digit())
        || !minor.chars().all(|c| c.is_ascii_digit())
        || !patch.chars().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    Some(tag)
}

pub async fn apply_update(
    State(state): State<crate::state::AppState>,
    actor: Actor,
    Json(req): Json<ApplyUpdateRequest>,
) -> Result<Json<ApplyUpdateResponse>, (StatusCode, Json<Value>)> {
    if !actor.admin() {
        return Err(forbidden());
    }
    if !updater_available() {
        return Err(internal(
            "updater is not installed; reinstall control with install.sh control",
        ));
    }
    let tag = if let Some(raw) = req.version {
        validate_tag(&raw).ok_or_else(|| bad_request("invalid release version"))?
    } else {
        let repo = update_repo();
        let release = fetch_latest(&repo)
            .await
            .map_err(internal)?;
        validate_tag(&release.tag_name).ok_or_else(|| bad_request("invalid latest release tag"))?
    };
    let request = request_path();
    if let Some(parent) = request.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| internal(format!("cannot create update request directory: {e}")))?;
    }
    // Recreate the file so the systemd .path unit always observes a change.
    let _ = std::fs::remove_file(&request);
    let tmp = request.with_extension("request.tmp");
    std::fs::write(&tmp, format!("{tag}\n"))
        .map_err(|e| internal(format!("cannot write update request: {e}")))?;
    std::fs::rename(&tmp, &request)
        .map_err(|e| internal(format!("cannot queue update request: {e}")))?;
    let _ = crate::repository::insert_audit(
        &state.pool,
        &actor.email,
        "system.update",
        &tag,
        "queued GitHub release update",
    )
    .await;
    Ok(Json(ApplyUpdateResponse {
        queued: true,
        version: tag.clone(),
        message: format!("update to {tag} queued; the control plane will restart"),
    }))
}

#[derive(Serialize)]
pub struct UpdateStatusResponse {
    pub state: String,
    pub version: Option<String>,
    pub message: Option<String>,
    pub updated_at: Option<String>,
    pub updater_available: bool,
    pub raw: Option<String>,
}

pub async fn update_status(
    actor: Actor,
) -> Result<Json<UpdateStatusResponse>, (StatusCode, Json<Value>)> {
    if !actor.admin() {
        return Err(forbidden());
    }
    let raw = std::fs::read_to_string(status_path()).ok();
    let mut state = "idle".to_string();
    let mut version = None;
    let mut message = None;
    let mut updated_at = None;
    if let Some(raw) = raw.as_deref() {
        let mut parts = raw.trim().splitn(4, '|');
        state = parts.next().unwrap_or("unknown").to_string();
        version = parts
            .next()
            .filter(|v| !v.is_empty())
            .map(str::to_string);
        message = parts
            .next()
            .filter(|v| !v.is_empty())
            .map(str::to_string);
        updated_at = parts
            .next()
            .filter(|v| !v.is_empty())
            .map(str::to_string);
    }
    Ok(Json(UpdateStatusResponse {
        state,
        version,
        message,
        updated_at,
        updater_available: updater_available(),
        raw,
    }))
}
