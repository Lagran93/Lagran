//! Signed managed WAF rulepack versions.
//!
//! The package is a stable JSON document describing the built-in ruleset
//! catalog. Control signs the exact bytes with HMAC-SHA256 and Edge verifies
//! the same bytes before caching them. Old versions can be restored without a
//! binary deploy.

use crate::waf_rulesets;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesetEntry {
    pub id: String,
    pub name: String,
    pub version: String,
    pub categories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rulepack {
    pub id: String,
    pub version: String,
    pub generated_at: String,
    pub rulesets: Vec<RulesetEntry>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RulepackRow {
    pub version: String,
    pub payload: String,
    pub signature: String,
    pub checksum: String,
    pub slot: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub created_by: String,
}

impl RulepackRow {
    pub fn parse_package(&self) -> Option<Rulepack> {
        serde_json::from_str(&self.payload).ok()
    }

    pub fn categories_for(&self, ids: &[String]) -> waf_rulesets::Categories {
        let mut categories = waf_rulesets::Categories::default();
        let Some(package) = self.parse_package() else {
            return categories;
        };
        for id in ids {
            let Some(entry) = package.rulesets.iter().find(|r| r.id == *id) else {
                continue;
            };
            for category in &entry.categories {
                categories = categories.enable(category);
            }
        }
        categories
    }
}

/// Resolve the HMAC key used to sign WAF rulepacks.
///
/// Returns `None` when `WAF_RULEPACK_SECRET` is unset. This used to fall back to
/// a constant that is published in this source tree, so any caller holding an
/// agent token could forge a signed rulepack and silently disable the managed
/// signatures on every domain. Callers must treat `None` as "rulepacks
/// unavailable" and must not start the control plane.
pub fn signing_key(config_secret: &str) -> Option<String> {
    let secret = config_secret.trim();
    if secret.is_empty() {
        return None;
    }
    Some(secret.to_string())
}

pub fn build(version: &str) -> Rulepack {
    Rulepack {
        id: "lagran-waf-core".into(),
        version: version.to_string(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        rulesets: waf_rulesets::catalog()
            .iter()
            .map(|r| RulesetEntry {
                id: r.id.into(),
                name: r.name.into(),
                version: r.version.into(),
                categories: r.categories.iter().map(|c| (*c).into()).collect(),
            })
            .collect(),
    }
}

pub fn catalog_entries() -> Vec<RulesetEntry> {
    waf_rulesets::catalog()
        .iter()
        .map(|r| RulesetEntry {
            id: r.id.into(),
            name: r.name.into(),
            version: r.version.into(),
            categories: r.categories.iter().map(|c| (*c).into()).collect(),
        })
        .collect()
}

pub fn build_with_rulesets(
    version: &str,
    rulesets: Vec<RulesetEntry>,
) -> Rulepack {
    Rulepack {
        id: "lagran-waf-core".into(),
        version: version.to_string(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        rulesets,
    }
}

pub fn validate_rulesets(rulesets: &[RulesetEntry]) -> Result<(), String> {
    if rulesets.is_empty() {
        return Err("rulesets must not be empty".into());
    }
    let allowed = [
        "sqli",
        "xss",
        "traversal",
        "scanners",
        "rce",
        "ssrf",
        "xxe",
        "log4shell",
        "crlf",
        "ssti",
        "nosql",
        "ldap",
        "java",
        "webshell",
        "protocol",
    ];
    let mut ids = std::collections::HashSet::new();
    for ruleset in rulesets {
        let id = ruleset.id.trim();
        if id.is_empty() || id.len() > 64 {
            return Err("ruleset id must be 1..=64 characters".into());
        }
        if !id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_'))
        {
            return Err(format!("invalid ruleset id: {id}"));
        }
        if !ids.insert(id.to_string()) {
            return Err(format!("duplicate ruleset id: {id}"));
        }
        if ruleset.name.trim().is_empty() || ruleset.name.len() > 128 {
            return Err("ruleset name must be 1..=128 characters".into());
        }
        if ruleset.categories.is_empty() {
            return Err(format!("ruleset {id} must contain at least one category"));
        }
        for category in &ruleset.categories {
            if !allowed.contains(&category.as_str()) {
                return Err(format!("unknown category {category:?} in {id}"));
            }
        }
    }
    Ok(())
}

/// Canonical fingerprint of the semantic catalog contents. Version labels,
/// human names and generated_at are intentionally excluded.
pub fn catalog_fingerprint(rulesets: &[RulesetEntry]) -> String {
    let mut normalized: Vec<(String, Vec<String>)> = rulesets
        .iter()
        .map(|r| {
            let mut categories: Vec<String> = r
                .categories
                .iter()
                .map(|c| c.trim().to_ascii_lowercase())
                .filter(|c| !c.is_empty())
                .collect();
            categories.sort();
            categories.dedup();
            (r.id.trim().to_string(), categories)
        })
        .collect();
    normalized.sort_by(|a, b| a.0.cmp(&b.0));
    let encoded = serde_json::to_string(&normalized).unwrap_or_default();
    hex(ring::digest::digest(&ring::digest::SHA256, encoded.as_bytes()).as_ref())
}

pub fn sign(payload: &str, secret: &str) -> (String, String) {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    let signature = hex(&ring::hmac::sign(&key, payload.as_bytes()).as_ref().to_vec());
    let checksum = hex(ring::digest::digest(&ring::digest::SHA256, payload.as_bytes()).as_ref());
    (signature, checksum)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub fn validate_version(version: &str) -> Result<(), String> {
    let version = version.trim();
    if version.is_empty() || version.len() > 64 {
        return Err("version must be 1..=64 characters".into());
    }
    if !version
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Err("version may only contain a-z, 0-9, dot, dash and underscore".into());
    }
    Ok(())
}

pub async fn publish(
    pool: &PgPool,
    secret: &str,
    version: &str,
    actor: &str,
) -> sqlx::Result<RulepackRow> {
    publish_with_rulesets(pool, secret, version, None, actor).await
}

pub async fn publish_with_rulesets(
    pool: &PgPool,
    secret: &str,
    version: &str,
    rulesets: Option<Vec<RulesetEntry>>,
    actor: &str,
) -> sqlx::Result<RulepackRow> {
    let version = version.trim();
    let package = match rulesets {
        Some(rulesets) => build_with_rulesets(version, rulesets),
        None => build(version),
    };
    let payload = serde_json::to_string(&package).map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    let (signature, checksum) = sign(&payload, secret);
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE waf_rulepack_versions SET slot = 'retired' WHERE slot = 'previous'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE waf_rulepack_versions SET slot = 'previous' WHERE slot = 'active'")
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        r#"
        INSERT INTO waf_rulepack_versions (version, payload, signature, checksum, slot, created_by)
        VALUES ($1, $2, $3, $4, 'active', $5)
        ON CONFLICT (version) DO UPDATE SET
          payload = EXCLUDED.payload,
          signature = EXCLUDED.signature,
          checksum = EXCLUDED.checksum,
          slot = 'active',
          created_by = EXCLUDED.created_by
        "#,
    )
    .bind(version)
    .bind(&payload)
    .bind(&signature)
    .bind(&checksum)
    .bind(actor)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    get(pool, version)
        .await?
        .ok_or_else(|| sqlx::Error::RowNotFound)
}

/// Verify a stored rulepack against `secret`.
///
/// True when the signature matches the payload under the given key. Returns
/// false on any mismatch, including a payload that no longer hashes to the
/// recorded checksum, so callers treat a corrupt row the same as a stale key.
pub fn verify(row: &RulepackRow, secret: &str) -> bool {
    let (_signature, expected_checksum) = sign(&row.payload, secret);
    let checksum_ok = expected_checksum == row.checksum;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    let sig_bytes: Option<Vec<u8>> = hex_decode(&row.signature);
    let sig_ok = sig_bytes
        .as_deref()
        .is_some_and(|sig| ring::hmac::verify(&key, row.payload.as_bytes(), sig).is_ok());
    checksum_ok && sig_ok
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(value.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

/// Outcome of deciding whether a stored row needs re-signing.
#[derive(Debug, PartialEq, Eq)]
pub enum SignAction {
    /// Signature already matches the current key: leave the row alone.
    Keep,
    /// Signature does not match: rewrite `signature` and `checksum`.
    Resign {
        signature: String,
        checksum: String,
    },
}

/// Decide what to do with a stored row under the current key.
///
/// Split out from [`ensure_signed`] so the decision is testable without a
/// database, and so both the startup path and the slot-switch path provably make
/// the same decision.
pub fn sign_action(row: &RulepackRow, secret: &str) -> SignAction {
    if verify(row, secret) {
        return SignAction::Keep;
    }
    let (signature, checksum) = sign(&row.payload, secret);
    SignAction::Resign {
        signature,
        checksum,
    }
}

/// Re-sign one stored row in place when it does not verify with `secret`.
///
/// The payload is kept byte-for-byte: the catalog on disk may have moved on since
/// this version was published, and quietly swapping the ruleset contents during
/// what is only a key rotation would be a surprise. Only `signature` and
/// `checksum` change.
pub async fn ensure_signed(
    pool: &PgPool,
    secret: &str,
    row: RulepackRow,
) -> sqlx::Result<RulepackRow> {
    let (signature, checksum) = match sign_action(&row, secret) {
        SignAction::Keep => return Ok(row),
        SignAction::Resign {
            signature,
            checksum,
        } => (signature, checksum),
    };
    tracing::warn!(
        version = %row.version,
        slot = %row.slot,
        "WAF rulepack does not verify with the configured WAF_RULEPACK_SECRET; re-signing in place (was the secret rotated?)"
    );
    sqlx::query(
        r#"
        UPDATE waf_rulepack_versions
           SET signature = $2, checksum = $3, created_by = 'system:resign'
         WHERE version = $1
        "#,
    )
    .bind(&row.version)
    .bind(&signature)
    .bind(&checksum)
    .execute(pool)
    .await?;
    get(pool, &row.version)
        .await?
        .ok_or(sqlx::Error::RowNotFound)
}

/// Ensure every slot that can be served to an edge verifies with `secret`.
///
/// Both `active` and `previous` are deliverable: a domain pinned to a specific
/// version, or a grey rollout, can hand out the previous package. Re-signing only
/// the active row left the other one permanently unverifiable, which is exactly
/// what produced `HMAC verification failed` after switching slots.
pub async fn ensure_all_signed(pool: &PgPool, secret: &str) -> sqlx::Result<()> {
    if let Some(row) = active(pool).await? {
        ensure_signed(pool, secret, row).await?;
    }
    if let Some(row) = previous(pool).await? {
        ensure_signed(pool, secret, row).await?;
    }
    Ok(())
}

/// Ensure an active rulepack exists and is signed with the current key.
///
/// Rotating `WAF_RULEPACK_SECRET` used to leave the previously signed rows in
/// place, so every edge rejected the package with "HMAC verification failed"
/// until an operator republished by hand. Rows are now re-signed in place, which
/// makes key rotation self-healing.
pub async fn ensure_seed(pool: &PgPool, secret: &str) -> sqlx::Result<RulepackRow> {
    match active(pool).await? {
        Some(row) => ensure_signed(pool, secret, row).await,
        None => publish(pool, secret, "2026.11", "system").await,
    }
}

pub async fn active(pool: &PgPool) -> sqlx::Result<Option<RulepackRow>> {
    sqlx::query_as::<_, RulepackRow>(
        "SELECT version, payload, signature, checksum, slot, created_at, created_by \
         FROM waf_rulepack_versions WHERE slot = 'active' LIMIT 1",
    )
    .fetch_optional(pool)
    .await
}

pub async fn previous(pool: &PgPool) -> sqlx::Result<Option<RulepackRow>> {
    sqlx::query_as::<_, RulepackRow>(
        "SELECT version, payload, signature, checksum, slot, created_at, created_by \
         FROM waf_rulepack_versions WHERE slot = 'previous' LIMIT 1",
    )
    .fetch_optional(pool)
    .await
}

pub async fn get(pool: &PgPool, version: &str) -> sqlx::Result<Option<RulepackRow>> {
    sqlx::query_as::<_, RulepackRow>(
        "SELECT version, payload, signature, checksum, slot, created_at, created_by \
         FROM waf_rulepack_versions WHERE version = $1",
    )
    .bind(version)
    .fetch_optional(pool)
    .await
}

pub async fn list(pool: &PgPool) -> sqlx::Result<Vec<RulepackRow>> {
    sqlx::query_as::<_, RulepackRow>(
        "SELECT version, payload, signature, checksum, slot, created_at, created_by \
         FROM waf_rulepack_versions ORDER BY created_at DESC LIMIT 50",
    )
    .fetch_all(pool)
    .await
}

/// Promote `version` to active, re-signing it with `secret` first.
///
/// Switching slots used to leave the target row signed with whatever key was
/// current when it was first published. If the secret had since been rotated the
/// promotion produced a version every edge rejected, and the warning repeated on
/// every config sync with no way to recover short of restarting the control
/// plane. Signing happens before the switch so the promoted row is always
/// deliverable.
pub async fn rollback(
    pool: &PgPool,
    secret: &str,
    version: &str,
) -> sqlx::Result<Option<RulepackRow>> {
    let Some(target) = get(pool, version).await? else {
        return Ok(None);
    };
    // Re-sign before promoting so the row is deliverable the moment it becomes
    // active; `ensure_signed` is a no-op when the signature already matches.
    ensure_signed(pool, secret, target).await?;
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE waf_rulepack_versions SET slot = 'retired' WHERE version = $1")
        .bind(version)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE waf_rulepack_versions SET slot = 'previous' WHERE slot = 'active'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE waf_rulepack_versions SET slot = 'active' WHERE version = $1")
        .bind(version)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    get(pool, version).await
}

pub async fn pinned_count(pool: &PgPool, version: &str) -> sqlx::Result<i64> {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM waf_settings WHERE waf_rulepack_version = $1",
    )
    .bind(version)
    .fetch_one(pool)
    .await
}

pub async fn retire(pool: &PgPool, version: &str) -> sqlx::Result<Option<RulepackRow>> {
    let Some(row) = get(pool, version).await? else {
        return Ok(None);
    };
    if row.slot == "active" {
        return Ok(None);
    }
    sqlx::query("UPDATE waf_rulepack_versions SET slot = 'retired' WHERE version = $1")
        .bind(version)
        .execute(pool)
        .await?;
    get(pool, version).await
}

pub async fn delete(pool: &PgPool, version: &str) -> sqlx::Result<u64> {
    let r = sqlx::query("DELETE FROM waf_rulepack_versions WHERE version = $1")
        .bind(version)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

#[derive(Debug, Clone, Serialize)]
pub struct RulesetSummary {
    pub id: String,
    pub name: String,
    pub version: String,
    pub categories: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RulepackInfo {
    pub version: String,
    pub signature: String,
    pub checksum: String,
    pub slot: String,
    pub created_at: String,
    pub rulesets: Vec<RulesetSummary>,
}

impl From<&RulepackRow> for RulepackInfo {
    fn from(row: &RulepackRow) -> Self {
        let rulesets = row
            .parse_package()
            .map(|p| {
                p.rulesets
                    .into_iter()
                    .map(|r| RulesetSummary {
                        id: r.id,
                        name: r.name,
                        version: r.version,
                        categories: r.categories,
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self {
            version: row.version.clone(),
            signature: row.signature.clone(),
            checksum: row.checksum.clone(),
            slot: row.slot.clone(),
            created_at: row.created_at.to_rfc3339(),
            rulesets,
        }
    }
}

pub fn gray_bucket(domain: &str, version: &str) -> u32 {
    // Stable FNV-1a; no process-random hashing so rollout does not flap.
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in domain.as_bytes().iter().chain(version.as_bytes()) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    (hash % 100) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row_signed_with(payload: &str, secret: &str) -> RulepackRow {
        let (signature, checksum) = sign(payload, secret);
        RulepackRow {
            version: "2026.11.07-163951".into(),
            payload: payload.to_string(),
            signature,
            checksum,
            slot: "active".into(),
            created_at: chrono::Utc::now(),
            created_by: "system".into(),
        }
    }

    /// The slot-switch path must reach the same decision as the startup path;
    /// switching to a row signed with an old key used to leave it unverifiable
    /// forever, which is the warning the user observed after "set as active".
    #[test]
    fn sign_action_resigns_rows_signed_with_an_old_key() {
        let stale = row_signed_with("{\"version\":\"1\"}", "old-secret");
        match sign_action(&stale, "new-secret") {
            SignAction::Resign {
                signature,
                checksum,
            } => {
                let mut fixed = stale.clone();
                fixed.signature = signature;
                fixed.checksum = checksum;
                assert!(verify(&fixed, "new-secret"), "re-signed row must verify");
                assert_eq!(fixed.payload, stale.payload, "payload must not change");
            }
            SignAction::Keep => panic!("stale signature must be re-signed"),
        }
    }

    #[test]
    fn sign_action_keeps_rows_that_already_verify() {
        let row = row_signed_with("{}", "secret");
        assert_eq!(sign_action(&row, "secret"), SignAction::Keep);
    }

    /// Re-signing must be idempotent: running it twice leaves the row valid and
    /// produces the same signature the second time.
    #[test]
    fn resign_is_idempotent() {
        let stale = row_signed_with("{\"a\":1}", "old-secret");
        let once = sign(&stale.payload, "new-secret");
        let mut row = stale.clone();
        row.signature = once.0.clone();
        row.checksum = once.1.clone();
        assert!(verify(&row, "new-secret"));
        assert_eq!(sign_action(&row, "new-secret"), SignAction::Keep);
        assert_eq!(sign(&row.payload, "new-secret"), once);
    }

    #[test]
    fn verify_accepts_matching_secret() {
        let row = row_signed_with("{\"version\":\"1\"}", "secret-a");
        assert!(verify(&row, "secret-a"));
    }

    /// Rotating the key must be detected, otherwise the stale row is served to
    /// every edge and they all reject it with "HMAC verification failed".
    #[test]
    fn verify_rejects_rotated_secret() {
        let row = row_signed_with("{\"version\":\"1\"}", "old-secret");
        assert!(!verify(&row, "new-secret"));
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let mut row = row_signed_with("{\"version\":\"1\"}", "secret");
        row.payload = "{\"version\":\"2\"}".into();
        assert!(!verify(&row, "secret"));
    }

    #[test]
    fn verify_rejects_tampered_checksum() {
        let mut row = row_signed_with("{}", "secret");
        row.checksum = "00".repeat(32);
        assert!(!verify(&row, "secret"));
    }

    /// Re-signing after a rotation must produce a row that verifies under the
    /// new key, which is what makes startup self-healing.
    #[test]
    fn resign_after_rotation_verifies() {
        let mut row = row_signed_with("{\"version\":\"1\"}", "old-secret");
        assert!(!verify(&row, "new-secret"));
        let (signature, checksum) = sign(&row.payload, "new-secret");
        row.signature = signature;
        row.checksum = checksum;
        assert!(verify(&row, "new-secret"));
        // The payload itself is untouched: re-signing must not rewrite rules.
        assert_eq!(row.payload, "{\"version\":\"1\"}");
    }

    #[test]
    fn signing_key_rejects_unset_secret() {
        assert!(signing_key("").is_none());
        assert!(signing_key("   ").is_none());
    }

    /// A published constant used to be substituted when the secret was unset,
    /// which let anyone forge a rulepack that disables managed signatures.
    #[test]
    fn signing_key_never_returns_a_shared_default() {
        for secret in ["", " ", "\t", "\n"] {
            assert!(
                signing_key(secret).is_none(),
                "empty secret must not resolve to a built-in key"
            );
        }
        assert_eq!(signing_key("  real-secret  ").as_deref(), Some("real-secret"));
    }

    #[test]
    fn signature_is_stable_and_detects_tamper() {
        let payload = "{\"id\":\"x\"}";
        let (a, ca) = sign(payload, "secret");
        let (b, cb) = sign(payload, "secret");
        assert_eq!(a, b);
        assert_eq!(ca, cb);
        let (c, _) = sign("{\"id\":\"y\"}", "secret");
        assert_ne!(a, c);
    }

    #[test]
    fn custom_catalog_validation() {
        let rulesets = vec![RulesetEntry {
            id: "owasp-core".into(),
            name: "OWASP core".into(),
            version: "test".into(),
            categories: vec!["xss".into(), "traversal".into()],
        }];
        assert!(validate_rulesets(&rulesets).is_ok());
        let bad = vec![RulesetEntry {
            id: "owasp-core".into(),
            name: "OWASP core".into(),
            version: "test".into(),
            categories: vec!["not-a-category".into()],
        }];
        assert!(validate_rulesets(&bad).is_err());
    }

    #[test]
    fn gray_bucket_is_stable() {
        assert_eq!(gray_bucket("a.example.com", "1"), gray_bucket("a.example.com", "1"));
        assert!(gray_bucket("a.example.com", "1") < 100);
    }

    #[test]
    fn version_validation() {
        assert!(validate_version("2026.11").is_ok());
        assert!(validate_version("../x").is_err());
    }
}
