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

pub async fn ensure_seed(pool: &PgPool, secret: &str) -> sqlx::Result<RulepackRow> {
    if let Some(row) = active(pool).await? {
        return Ok(row);
    }
    publish(pool, secret, "2026.11", "system").await
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

pub async fn rollback(pool: &PgPool, version: &str) -> sqlx::Result<Option<RulepackRow>> {
    if get(pool, version).await?.is_none() {
        return Ok(None);
    }
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
