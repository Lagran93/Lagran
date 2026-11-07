//! Verified, disk-cached WAF rulepacks.

use ring::hmac;
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct RulepackEntry {
    pub id: String,
    #[serde(default)]
    pub categories: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rulepack {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub rulesets: Vec<RulepackEntry>,
}

pub fn signing_key(config_secret: &str, agent_token: &str) -> String {
    let secret = config_secret.trim();
    if !secret.is_empty() {
        return secret.to_string();
    }
    // Agent tokens are per-node on Edge and global on Control; they are not a
    // shared rulepack key. Use the built-in development key when unset, and
    // require WAF_RULEPACK_SECRET in production.
    let _ = agent_token;
    "lagran-dev-waf-rulepack-secret".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignedRulepack {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub payload: String,
    #[serde(default)]
    pub signature: String,
    #[serde(default)]
    pub checksum: String,
}

impl SignedRulepack {
    /// Verify checksum and HMAC over the exact signed payload, then cache it.
    pub fn verify_and_cache(&self, secret: &str, cache_dir: &str) -> Option<Rulepack> {
        if self.payload.is_empty() || self.signature.is_empty() {
            return None;
        }
        let expected = hex(ring::digest::digest(&ring::digest::SHA256, self.payload.as_bytes()).as_ref());
        if !self.checksum.is_empty() && !constant_eq(&self.checksum, &expected) {
            tracing::warn!(version = %self.version, "WAF rulepack checksum mismatch");
            return None;
        }
        let Some(signature) = from_hex(&self.signature) else {
            tracing::warn!(version = %self.version, "WAF rulepack signature is not hex");
            return None;
        };
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        if hmac::verify(&key, self.payload.as_bytes(), &signature).is_err() {
            tracing::warn!(version = %self.version, "WAF rulepack HMAC verification failed");
            return None;
        }
        let package: Rulepack = serde_json::from_str(&self.payload).ok()?;
        if !self.version.is_empty() && !package.version.is_empty() && self.version != package.version
        {
            tracing::warn!(
                envelope = %self.version,
                package = %package.version,
                "WAF rulepack version mismatch"
            );
            return None;
        }
        if let Err(e) = cache(self, cache_dir) {
            tracing::warn!(version = %self.version, error = %e, "failed to cache WAF rulepack");
        }
        Some(package)
    }
}

fn cache(pack: &SignedRulepack, cache_dir: &str) -> std::io::Result<()> {
    let cache_dir = cache_dir.trim();
    if cache_dir.is_empty() || !safe_component(&pack.version) {
        return Ok(());
    }
    let dir = Path::new(cache_dir);
    std::fs::create_dir_all(dir)?;
    let payload_path = dir.join(format!("{}.json", pack.version));
    let sig_path = dir.join(format!("{}.sig", pack.version));
    atomic_write(&payload_path, pack.payload.as_bytes())?;
    atomic_write(
        &sig_path,
        format!("{}\n{}\n", pack.signature, pack.checksum).as_bytes(),
    )
}

fn atomic_write(path: &PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(tmp, path)
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

fn constant_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn from_hex(input: &str) -> Option<Vec<u8>> {
    let input = input.trim();
    if input.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let mut chars = input.as_bytes().chunks(2);
    while let Some(pair) = chars.next() {
        let s = std::str::from_utf8(pair).ok()?;
        out.push(u8::from_str_radix(s, 16).ok()?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed(payload: &str, secret: &str) -> SignedRulepack {
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        let signature = hex(hmac::sign(&key, payload.as_bytes()).as_ref());
        let checksum = hex(ring::digest::digest(&ring::digest::SHA256, payload.as_bytes()).as_ref());
        SignedRulepack {
            version: "1".into(),
            payload: payload.into(),
            signature,
            checksum,
        }
    }

    #[test]
    fn verifies_and_rejects_tamper() {
        let payload = r#"{"id":"lagran-waf-core","version":"1","rulesets":[]}"#;
        let good = signed(payload, "secret");
        assert!(good.verify_and_cache("secret", "").is_some());
        assert!(good.verify_and_cache("wrong", "").is_none());
        let mut bad = good.clone();
        bad.payload.push(' ');
        assert!(bad.verify_and_cache("secret", "").is_none());
    }

    #[test]
    fn writes_disk_cache() {
        let payload = r#"{"id":"lagran-waf-core","version":"1","rulesets":[]}"#;
        let good = signed(payload, "secret");
        let dir = std::env::temp_dir().join(format!(
            "lagran-waf-rulepack-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(good
            .verify_and_cache("secret", dir.to_str().unwrap())
            .is_some());
        assert!(dir.join("1.json").exists());
        assert!(dir.join("1.sig").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn safe_paths() {
        assert!(safe_component("2026.11"));
        assert!(!safe_component("../x"));
    }
}
