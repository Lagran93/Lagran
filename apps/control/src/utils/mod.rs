//! Auth helpers: password hash + JWT

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use uuid::Uuid;

/// Normalize an edge node address for display/API output.
///
/// Node heartbeats can report a listen address such as `0.0.0.0:80`; that is
/// not a reachable edge IP and must not be shown as one. Loopback, unspecified
/// and multicast addresses are dropped; ports and URL schemes are stripped.
pub fn normalize_node_ip(raw: &str) -> Option<String> {
    let mut value = raw.trim();
    if let Some((_, rest)) = value.split_once("://") {
        value = rest;
    }
    let value = value.trim_end_matches('/');
    let ip = value
        .parse::<IpAddr>()
        .ok()
        .or_else(|| value.parse::<SocketAddr>().ok().map(|addr| addr.ip()))?;
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return None;
    }
    Some(ip.to_string())
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String, // user id
    pub email: String,
    pub name: String,
    pub exp: i64,
    pub iat: i64,
    /// Session epoch. Tokens with a stale version are rejected after a
    /// password change/reset.
    #[serde(default)]
    pub ver: i64,
}

pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    bcrypt::verify(password, hash)
}

pub fn issue_token(
    user_id: Uuid,
    email: &str,
    name: &str,
    secret: &str,
    expire_hours: i64,
    token_version: i64,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        name: name.to_string(),
        iat: now.timestamp(),
        exp: (now + Duration::hours(expire_hours)).timestamp(),
        ver: token_version,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

pub fn decode_token(token: &str, secret: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )?;
    Ok(data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn token_carries_and_decodes_version() {
        let id = Uuid::new_v4();
        let token = issue_token(id, "u@example.test", "U", "test-secret", 1, 7).unwrap();
        let claims = decode_token(&token, "test-secret").unwrap();
        assert_eq!(claims.ver, 7);
    }

    #[test]
    fn old_token_without_version_defaults_to_zero() {
        let claims: Claims = serde_json::from_str(
            r#"{"sub":"00000000-0000-0000-0000-000000000000","email":"u@example.test","name":"U","exp":9999999999,"iat":1}"#,
        )
        .unwrap();
        assert_eq!(claims.ver, 0);
    }

    #[test]
    fn node_ip_ignores_listen_and_loopback_addresses() {
        assert_eq!(normalize_node_ip("0.0.0.0:80"), None);
        assert_eq!(normalize_node_ip("[::]:443"), None);
        assert_eq!(normalize_node_ip("127.0.0.1"), None);
        assert_eq!(
            normalize_node_ip("146.56.187.190").as_deref(),
            Some("146.56.187.190")
        );
        assert_eq!(
            normalize_node_ip("https://129.154.202.52:443/").as_deref(),
            Some("129.154.202.52")
        );
    }
}
