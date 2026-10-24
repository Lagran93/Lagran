//! Shared domain models used by both control plane and edge plane

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A project (tenant workspace)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: Uuid,
    pub name: String,
    pub owner_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Domain configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Domain {
    pub id: Uuid,
    pub project_id: Uuid,
    pub name: String, // e.g. "cdn.example.com"
    pub origin: Origin,
    pub ssl_enabled: bool,
    pub status: DomainStatus,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Origin {
    pub host: String,
    pub port: u16,
    pub protocol: Protocol,
    pub path_prefix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Protocol {
    Http,
    Https,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DomainStatus {
    Active,
    Pending,
    Disabled,
}

/// Cache rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheRule {
    pub id: Uuid,
    pub domain_id: Uuid,
    pub path_pattern: String, // e.g. "/static/*"
    pub ttl_seconds: u64,
    pub priority: i32,
}

/// Edge node registration info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeNode {
    pub id: Uuid,
    pub name: String,
    pub region: String,
    pub ip: String,
    pub status: NodeStatus,
    pub last_heartbeat: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeStatus {
    Online,
    Offline,
    Draining,
}
