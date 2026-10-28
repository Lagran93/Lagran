//! Database access layer

pub mod alert;
pub use alert::*;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRow {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub name: String,
    pub role: String,
    pub is_active: bool,
    pub last_login_at: Option<DateTime<Utc>>,
    pub token_version: i64,
    pub created_at: DateTime<Utc>,
    /// Populated by the admin list query only.
    #[sqlx(default)]
    pub project_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainOrigin {
    pub host: String,
    pub port: u16,
    pub proto: String,
    #[serde(default = "default_origin_weight")]
    pub weight: u32,
    #[serde(default)]
    pub priority: i32,
    #[serde(default = "default_origin_enabled")]
    pub enabled: bool,
}

fn default_origin_weight() -> u32 {
    100
}

fn default_origin_enabled() -> bool {
    true
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DomainRow {
    pub id: Uuid,
    pub project_id: Option<Uuid>,
    pub name: String,
    pub origin_host: String,
    pub origin_port: i32,
    pub origin_proto: String,
    pub ssl_enabled: bool,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub rate_limit_rps: i32,
    pub rate_limit_burst: i32,
    #[sqlx(default)]
    pub origins: sqlx::types::Json<Vec<DomainOrigin>>,
    #[sqlx(default)]
    pub backup_origin_host: String,
    #[sqlx(default)]
    pub backup_origin_port: i32,
    #[sqlx(default)]
    pub backup_origin_proto: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct NodeRow {
    pub id: Uuid,
    pub name: String,
    pub region: String,
    pub ip: String,
    pub status: String,
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub agent_url: String,
    pub auth_token: String,
    pub cpu_usage: Option<f64>,
    pub memory_usage: Option<f64>,
    pub active_connections: Option<i64>,
    pub version: String,
    pub created_at: DateTime<Utc>,
    #[sqlx(default)]
    pub public_ip: String,
    #[sqlx(default)]
    pub isp: String,
    #[sqlx(default)]
    pub country: String,
    #[sqlx(default)]
    pub province: String,
    #[sqlx(default)]
    pub city: String,
    #[sqlx(default)]
    pub weight: i32,
    #[sqlx(default)]
    pub max_bandwidth_mbps: i32,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CacheRuleRow {
    pub id: Uuid,
    pub domain_id: Uuid,
    pub path_pattern: String,
    /// glob | regex
    pub match_type: String,
    pub ttl_seconds: i64,
    pub priority: i32,
    pub action: String,
    pub swr_seconds: i64,
    pub enabled: bool,
    pub match_methods: String,
    pub match_query: String,
    pub browser_ttl_seconds: i64,
    pub ignore_query: Option<bool>,
    pub ignore_cookie: bool,
    pub match_content_type: String,
    pub note: String,
}

/// Fields shared by rule create/update.
#[derive(Debug, Clone)]
pub struct RuleInput<'a> {
    pub path_pattern: &'a str,
    pub match_type: &'a str,
    pub ttl_seconds: i64,
    pub priority: i32,
    pub action: &'a str,
    pub swr_seconds: i64,
    pub enabled: bool,
    pub match_methods: &'a str,
    pub match_query: &'a str,
    pub browser_ttl_seconds: i64,
    pub ignore_query: Option<bool>,
    pub ignore_cookie: bool,
    pub match_content_type: &'a str,
    pub note: &'a str,
}

pub async fn find_user_by_email(pool: &PgPool, email: &str) -> sqlx::Result<Option<UserRow>> {
    sqlx::query_as::<_, UserRow>(
        "SELECT id, email, password_hash, name, role, is_active, last_login_at, token_version, created_at FROM users WHERE lower(email) = lower($1)",
    )
    .bind(email)
    .fetch_optional(pool)
    .await
}

pub async fn find_user_by_id(pool: &PgPool, id: Uuid) -> sqlx::Result<Option<UserRow>> {
    sqlx::query_as::<_, UserRow>(
        "SELECT id, email, password_hash, name, role, is_active, last_login_at, token_version, created_at FROM users WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn create_user(
    pool: &PgPool,
    email: &str,
    password_hash: &str,
    name: &str,
) -> sqlx::Result<UserRow> {
    sqlx::query_as::<_, UserRow>(
        r#"
        INSERT INTO users (email, password_hash, name)
        VALUES ($1, $2, $3)
        RETURNING id, email, password_hash, name, role, is_active, last_login_at, token_version, created_at
        "#,
    )
    .bind(email)
    .bind(password_hash)
    .bind(name)
    .fetch_one(pool)
    .await
}

pub async fn create_user_with_role(
    pool: &PgPool,
    email: &str,
    password_hash: &str,
    name: &str,
    role: &str,
) -> sqlx::Result<UserRow> {
    sqlx::query_as::<_, UserRow>(
        r#"
        INSERT INTO users (email, password_hash, name, role)
        VALUES ($1, $2, $3, $4)
        RETURNING id, email, password_hash, name, role, is_active, last_login_at, token_version, created_at
        "#,
    )
    .bind(email)
    .bind(password_hash)
    .bind(name)
    .bind(role)
    .fetch_one(pool)
    .await
}

pub async fn list_users(pool: &PgPool) -> sqlx::Result<Vec<UserRow>> {
    sqlx::query_as::<_, UserRow>(
        r#"
        SELECT u.id, u.email, u.password_hash, u.name, u.role, u.is_active,
               u.last_login_at, u.token_version, u.created_at,
               (SELECT COUNT(*) FROM projects p WHERE p.owner_id = u.id) AS project_count
        FROM users u
        ORDER BY u.created_at DESC
        "#,
    )
    .fetch_all(pool)
    .await
}

pub async fn update_user_admin(
    pool: &PgPool,
    id: Uuid,
    name: &str,
    role: &str,
    is_active: bool,
    password_hash: Option<&str>,
) -> sqlx::Result<Option<UserRow>> {
    sqlx::query_as::<_, UserRow>(
        r#"
        UPDATE users SET
            name = $2, role = $3, is_active = $4,
            password_hash = COALESCE($5, password_hash),
            token_version = token_version + CASE WHEN $5 IS NULL THEN 0 ELSE 1 END,
            updated_at = NOW()
        WHERE id = $1
        RETURNING id, email, password_hash, name, role, is_active, last_login_at, token_version, created_at
        "#,
    )
    .bind(id)
    .bind(name)
    .bind(role)
    .bind(is_active)
    .bind(password_hash)
    .fetch_optional(pool)
    .await
}

pub async fn update_user_profile(
    pool: &PgPool,
    id: Uuid,
    name: &str,
) -> sqlx::Result<Option<UserRow>> {
    sqlx::query_as::<_, UserRow>(
        r#"
        UPDATE users SET name = $2, updated_at = NOW()
        WHERE id = $1
        RETURNING id, email, password_hash, name, role, is_active, last_login_at, token_version, created_at
        "#,
    )
    .bind(id)
    .bind(name)
    .fetch_optional(pool)
    .await
}

pub async fn update_user_password(
    pool: &PgPool,
    id: Uuid,
    password_hash: &str,
) -> sqlx::Result<Option<i64>> {
    let row: Option<(i64,)> = sqlx::query_as(
        "UPDATE users SET password_hash = $2, token_version = token_version + 1, \
         updated_at = NOW() WHERE id = $1 RETURNING token_version",
    )
    .bind(id)
    .bind(password_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.0))
}

/// Session fields needed to validate a JWT: current role, active flag and the
/// token version/epoch. Incrementing `token_version` revokes old tokens.
pub async fn get_user_session(
    pool: &PgPool,
    id: Uuid,
) -> sqlx::Result<Option<(String, bool, i64)>> {
    sqlx::query_as("SELECT role, is_active, token_version FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn touch_last_login(pool: &PgPool, id: Uuid) -> sqlx::Result<()> {
    sqlx::query("UPDATE users SET last_login_at = NOW(), updated_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_user(pool: &PgPool, id: Uuid) -> sqlx::Result<u64> {
    let r = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

pub async fn count_active_admins(pool: &PgPool) -> sqlx::Result<i64> {
    let (n,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active")
            .fetch_one(pool)
            .await?;
    Ok(n)
}

pub async fn list_domains(pool: &PgPool) -> sqlx::Result<Vec<DomainRow>> {
    sqlx::query_as::<_, DomainRow>(
        r#"
        SELECT id, project_id, name, origin_host, origin_port, origin_proto,
               ssl_enabled, status, created_at, rate_limit_rps, rate_limit_burst,
               COALESCE(origins, '[]'::jsonb) AS origins, COALESCE(backup_origin_host, '') AS backup_origin_host,
               COALESCE(backup_origin_port, 0) AS backup_origin_port,
               COALESCE(backup_origin_proto, 'http') AS backup_origin_proto
        FROM domains
        ORDER BY created_at DESC
        "#,
    )
    .fetch_all(pool)
    .await
}

pub async fn get_domain(pool: &PgPool, id: Uuid) -> sqlx::Result<Option<DomainRow>> {
    sqlx::query_as::<_, DomainRow>(
        r#"
        SELECT id, project_id, name, origin_host, origin_port, origin_proto,
               ssl_enabled, status, created_at, rate_limit_rps, rate_limit_burst,
               COALESCE(origins, '[]'::jsonb) AS origins, COALESCE(backup_origin_host, '') AS backup_origin_host,
               COALESCE(backup_origin_port, 0) AS backup_origin_port,
               COALESCE(backup_origin_proto, 'http') AS backup_origin_proto
        FROM domains WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn get_domain_by_name(pool: &PgPool, name: &str) -> sqlx::Result<Option<DomainRow>> {
    sqlx::query_as::<_, DomainRow>(
        r#"
        SELECT id, project_id, name, origin_host, origin_port, origin_proto,
               ssl_enabled, status, created_at, rate_limit_rps, rate_limit_burst,
               COALESCE(origins, '[]'::jsonb) AS origins, COALESCE(backup_origin_host, '') AS backup_origin_host,
               COALESCE(backup_origin_port, 0) AS backup_origin_port,
               COALESCE(backup_origin_proto, 'http') AS backup_origin_proto
        FROM domains WHERE name = $1
        "#,
    )
    .bind(name)
    .fetch_optional(pool)
    .await
}

pub async fn create_domain(
    pool: &PgPool,
    name: &str,
    origin_host: &str,
    origin_port: i32,
    origin_proto: &str,
    ssl_enabled: bool,
) -> sqlx::Result<DomainRow> {
    sqlx::query_as::<_, DomainRow>(
        r#"
        INSERT INTO domains (name, origin_host, origin_port, origin_proto, ssl_enabled, status)
        VALUES ($1, $2, $3, $4, $5, 'active')
        RETURNING id, project_id, name, origin_host, origin_port, origin_proto,
                  ssl_enabled, status, created_at, rate_limit_rps, rate_limit_burst
        "#,
    )
    .bind(name)
    .bind(origin_host)
    .bind(origin_port)
    .bind(origin_proto)
    .bind(ssl_enabled)
    .fetch_one(pool)
    .await
}

pub async fn delete_domain(pool: &PgPool, id: Uuid) -> sqlx::Result<u64> {
    let _ =
        sqlx::query("DELETE FROM cc_bans WHERE domain = (SELECT name FROM domains WHERE id = $1)")
            .bind(id)
            .execute(pool)
            .await;
    let _ = sqlx::query(
        "DELETE FROM origin_health WHERE domain_name = (SELECT name FROM domains WHERE id = $1)",
    )
    .bind(id)
    .execute(pool)
    .await;
    let r = sqlx::query("DELETE FROM domains WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

pub async fn list_nodes(pool: &PgPool) -> sqlx::Result<Vec<NodeRow>> {
    sqlx::query_as::<_, NodeRow>(
        r#"
        SELECT id, name, region, ip, status, last_heartbeat,
               COALESCE(agent_url, '') AS agent_url, auth_token,
               cpu_usage, memory_usage, active_connections,
               COALESCE(version, '') AS version, created_at,
               COALESCE(public_ip, '') AS public_ip,
               COALESCE(isp, '') AS isp,
               COALESCE(country, 'CN') AS country,
               COALESCE(province, '') AS province,
               COALESCE(city, '') AS city,
               COALESCE(weight, 100) AS weight,
               COALESCE(max_bandwidth_mbps, 0) AS max_bandwidth_mbps
        FROM edge_nodes
        ORDER BY name
        "#,
    )
    .fetch_all(pool)
    .await
}

pub async fn get_node(pool: &PgPool, id: Uuid) -> sqlx::Result<Option<NodeRow>> {
    sqlx::query_as::<_, NodeRow>(
        r#"
        SELECT id, name, region, ip, status, last_heartbeat,
               COALESCE(agent_url, '') AS agent_url, auth_token,
               cpu_usage, memory_usage, active_connections,
               COALESCE(version, '') AS version, created_at,
               COALESCE(public_ip, '') AS public_ip,
               COALESCE(isp, '') AS isp,
               COALESCE(country, 'CN') AS country,
               COALESCE(province, '') AS province,
               COALESCE(city, '') AS city,
               COALESCE(weight, 100) AS weight,
               COALESCE(max_bandwidth_mbps, 0) AS max_bandwidth_mbps
        FROM edge_nodes WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn get_node_by_name(pool: &PgPool, name: &str) -> sqlx::Result<Option<NodeRow>> {
    sqlx::query_as::<_, NodeRow>(
        r#"
        SELECT id, name, region, ip, status, last_heartbeat,
               COALESCE(agent_url, '') AS agent_url, auth_token,
               cpu_usage, memory_usage, active_connections,
               COALESCE(version, '') AS version, created_at,
               COALESCE(public_ip, '') AS public_ip,
               COALESCE(isp, '') AS isp,
               COALESCE(country, 'CN') AS country,
               COALESCE(province, '') AS province,
               COALESCE(city, '') AS city,
               COALESCE(weight, 100) AS weight,
               COALESCE(max_bandwidth_mbps, 0) AS max_bandwidth_mbps
        FROM edge_nodes WHERE name = $1
        "#,
    )
    .bind(name)
    .fetch_optional(pool)
    .await
}

pub async fn list_online_nodes_with_agent(pool: &PgPool) -> sqlx::Result<Vec<NodeRow>> {
    sqlx::query_as::<_, NodeRow>(
        r#"
        SELECT id, name, region, ip, status, last_heartbeat,
               COALESCE(agent_url, '') AS agent_url, auth_token,
               cpu_usage, memory_usage, active_connections,
               COALESCE(version, '') AS version, created_at,
               COALESCE(public_ip, '') AS public_ip,
               COALESCE(isp, '') AS isp,
               COALESCE(country, 'CN') AS country,
               COALESCE(province, '') AS province,
               COALESCE(city, '') AS city,
               COALESCE(weight, 100) AS weight,
               COALESCE(max_bandwidth_mbps, 0) AS max_bandwidth_mbps
        FROM edge_nodes
        WHERE status = 'online' AND COALESCE(agent_url, '') <> ''
        ORDER BY name
        "#,
    )
    .fetch_all(pool)
    .await
}

/// Pre-register a node. It stays `pending` until the first heartbeat arrives.
pub async fn create_node(
    pool: &PgPool,
    name: &str,
    region: &str,
    ip: &str,
    agent_url: &str,
    auth_token: &str,
) -> sqlx::Result<NodeRow> {
    sqlx::query_as::<_, NodeRow>(
        r#"
        INSERT INTO edge_nodes (name, region, ip, agent_url, status, auth_token)
        VALUES ($1, $2, $3, $4, 'pending', $5)
        RETURNING id, name, region, ip, status, last_heartbeat,
                  COALESCE(agent_url, '') AS agent_url, auth_token,
                  cpu_usage, memory_usage, active_connections,
                  COALESCE(version, '') AS version, created_at,
               COALESCE(public_ip, '') AS public_ip,
               COALESCE(isp, '') AS isp,
               COALESCE(country, 'CN') AS country,
               COALESCE(province, '') AS province,
               COALESCE(city, '') AS city,
               COALESCE(weight, 100) AS weight,
               COALESCE(max_bandwidth_mbps, 0) AS max_bandwidth_mbps
        "#,
    )
    .bind(name)
    .bind(region)
    .bind(ip)
    .bind(agent_url)
    .bind(auth_token)
    .fetch_one(pool)
    .await
}

pub async fn update_node(
    pool: &PgPool,
    id: Uuid,
    name: &str,
    region: &str,
    agent_url: &str,
) -> sqlx::Result<Option<NodeRow>> {
    sqlx::query_as::<_, NodeRow>(
        r#"
        UPDATE edge_nodes
        SET name = $2, region = $3, agent_url = $4, updated_at = NOW()
        WHERE id = $1
        RETURNING id, name, region, ip, status, last_heartbeat,
                  COALESCE(agent_url, '') AS agent_url, auth_token,
                  cpu_usage, memory_usage, active_connections,
                  COALESCE(version, '') AS version, created_at,
               COALESCE(public_ip, '') AS public_ip,
               COALESCE(isp, '') AS isp,
               COALESCE(country, 'CN') AS country,
               COALESCE(province, '') AS province,
               COALESCE(city, '') AS city,
               COALESCE(weight, 100) AS weight,
               COALESCE(max_bandwidth_mbps, 0) AS max_bandwidth_mbps
        "#,
    )
    .bind(id)
    .bind(name)
    .bind(region)
    .bind(agent_url)
    .fetch_optional(pool)
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn update_node_meta(
    pool: &PgPool,
    id: Uuid,
    public_ip: &str,
    isp: &str,
    country: &str,
    province: &str,
    city: &str,
    weight: i32,
    max_bandwidth_mbps: i32,
) -> sqlx::Result<Option<NodeRow>> {
    sqlx::query_as::<_, NodeRow>(
        r#"
        UPDATE edge_nodes SET
            public_ip = $2, isp = $3, country = $4, province = $5,
            city = $6, weight = $7, max_bandwidth_mbps = $8,
            updated_at = NOW()
        WHERE id = $1
        RETURNING id, name, region, ip, status, last_heartbeat,
                  COALESCE(agent_url, '') AS agent_url, auth_token,
                  cpu_usage, memory_usage, active_connections,
                  COALESCE(version, '') AS version, created_at,
                  COALESCE(public_ip, '') AS public_ip,
                  COALESCE(isp, '') AS isp,
                  COALESCE(country, 'CN') AS country,
                  COALESCE(province, '') AS province,
                  COALESCE(city, '') AS city,
                  COALESCE(weight, 100) AS weight,
                  COALESCE(max_bandwidth_mbps, 0) AS max_bandwidth_mbps
        "#,
    )
    .bind(id)
    .bind(public_ip)
    .bind(isp)
    .bind(country)
    .bind(province)
    .bind(city)
    .bind(weight)
    .bind(max_bandwidth_mbps)
    .fetch_optional(pool)
    .await
}

pub async fn set_node_public_ip(pool: &PgPool, id: Uuid, public_ip: &str) -> sqlx::Result<()> {
    sqlx::query("UPDATE edge_nodes SET public_ip = $2 WHERE id = $1")
        .bind(id)
        .bind(public_ip)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn set_node_status(
    pool: &PgPool,
    id: Uuid,
    status: &str,
) -> sqlx::Result<Option<NodeRow>> {
    sqlx::query_as::<_, NodeRow>(
        r#"
        UPDATE edge_nodes
        SET status = $2, updated_at = NOW()
        WHERE id = $1
        RETURNING id, name, region, ip, status, last_heartbeat,
                  COALESCE(agent_url, '') AS agent_url, auth_token,
                  cpu_usage, memory_usage, active_connections,
                  COALESCE(version, '') AS version, created_at,
               COALESCE(public_ip, '') AS public_ip,
               COALESCE(isp, '') AS isp,
               COALESCE(country, 'CN') AS country,
               COALESCE(province, '') AS province,
               COALESCE(city, '') AS city,
               COALESCE(weight, 100) AS weight,
               COALESCE(max_bandwidth_mbps, 0) AS max_bandwidth_mbps
        "#,
    )
    .bind(id)
    .bind(status)
    .fetch_optional(pool)
    .await
}

pub async fn delete_node(pool: &PgPool, id: Uuid) -> sqlx::Result<u64> {
    let r = sqlx::query("DELETE FROM edge_nodes WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

pub async fn node_token_exists(pool: &PgPool, token: &str) -> sqlx::Result<bool> {
    if token.is_empty() {
        return Ok(false);
    }
    let row: Option<(i32,)> =
        sqlx::query_as("SELECT 1 FROM edge_nodes WHERE auth_token = $1 LIMIT 1")
            .bind(token)
            .fetch_optional(pool)
            .await?;
    Ok(row.is_some())
}

/// Resolve a per-node token to the node name it belongs to.
pub async fn node_name_for_token(pool: &PgPool, token: &str) -> sqlx::Result<Option<String>> {
    if token.is_empty() {
        return Ok(None);
    }
    let row: Option<(String,)> =
        sqlx::query_as("SELECT name FROM edge_nodes WHERE auth_token = $1 LIMIT 1")
            .bind(token)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|r| r.0))
}

#[allow(clippy::too_many_arguments)]
pub async fn upsert_node_heartbeat(
    pool: &PgPool,
    node_key: &str,
    region: &str,
    ip: &str,
    agent_url: &str,
    cpu_usage: Option<f64>,
    memory_usage: Option<f64>,
    active_connections: Option<i64>,
    version: &str,
) -> sqlx::Result<NodeRow> {
    let existing = sqlx::query_as::<_, NodeRow>(
        r#"
        SELECT id, name, region, ip, status, last_heartbeat,
               COALESCE(agent_url, '') AS agent_url, auth_token,
               cpu_usage, memory_usage, active_connections,
               COALESCE(version, '') AS version, created_at,
               COALESCE(public_ip, '') AS public_ip,
               COALESCE(isp, '') AS isp,
               COALESCE(country, 'CN') AS country,
               COALESCE(province, '') AS province,
               COALESCE(city, '') AS city,
               COALESCE(weight, 100) AS weight,
               COALESCE(max_bandwidth_mbps, 0) AS max_bandwidth_mbps
        FROM edge_nodes WHERE name = $1
        "#,
    )
    .bind(node_key)
    .fetch_optional(pool)
    .await?;

    let node = existing.ok_or(sqlx::Error::RowNotFound)?;
    // A disabled node keeps its status: it still reports telemetry but the
    // edge stops serving traffic until an admin enables it again.
    sqlx::query_as::<_, NodeRow>(
        r#"
            UPDATE edge_nodes
            SET region = CASE WHEN region = '' THEN $2 ELSE region END,
                ip = $3,
                agent_url = CASE WHEN COALESCE(agent_url, '') = '' THEN $4 ELSE agent_url END,
                status = CASE WHEN status = 'disabled' THEN 'disabled' ELSE 'online' END,
                last_heartbeat = NOW(),
                cpu_usage = $5,
                memory_usage = $6,
                active_connections = $7,
                version = $8,
                updated_at = NOW()
            WHERE id = $1
            RETURNING id, name, region, ip, status, last_heartbeat,
                      COALESCE(agent_url, '') AS agent_url, auth_token,
                      cpu_usage, memory_usage, active_connections,
                      COALESCE(version, '') AS version, created_at,
               COALESCE(public_ip, '') AS public_ip,
               COALESCE(isp, '') AS isp,
               COALESCE(country, 'CN') AS country,
               COALESCE(province, '') AS province,
               COALESCE(city, '') AS city,
               COALESCE(weight, 100) AS weight,
               COALESCE(max_bandwidth_mbps, 0) AS max_bandwidth_mbps
            "#,
    )
    .bind(node.id)
    .bind(region)
    .bind(ip)
    .bind(agent_url)
    .bind(cpu_usage)
    .bind(memory_usage)
    .bind(active_connections)
    .bind(version)
    .fetch_one(pool)
    .await
}

pub async fn list_rules_for_domain(
    pool: &PgPool,
    domain_id: Uuid,
) -> sqlx::Result<Vec<CacheRuleRow>> {
    sqlx::query_as::<_, CacheRuleRow>(
        r#"
        SELECT id, domain_id, path_pattern, match_type, ttl_seconds, priority, action, swr_seconds,
               enabled, match_methods, match_query, browser_ttl_seconds, ignore_query, ignore_cookie, match_content_type, note
        FROM cache_rules
        WHERE domain_id = $1
        ORDER BY priority DESC
        "#,
    )
    .bind(domain_id)
    .fetch_all(pool)
    .await
}

pub async fn ensure_demo_user(pool: &PgPool) -> anyhow::Result<()> {
    let exists = find_user_by_email(pool, "demo@lagran.dev").await?;
    if exists.is_none() {
        let hash = crate::utils::hash_password("demo123")
            .map_err(|e| anyhow::anyhow!("bcrypt error: {e}"))?;
        create_user(pool, "demo@lagran.dev", &hash, "Demo User").await?;
        tracing::info!("seeded demo user demo@lagran.dev / demo123");
    }
    // Fresh databases seed the demo user *after* migrations ran, so the
    // migration's admin promotion would miss it; enforce it here.
    sqlx::query("UPDATE users SET role = 'admin' WHERE email = 'demo@lagran.dev'")
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn ensure_demo_domain(pool: &PgPool) -> sqlx::Result<()> {
    if get_domain_by_name(pool, "cdn.example.com").await?.is_none() {
        let d = create_domain(pool, "cdn.example.com", "example.com", 443, "https", true).await?;
        sqlx::query(
            r#"
            INSERT INTO cache_rules (domain_id, path_pattern, ttl_seconds, priority)
            VALUES ($1, '/*', 60, 0)
            "#,
        )
        .bind(d.id)
        .execute(pool)
        .await?;
        tracing::info!("seeded demo domain cdn.example.com");
    }
    Ok(())
}

pub async fn update_domain(
    pool: &PgPool,
    id: Uuid,
    origin_host: Option<&str>,
    origin_port: Option<i32>,
    origin_proto: Option<&str>,
    ssl_enabled: Option<bool>,
    status: Option<&str>,
) -> sqlx::Result<Option<DomainRow>> {
    let existing = get_domain(pool, id).await?;
    let Some(e) = existing else {
        return Ok(None);
    };
    let host = origin_host.unwrap_or(&e.origin_host);
    let port = origin_port.unwrap_or(e.origin_port);
    let proto = origin_proto.unwrap_or(&e.origin_proto);
    let ssl = ssl_enabled.unwrap_or(e.ssl_enabled);
    let st = status.unwrap_or(&e.status);

    let row = sqlx::query_as::<_, DomainRow>(
        r#"
        UPDATE domains SET
            origin_host = $2, origin_port = $3, origin_proto = $4,
            ssl_enabled = $5, status = $6, updated_at = NOW()
        WHERE id = $1
        RETURNING id, project_id, name, origin_host, origin_port, origin_proto,
                  ssl_enabled, status, created_at, rate_limit_rps, rate_limit_burst
        "#,
    )
    .bind(id)
    .bind(host)
    .bind(port)
    .bind(proto)
    .bind(ssl)
    .bind(st)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn list_all_rules(pool: &PgPool) -> sqlx::Result<Vec<(CacheRuleRow, String)>> {
    #[derive(sqlx::FromRow)]
    struct Row {
        id: Uuid,
        domain_id: Uuid,
        path_pattern: String,
        match_type: String,
        ttl_seconds: i64,
        priority: i32,
        action: String,
        swr_seconds: i64,
        enabled: bool,
        match_methods: String,
        match_query: String,
        browser_ttl_seconds: i64,
        ignore_query: Option<bool>,
        ignore_cookie: bool,
        match_content_type: String,
        note: String,
        domain_name: String,
    }
    let rows = sqlx::query_as::<_, Row>(
        r#"
        SELECT r.id, r.domain_id, r.path_pattern, r.match_type, r.ttl_seconds, r.priority,
               r.action, r.swr_seconds, r.enabled, r.match_methods, r.match_query,
               r.browser_ttl_seconds, r.ignore_query, r.ignore_cookie, r.match_content_type, r.note, d.name AS domain_name
        FROM cache_rules r
        JOIN domains d ON d.id = r.domain_id
        ORDER BY r.priority DESC, r.path_pattern
        "#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            (
                CacheRuleRow {
                    id: r.id,
                    domain_id: r.domain_id,
                    path_pattern: r.path_pattern,
                    match_type: r.match_type,
                    ttl_seconds: r.ttl_seconds,
                    priority: r.priority,
                    action: r.action,
                    swr_seconds: r.swr_seconds,
                    enabled: r.enabled,
                    match_methods: r.match_methods,
                    match_query: r.match_query,
                    browser_ttl_seconds: r.browser_ttl_seconds,
                    ignore_query: r.ignore_query,
                    ignore_cookie: r.ignore_cookie,
                    match_content_type: r.match_content_type,
                    note: r.note,
                },
                r.domain_name,
            )
        })
        .collect())
}

pub async fn create_rule(
    pool: &PgPool,
    domain_id: Uuid,
    input: &RuleInput<'_>,
) -> sqlx::Result<CacheRuleRow> {
    sqlx::query_as::<_, CacheRuleRow>(
        r#"
        INSERT INTO cache_rules
            (domain_id, path_pattern, match_type, ttl_seconds, priority, action, swr_seconds,
             enabled, match_methods, match_query, browser_ttl_seconds, ignore_query, ignore_cookie, match_content_type, note)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        RETURNING id, domain_id, path_pattern, match_type, ttl_seconds, priority, action, swr_seconds,
                  enabled, match_methods, match_query, browser_ttl_seconds, ignore_query, ignore_cookie, match_content_type, note
        "#,
    )
    .bind(domain_id)
    .bind(input.path_pattern)
    .bind(input.match_type)
    .bind(input.ttl_seconds)
    .bind(input.priority)
    .bind(input.action)
    .bind(input.swr_seconds)
    .bind(input.enabled)
    .bind(input.match_methods)
    .bind(input.match_query)
    .bind(input.browser_ttl_seconds)
    .bind(input.ignore_query)
    .bind(input.ignore_cookie)
    .bind(input.match_content_type)
    .bind(input.note)
    .fetch_one(pool)
    .await
}

pub async fn update_rule(
    pool: &PgPool,
    id: Uuid,
    input: &RuleInput<'_>,
) -> sqlx::Result<Option<CacheRuleRow>> {
    sqlx::query_as::<_, CacheRuleRow>(
        r#"
        UPDATE cache_rules SET
            path_pattern = $2, match_type = $3, ttl_seconds = $4, priority = $5, action = $6,
            swr_seconds = $7, enabled = $8, match_methods = $9, match_query = $10,
            browser_ttl_seconds = $11, ignore_query = $12, ignore_cookie = $13,
            match_content_type = $14, note = $15
        WHERE id = $1
        RETURNING id, domain_id, path_pattern, match_type, ttl_seconds, priority, action, swr_seconds,
                  enabled, match_methods, match_query, browser_ttl_seconds, ignore_query, ignore_cookie, match_content_type, note
        "#,
    )
    .bind(id)
    .bind(input.path_pattern)
    .bind(input.match_type)
    .bind(input.ttl_seconds)
    .bind(input.priority)
    .bind(input.action)
    .bind(input.swr_seconds)
    .bind(input.enabled)
    .bind(input.match_methods)
    .bind(input.match_query)
    .bind(input.browser_ttl_seconds)
    .bind(input.ignore_query)
    .bind(input.ignore_cookie)
    .bind(input.match_content_type)
    .bind(input.note)
    .fetch_optional(pool)
    .await
}

pub async fn get_rule(pool: &PgPool, id: Uuid) -> sqlx::Result<Option<CacheRuleRow>> {
    sqlx::query_as::<_, CacheRuleRow>(
        r#"
        SELECT id, domain_id, path_pattern, match_type, ttl_seconds, priority, action, swr_seconds,
               enabled, match_methods, match_query, browser_ttl_seconds, ignore_query, ignore_cookie, match_content_type, note
        FROM cache_rules WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn delete_rule(pool: &PgPool, id: Uuid) -> sqlx::Result<u64> {
    let r = sqlx::query("DELETE FROM cache_rules WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

pub async fn mark_stale_nodes_offline(pool: &PgPool, timeout_secs: i64) -> sqlx::Result<u64> {
    let r = sqlx::query(
        r#"
        UPDATE edge_nodes
        SET status = 'offline'
        WHERE status = 'online'
          AND (last_heartbeat IS NULL
               OR last_heartbeat < NOW() - make_interval(secs => $1))
        "#,
    )
    .bind(timeout_secs)
    .execute(pool)
    .await?;
    Ok(r.rows_affected())
}

pub async fn count_domains(pool: &PgPool) -> sqlx::Result<i64> {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM domains")
        .fetch_one(pool)
        .await?;
    Ok(n)
}

pub async fn count_online_nodes(pool: &PgPool) -> sqlx::Result<i64> {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM edge_nodes WHERE status = 'online'")
        .fetch_one(pool)
        .await?;
    Ok(n)
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CertRow {
    pub id: Uuid,
    pub domain_id: Option<Uuid>,
    pub domain_name: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub issuer: String,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub status: String,
    pub auto_renew: bool,
    pub created_at: DateTime<Utc>,
}

pub async fn insert_metrics(
    pool: &PgPool,
    node_name: &str,
    domain: &str,
    requests: i64,
    cache_hits: i64,
    cache_misses: i64,
    bytes_sent: i64,
) -> sqlx::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO edge_metrics (node_name, domain, requests, cache_hits, cache_misses, bytes_sent)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(node_name)
    .bind(domain)
    .bind(requests)
    .bind(cache_hits)
    .bind(cache_misses)
    .bind(bytes_sent)
    .execute(pool)
    .await?;
    Ok(())
}

/// Insert a batch of per-domain metric samples in one transaction.
pub async fn insert_metrics_batch(
    pool: &PgPool,
    rows: &[(String, String, i64, i64, i64, i64)],
) -> sqlx::Result<()> {
    let mut tx = pool.begin().await?;
    for (node, domain, requests, hits, misses, bytes) in rows {
        sqlx::query(
            r#"
            INSERT INTO edge_metrics (node_name, domain, requests, cache_hits, cache_misses, bytes_sent)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(node)
        .bind(domain)
        .bind(requests)
        .bind(hits)
        .bind(misses)
        .bind(bytes)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn sum_metrics(pool: &PgPool) -> sqlx::Result<(i64, i64, i64, i64)> {
    #[derive(sqlx::FromRow)]
    struct S {
        requests: Option<i64>,
        hits: Option<i64>,
        misses: Option<i64>,
        bytes: Option<i64>,
    }
    let s = sqlx::query_as::<_, S>(
        r#"
        SELECT
            COALESCE(SUM(requests), 0)::bigint AS requests,
            COALESCE(SUM(cache_hits), 0)::bigint AS hits,
            COALESCE(SUM(cache_misses), 0)::bigint AS misses,
            COALESCE(SUM(bytes_sent), 0)::bigint AS bytes
        FROM edge_metrics
        WHERE reported_at > NOW() - INTERVAL '24 hours'
        "#,
    )
    .fetch_one(pool)
    .await?;
    Ok((
        s.requests.unwrap_or(0),
        s.hits.unwrap_or(0),
        s.misses.unwrap_or(0),
        s.bytes.unwrap_or(0),
    ))
}

pub async fn sum_metrics_for(
    pool: &PgPool,
    hosts: &[String],
) -> sqlx::Result<(i64, i64, i64, i64)> {
    #[derive(sqlx::FromRow)]
    struct S {
        requests: Option<i64>,
        hits: Option<i64>,
        misses: Option<i64>,
        bytes: Option<i64>,
    }
    let s = sqlx::query_as::<_, S>(
        r#"
        SELECT
            COALESCE(SUM(requests), 0)::bigint AS requests,
            COALESCE(SUM(cache_hits), 0)::bigint AS hits,
            COALESCE(SUM(cache_misses), 0)::bigint AS misses,
            COALESCE(SUM(bytes_sent), 0)::bigint AS bytes
        FROM edge_metrics
        WHERE reported_at > NOW() - INTERVAL '24 hours'
          AND domain = ANY($1)
        "#,
    )
    .bind(hosts)
    .fetch_one(pool)
    .await?;
    Ok((
        s.requests.unwrap_or(0),
        s.hits.unwrap_or(0),
        s.misses.unwrap_or(0),
        s.bytes.unwrap_or(0),
    ))
}

pub async fn metrics_by_domain_for(
    pool: &PgPool,
    hosts: &[String],
) -> sqlx::Result<Vec<(String, i64, i64, i64, i64)>> {
    sqlx::query_as(
        r#"
        SELECT COALESCE(NULLIF(domain, ''), '(unknown)') AS domain,
               COALESCE(SUM(requests), 0)::bigint,
               COALESCE(SUM(cache_hits), 0)::bigint,
               COALESCE(SUM(cache_misses), 0)::bigint,
               COALESCE(SUM(bytes_sent), 0)::bigint
        FROM edge_metrics
        WHERE reported_at > NOW() - INTERVAL '24 hours'
          AND domain = ANY($1)
        GROUP BY 1
        ORDER BY 2 DESC
        "#,
    )
    .bind(hosts)
    .fetch_all(pool)
    .await
}

pub async fn list_certs(pool: &PgPool) -> sqlx::Result<Vec<CertRow>> {
    sqlx::query_as::<_, CertRow>(
        r#"
        SELECT id, domain_id, domain_name, cert_pem, key_pem, issuer,
               not_before, not_after, status, auto_renew, created_at
        FROM certificates
        ORDER BY created_at DESC
        "#,
    )
    .fetch_all(pool)
    .await
}

pub async fn get_cert(pool: &PgPool, id: Uuid) -> sqlx::Result<Option<CertRow>> {
    sqlx::query_as::<_, CertRow>(
        r#"
        SELECT id, domain_id, domain_name, cert_pem, key_pem, issuer,
               not_before, not_after, status, auto_renew, created_at
        FROM certificates WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn update_cert_material(
    pool: &PgPool,
    id: Uuid,
    cert_pem: &str,
    key_pem: &str,
    issuer: &str,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
) -> sqlx::Result<()> {
    sqlx::query(
        r#"
        UPDATE certificates
        SET cert_pem = $2,
            key_pem = $3,
            issuer = $4,
            not_before = $5,
            not_after = $6,
            status = 'active',
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(cert_pem)
    .bind(key_pem)
    .bind(issuer)
    .bind(not_before)
    .bind(not_after)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_cert_by_domain(pool: &PgPool, domain_name: &str) -> sqlx::Result<Option<CertRow>> {
    sqlx::query_as::<_, CertRow>(
        r#"
        SELECT id, domain_id, domain_name, cert_pem, key_pem, issuer,
               not_before, not_after, status, auto_renew, created_at
        FROM certificates
        WHERE domain_name = $1 AND status = 'active'
        ORDER BY updated_at DESC
        LIMIT 1
        "#,
    )
    .bind(domain_name)
    .fetch_optional(pool)
    .await
}

pub async fn create_cert(
    pool: &PgPool,
    domain_id: Option<Uuid>,
    domain_name: &str,
    cert_pem: &str,
    key_pem: &str,
    issuer: &str,
    auto_renew: bool,
) -> sqlx::Result<CertRow> {
    // Simple expiry parse: if PEM looks present mark active for 90 days
    let status = if cert_pem.contains("BEGIN CERTIFICATE") && key_pem.contains("BEGIN") {
        "active"
    } else if cert_pem.is_empty() {
        "pending"
    } else {
        "error"
    };
    let not_after = if status == "active" {
        Some(Utc::now() + chrono::Duration::days(90))
    } else {
        None
    };
    let not_before = if status == "active" {
        Some(Utc::now())
    } else {
        None
    };

    sqlx::query_as::<_, CertRow>(
        r#"
        INSERT INTO certificates
            (domain_id, domain_name, cert_pem, key_pem, issuer, not_before, not_after, status, auto_renew)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id, domain_id, domain_name, cert_pem, key_pem, issuer,
                  not_before, not_after, status, auto_renew, created_at
        "#,
    )
    .bind(domain_id)
    .bind(domain_name)
    .bind(cert_pem)
    .bind(key_pem)
    .bind(issuer)
    .bind(not_before)
    .bind(not_after)
    .bind(status)
    .bind(auto_renew)
    .fetch_one(pool)
    .await
}

pub async fn delete_cert(pool: &PgPool, id: Uuid) -> sqlx::Result<u64> {
    let r = sqlx::query("DELETE FROM certificates WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

pub async fn put_acme_challenge(
    pool: &PgPool,
    token: &str,
    key_auth: &str,
    domain: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO acme_challenges (token, key_authorization, domain_name, expires_at)
        VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour')
        ON CONFLICT (token) DO UPDATE
          SET key_authorization = EXCLUDED.key_authorization,
              domain_name = EXCLUDED.domain_name,
              expires_at = EXCLUDED.expires_at
        "#,
    )
    .bind(token)
    .bind(key_auth)
    .bind(domain)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_acme_challenge(pool: &PgPool, token: &str) -> sqlx::Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as(
        r#"
        SELECT key_authorization FROM acme_challenges
        WHERE token = $1 AND expires_at > NOW()
        "#,
    )
    .bind(token)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.0))
}

pub async fn get_acme_account(
    pool: &PgPool,
    directory: &str,
) -> sqlx::Result<Option<(String, String)>> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT key_pem, kid FROM acme_accounts WHERE directory = $1")
            .bind(directory)
            .fetch_optional(pool)
            .await?;
    Ok(row)
}

pub async fn save_acme_account(
    pool: &PgPool,
    directory: &str,
    key_pem: &str,
    kid: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO acme_accounts (directory, key_pem, kid)
        VALUES ($1, $2, $3)
        ON CONFLICT (directory) DO UPDATE
          SET key_pem = EXCLUDED.key_pem,
              kid = EXCLUDED.kid,
              updated_at = NOW()
        "#,
    )
    .bind(directory)
    .bind(key_pem)
    .bind(kid)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuditRow {
    pub id: Uuid,
    pub actor: String,
    pub action: String,
    pub resource: String,
    pub detail: String,
    pub ip: String,
    pub created_at: DateTime<Utc>,
}

pub async fn insert_audit(
    pool: &PgPool,
    actor: &str,
    action: &str,
    resource: &str,
    detail: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO audit_logs (actor, action, resource, detail)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(actor)
    .bind(action)
    .bind(resource)
    .bind(detail)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_audit(pool: &PgPool, limit: i64) -> sqlx::Result<Vec<AuditRow>> {
    sqlx::query_as::<_, AuditRow>(
        r#"
        SELECT id, actor, action, resource, detail, ip, created_at
        FROM audit_logs
        ORDER BY created_at DESC
        LIMIT $1
        "#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await
}

pub async fn set_domain_status(
    pool: &PgPool,
    id: Uuid,
    status: &str,
) -> sqlx::Result<Option<DomainRow>> {
    sqlx::query_as::<_, DomainRow>(
        r#"
        UPDATE domains SET status = $2, updated_at = NOW()
        WHERE id = $1
        RETURNING id, project_id, name, origin_host, origin_port, origin_proto,
                  ssl_enabled, status, created_at, rate_limit_rps, rate_limit_burst
        "#,
    )
    .bind(id)
    .bind(status)
    .fetch_optional(pool)
    .await
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProjectRow {
    pub id: Uuid,
    pub name: String,
    pub owner_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub domain_count: Option<i64>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OriginHealthRow {
    pub domain_name: String,
    pub origin_url: String,
    pub healthy: bool,
    pub latency_ms: i32,
    pub last_check_at: Option<DateTime<Utc>>,
    pub last_error: String,
    pub consecutive_fails: i32,
}

pub async fn list_projects_for_user(pool: &PgPool, user_id: Uuid) -> sqlx::Result<Vec<ProjectRow>> {
    sqlx::query_as::<_, ProjectRow>(
        r#"
        SELECT p.id, p.name, p.owner_id, p.created_at,
               (SELECT COUNT(*) FROM domains d WHERE d.project_id = p.id) AS domain_count
        FROM projects p
        WHERE p.owner_id = $1
           OR EXISTS (
             SELECT 1 FROM project_members m
             WHERE m.project_id = p.id AND m.user_id = $1
           )
        ORDER BY p.created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

pub async fn list_all_projects(pool: &PgPool) -> sqlx::Result<Vec<ProjectRow>> {
    sqlx::query_as::<_, ProjectRow>(
        r#"
        SELECT p.id, p.name, p.owner_id, p.created_at,
               (SELECT COUNT(*) FROM domains d WHERE d.project_id = p.id) AS domain_count
        FROM projects p
        ORDER BY p.created_at DESC
        "#,
    )
    .fetch_all(pool)
    .await
}

pub async fn create_project(pool: &PgPool, name: &str, owner_id: Uuid) -> sqlx::Result<ProjectRow> {
    let row = sqlx::query_as::<_, ProjectRow>(
        r#"
        INSERT INTO projects (name, owner_id)
        VALUES ($1, $2)
        RETURNING id, name, owner_id, created_at, 0::bigint AS domain_count
        "#,
    )
    .bind(name)
    .bind(owner_id)
    .fetch_one(pool)
    .await?;
    sqlx::query(
        "INSERT INTO project_members (project_id, user_id, role) VALUES ($1, $2, 'owner') ON CONFLICT DO NOTHING",
    )
    .bind(row.id)
    .bind(owner_id)
    .execute(pool)
    .await?;
    Ok(row)
}

pub async fn get_project(pool: &PgPool, id: Uuid) -> sqlx::Result<Option<ProjectRow>> {
    sqlx::query_as::<_, ProjectRow>(
        r#"
        SELECT p.id, p.name, p.owner_id, p.created_at,
               (SELECT COUNT(*) FROM domains d WHERE d.project_id = p.id) AS domain_count
        FROM projects p WHERE p.id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn delete_project(pool: &PgPool, id: Uuid, owner_id: Uuid) -> sqlx::Result<u64> {
    let r = sqlx::query("DELETE FROM projects WHERE id = $1 AND owner_id = $2")
        .bind(id)
        .bind(owner_id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

pub async fn delete_project_any(pool: &PgPool, id: Uuid) -> sqlx::Result<u64> {
    let r = sqlx::query("DELETE FROM projects WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

pub async fn user_can_access_project(
    pool: &PgPool,
    project_id: Uuid,
    user_id: Uuid,
) -> sqlx::Result<bool> {
    let (n,): (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM projects p
        WHERE p.id = $1 AND (
          p.owner_id = $2 OR EXISTS (
            SELECT 1 FROM project_members m WHERE m.project_id = p.id AND m.user_id = $2
          )
        )
        "#,
    )
    .bind(project_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(n > 0)
}

pub async fn list_domains_by_project(
    pool: &PgPool,
    project_id: Uuid,
) -> sqlx::Result<Vec<DomainRow>> {
    sqlx::query_as::<_, DomainRow>(
        r#"
        SELECT id, project_id, name, origin_host, origin_port, origin_proto,
               ssl_enabled, status, created_at, rate_limit_rps, rate_limit_burst,
               COALESCE(origins, '[]'::jsonb) AS origins, COALESCE(backup_origin_host, '') AS backup_origin_host,
               COALESCE(backup_origin_port, 0) AS backup_origin_port,
               COALESCE(backup_origin_proto, 'http') AS backup_origin_proto
        FROM domains WHERE project_id = $1
        ORDER BY created_at DESC
        "#,
    )
    .bind(project_id)
    .fetch_all(pool)
    .await
}

pub async fn assign_domain_project(
    pool: &PgPool,
    domain_id: Uuid,
    project_id: Option<Uuid>,
) -> sqlx::Result<u64> {
    let r = sqlx::query("UPDATE domains SET project_id = $2, updated_at = NOW() WHERE id = $1")
        .bind(domain_id)
        .bind(project_id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

pub async fn upsert_origin_health(
    pool: &PgPool,
    domain_name: &str,
    origin_url: &str,
    healthy: bool,
    latency_ms: i32,
    last_error: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO origin_health (domain_name, origin_url, healthy, latency_ms, last_check_at, last_error, consecutive_fails)
        VALUES ($1, $2, $3, $4, NOW(), $5, CASE WHEN $3 THEN 0 ELSE 1 END)
        ON CONFLICT (domain_name, origin_url) DO UPDATE SET
          healthy = EXCLUDED.healthy,
          latency_ms = EXCLUDED.latency_ms,
          last_check_at = NOW(),
          last_error = EXCLUDED.last_error,
          consecutive_fails = CASE
            WHEN EXCLUDED.healthy THEN 0
            ELSE origin_health.consecutive_fails + 1
          END
        "#,
    )
    .bind(domain_name)
    .bind(origin_url)
    .bind(healthy)
    .bind(latency_ms)
    .bind(last_error)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_origin_health(pool: &PgPool) -> sqlx::Result<Vec<OriginHealthRow>> {
    sqlx::query_as::<_, OriginHealthRow>(
        r#"
        SELECT domain_name, origin_url, healthy, latency_ms, last_check_at, last_error, consecutive_fails
        FROM origin_health
        ORDER BY domain_name
        "#,
    )
    .fetch_all(pool)
    .await
}

pub async fn get_domain_rate_limit(pool: &PgPool, name: &str) -> sqlx::Result<Option<(i32, i32)>> {
    let row: Option<(i32, i32)> =
        sqlx::query_as("SELECT rate_limit_rps, rate_limit_burst FROM domains WHERE name = $1")
            .bind(name)
            .fetch_optional(pool)
            .await?;
    Ok(row)
}

pub async fn set_domain_rate_limit(
    pool: &PgPool,
    id: Uuid,
    rps: i32,
    burst: i32,
) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE domains SET rate_limit_rps = $2, rate_limit_burst = $3, updated_at = NOW() WHERE id = $1",
    )
    .bind(id)
    .bind(rps)
    .bind(burst)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn create_domain_with_project(
    pool: &PgPool,
    name: &str,
    origin_host: &str,
    origin_port: i32,
    origin_proto: &str,
    ssl: bool,
    project_id: Option<Uuid>,
) -> sqlx::Result<DomainRow> {
    sqlx::query_as::<_, DomainRow>(
        r#"
        INSERT INTO domains (name, origin_host, origin_port, origin_proto, ssl_enabled, status, project_id)
        VALUES ($1, $2, $3, $4, $5, 'active', $6)
        RETURNING id, project_id, name, origin_host, origin_port, origin_proto,
                  ssl_enabled, status, created_at, rate_limit_rps, rate_limit_burst
        "#,
    )
    .bind(name)
    .bind(origin_host)
    .bind(origin_port)
    .bind(origin_proto)
    .bind(ssl)
    .bind(project_id)
    .fetch_one(pool)
    .await
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DomainSettingsRow {
    pub ignore_query_string: bool,
    pub cors_origins: String,
    pub hotlink_allow_referers: String,
    pub origin_timeout_ms: i32,
    pub custom_headers: String,
    pub rate_limit_rps: i32,
    pub rate_limit_burst: i32,
    pub cc_enabled: bool,
    pub cc_rps: i32,
    pub cc_burst: i32,
    pub cc_ban_after: i32,
    pub cc_ban_seconds: i32,
    pub cc_mode: String,
    pub cc_allow_ips: String,
}

pub async fn get_domain_settings(
    pool: &PgPool,
    name: &str,
) -> sqlx::Result<Option<DomainSettingsRow>> {
    sqlx::query_as::<_, DomainSettingsRow>(
        r#"
        SELECT ignore_query_string, cors_origins, hotlink_allow_referers,
               origin_timeout_ms, custom_headers, rate_limit_rps, rate_limit_burst,
               cc_enabled, cc_rps, cc_burst, cc_ban_after, cc_ban_seconds, cc_mode, cc_allow_ips
        FROM domains WHERE name = $1
        "#,
    )
    .bind(name)
    .fetch_optional(pool)
    .await
}

type DomainSettingsPatchRow = (
    bool,
    String,
    String,
    i32,
    String,
    i32,
    i32,
    bool,
    i32,
    i32,
    i32,
    i32,
    String,
    String,
);

#[allow(clippy::too_many_arguments)]
pub async fn update_domain_settings(
    pool: &PgPool,
    id: Uuid,
    ignore_query: Option<bool>,
    cors: Option<&str>,
    hotlink: Option<&str>,
    timeout_ms: Option<i32>,
    headers: Option<&str>,
    rps: Option<i32>,
    burst: Option<i32>,
    cc_enabled: Option<bool>,
    cc_rps: Option<i32>,
    cc_burst: Option<i32>,
    cc_ban_after: Option<i32>,
    cc_ban_seconds: Option<i32>,
    cc_mode: Option<&str>,
    cc_allow_ips: Option<&str>,
) -> sqlx::Result<u64> {
    // load existing then patch
    let row: Option<DomainSettingsPatchRow> = sqlx::query_as(
        r#"
        SELECT ignore_query_string, cors_origins, hotlink_allow_referers,
               origin_timeout_ms, custom_headers, rate_limit_rps, rate_limit_burst,
               cc_enabled, cc_rps, cc_burst, cc_ban_after, cc_ban_seconds, cc_mode, cc_allow_ips
        FROM domains WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    let Some(e) = row else { return Ok(0) };
    let r = sqlx::query(
        r#"
        UPDATE domains SET
          ignore_query_string = $2,
          cors_origins = $3,
          hotlink_allow_referers = $4,
          origin_timeout_ms = $5,
          custom_headers = $6,
          rate_limit_rps = $7,
          rate_limit_burst = $8,
          cc_enabled = $9,
          cc_rps = $10,
          cc_burst = $11,
          cc_ban_after = $12,
          cc_ban_seconds = $13,
          cc_mode = $14,
          cc_allow_ips = $15,
          updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(ignore_query.unwrap_or(e.0))
    .bind(cors.unwrap_or(&e.1))
    .bind(hotlink.unwrap_or(&e.2))
    .bind(timeout_ms.unwrap_or(e.3))
    .bind(headers.unwrap_or(&e.4))
    .bind(rps.unwrap_or(e.5))
    .bind(burst.unwrap_or(e.6))
    .bind(cc_enabled.unwrap_or(e.7))
    .bind(cc_rps.unwrap_or(e.8))
    .bind(cc_burst.unwrap_or(e.9))
    .bind(cc_ban_after.unwrap_or(e.10))
    .bind(cc_ban_seconds.unwrap_or(e.11))
    .bind(cc_mode.unwrap_or(&e.12))
    .bind(cc_allow_ips.unwrap_or(&e.13))
    .execute(pool)
    .await?;
    Ok(r.rows_affected())
}

pub async fn create_prefetch(pool: &PgPool, domain: &str, url_path: &str) -> sqlx::Result<Uuid> {
    let (id,): (Uuid,) = sqlx::query_as(
        r#"
        INSERT INTO prefetch_tasks (domain, url_path, status)
        VALUES ($1, $2, 'pending')
        RETURNING id
        "#,
    )
    .bind(domain)
    .bind(url_path)
    .fetch_one(pool)
    .await?;
    Ok(id)
}

pub async fn list_prefetch(
    pool: &PgPool,
    limit: i64,
) -> sqlx::Result<Vec<(Uuid, String, String, String, String)>> {
    sqlx::query_as(
        r#"
        SELECT id, domain, url_path, status, message
        FROM prefetch_tasks
        ORDER BY created_at DESC
        LIMIT $1
        "#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await
}

pub async fn metrics_by_domain(pool: &PgPool) -> sqlx::Result<Vec<(String, i64, i64, i64, i64)>> {
    sqlx::query_as(
        r#"
        SELECT COALESCE(NULLIF(domain, ''), '(unknown)') AS domain,
               COALESCE(SUM(requests), 0)::bigint,
               COALESCE(SUM(cache_hits), 0)::bigint,
               COALESCE(SUM(cache_misses), 0)::bigint,
               COALESCE(SUM(bytes_sent), 0)::bigint
        FROM edge_metrics
        WHERE reported_at > NOW() - INTERVAL '24 hours'
        GROUP BY 1
        ORDER BY 2 DESC
        "#,
    )
    .fetch_all(pool)
    .await
}

pub async fn get_backup_origin(
    pool: &PgPool,
    name: &str,
) -> sqlx::Result<Option<(String, i32, String)>> {
    let row: Option<(String, i32, String)> = sqlx::query_as(
        r#"
        SELECT backup_origin_host, backup_origin_port, backup_origin_proto
        FROM domains WHERE name = $1
        "#,
    )
    .bind(name)
    .fetch_optional(pool)
    .await?;
    Ok(row.filter(|r| !r.0.is_empty() && r.1 > 0))
}

pub async fn set_backup_origin(
    pool: &PgPool,
    id: Uuid,
    host: &str,
    port: i32,
    proto: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        r#"
        UPDATE domains SET
          backup_origin_host = $2,
          backup_origin_port = $3,
          backup_origin_proto = $4,
          updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(host)
    .bind(port)
    .bind(proto)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn set_domain_origins(
    pool: &PgPool,
    id: Uuid,
    origins: &[DomainOrigin],
) -> sqlx::Result<()> {
    let value = serde_json::to_value(origins).unwrap_or_else(|_| serde_json::json!([]));
    sqlx::query(
        r#"
        UPDATE domains SET origins = $2, updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(value)
    .execute(pool)
    .await?;
    let urls: Vec<String> = origins
        .iter()
        .map(|o| format!("{}://{}:{}", o.proto, o.host, o.port))
        .collect();
    if !urls.is_empty() {
        let _ = sqlx::query(
            r#"
            DELETE FROM origin_health
            WHERE domain_name = (SELECT name FROM domains WHERE id = $1)
              AND origin_url <> ALL($2)
            "#,
        )
        .bind(id)
        .bind(&urls)
        .execute(pool)
        .await;
    }
    Ok(())
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AccessLogRow {
    pub id: i64,
    pub ts: DateTime<Utc>,
    pub node_id: String,
    pub client_ip: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub status: i32,
    pub bytes: i64,
    pub latency_ms: i32,
    pub cache_status: String,
    pub user_agent: String,
    pub referer: String,
}

#[allow(clippy::type_complexity)]
pub async fn insert_access_logs_batch(
    pool: &PgPool,
    entries: &[(
        String, // ts
        String, // node_id
        String, // client_ip
        String, // method
        String, // host
        String, // path
        i32,    // status
        i64,    // bytes
        i32,    // latency_ms
        String, // cache
        String, // ua
        String, // ref
    )],
) -> sqlx::Result<u64> {
    let mut n = 0u64;
    for e in entries {
        let r = sqlx::query(
            r#"
            INSERT INTO access_logs
              (ts, node_id, client_ip, method, host, path, status, bytes, latency_ms, cache_status, user_agent, referer)
            VALUES (
              COALESCE($1::timestamptz, NOW()),
              $2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12
            )
            "#,
        )
        .bind(&e.0)
        .bind(&e.1)
        .bind(&e.2)
        .bind(&e.3)
        .bind(&e.4)
        .bind(&e.5)
        .bind(e.6)
        .bind(e.7)
        .bind(e.8)
        .bind(&e.9)
        .bind(&e.10)
        .bind(&e.11)
        .execute(pool)
        .await?;
        n += r.rows_affected();
    }
    Ok(n)
}

pub async fn list_access_logs(
    pool: &PgPool,
    host: Option<&str>,
    limit: i64,
) -> sqlx::Result<Vec<AccessLogRow>> {
    if let Some(h) = host.filter(|s| !s.is_empty()) {
        sqlx::query_as::<_, AccessLogRow>(
            r#"
            SELECT id, ts, node_id, client_ip, method, host, path, status, bytes,
                   latency_ms, cache_status, user_agent, referer
            FROM access_logs
            WHERE host = $1
            ORDER BY ts DESC
            LIMIT $2
            "#,
        )
        .bind(h)
        .bind(limit)
        .fetch_all(pool)
        .await
    } else {
        sqlx::query_as::<_, AccessLogRow>(
            r#"
            SELECT id, ts, node_id, client_ip, method, host, path, status, bytes,
                   latency_ms, cache_status, user_agent, referer
            FROM access_logs
            ORDER BY ts DESC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(pool)
        .await
    }
}

// ---------------------------------------------------------------------------
// Roles & tenancy
// ---------------------------------------------------------------------------

/// Global role (`admin` | `user`) for a user; `None` when the user is gone.
pub async fn get_user_role(pool: &PgPool, user_id: Uuid) -> sqlx::Result<Option<String>> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT role FROM users WHERE id = $1 AND is_active")
            .bind(user_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|r| r.0))
}

/// Effective role of `user_id` inside `project_id`:
/// `owner` | `admin` | `member`, or `None` when the user has no access.
pub async fn project_role(
    pool: &PgPool,
    project_id: Uuid,
    user_id: Uuid,
) -> sqlx::Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as(
        r#"
        SELECT CASE WHEN p.owner_id = $2 THEN 'owner' ELSE COALESCE(m.role, '') END
        FROM projects p
        LEFT JOIN project_members m ON m.project_id = p.id AND m.user_id = $2
        WHERE p.id = $1
        "#,
    )
    .bind(project_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.0).filter(|role| !role.is_empty()))
}

/// Project a domain belongs to. `None` = domain missing, `Some(None)` = no project.
pub async fn domain_project(pool: &PgPool, domain_id: Uuid) -> sqlx::Result<Option<Option<Uuid>>> {
    let row: Option<(Option<Uuid>,)> =
        sqlx::query_as("SELECT project_id FROM domains WHERE id = $1")
            .bind(domain_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|r| r.0))
}

/// All domain ids readable by a non-admin user (via project ownership/membership).
pub async fn domains_for_user(pool: &PgPool, user_id: Uuid) -> sqlx::Result<Vec<Uuid>> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        r#"
        SELECT d.id
        FROM domains d
        JOIN projects p ON p.id = d.project_id
        LEFT JOIN project_members m ON m.project_id = p.id AND m.user_id = $1
        WHERE p.owner_id = $1 OR m.user_id IS NOT NULL
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

/// The per-user "Default" project, created on first use.
pub async fn ensure_personal_project(pool: &PgPool, user_id: Uuid) -> sqlx::Result<Uuid> {
    let existing: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM projects WHERE owner_id = $1 AND name = 'Default' LIMIT 1")
            .bind(user_id)
            .fetch_optional(pool)
            .await?;
    if let Some((id,)) = existing {
        return Ok(id);
    }
    let row = create_project(pool, "Default", user_id).await?;
    Ok(row.id)
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MemberRow {
    pub user_id: Uuid,
    pub email: String,
    pub name: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

pub async fn list_project_members(pool: &PgPool, project_id: Uuid) -> sqlx::Result<Vec<MemberRow>> {
    sqlx::query_as::<_, MemberRow>(
        r#"
        SELECT u.id AS user_id, u.email, u.name, m.role, m.created_at
        FROM project_members m
        JOIN users u ON u.id = m.user_id
        WHERE m.project_id = $1
        ORDER BY m.role, u.email
        "#,
    )
    .bind(project_id)
    .fetch_all(pool)
    .await
}

pub async fn upsert_project_member(
    pool: &PgPool,
    project_id: Uuid,
    user_id: Uuid,
    role: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO project_members (project_id, user_id, role)
        VALUES ($1, $2, $3)
        ON CONFLICT (project_id, user_id) DO UPDATE SET role = EXCLUDED.role
        "#,
    )
    .bind(project_id)
    .bind(user_id)
    .bind(role)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn remove_project_member(
    pool: &PgPool,
    project_id: Uuid,
    user_id: Uuid,
) -> sqlx::Result<u64> {
    let r = sqlx::query(
        "DELETE FROM project_members WHERE project_id = $1 AND user_id = $2 AND role <> 'owner'",
    )
    .bind(project_id)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(r.rows_affected())
}

// ---------------------------------------------------------------------------
// Bulk config delivery (one round-trip per table instead of per domain)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DomainFullRow {
    pub id: Uuid,
    pub name: String,
    pub origin_host: String,
    pub origin_port: i32,
    pub origin_proto: String,
    pub ssl_enabled: bool,
    pub status: String,
    pub rate_limit_rps: i32,
    pub rate_limit_burst: i32,
    pub ignore_query_string: bool,
    pub cors_origins: String,
    pub hotlink_allow_referers: String,
    pub origin_timeout_ms: i32,
    pub custom_headers: String,
    #[sqlx(default)]
    pub origins: sqlx::types::Json<Vec<DomainOrigin>>,
    pub backup_origin_host: String,
    pub backup_origin_port: i32,
    pub backup_origin_proto: String,
    pub cc_enabled: bool,
    pub cc_rps: i32,
    pub cc_burst: i32,
    pub cc_ban_after: i32,
    pub cc_ban_seconds: i32,
    pub cc_mode: String,
    pub cc_allow_ips: String,
}

pub async fn list_domains_full(pool: &PgPool) -> sqlx::Result<Vec<DomainFullRow>> {
    sqlx::query_as::<_, DomainFullRow>(
        r#"
        SELECT id, name, origin_host, origin_port, origin_proto, ssl_enabled, status,
               rate_limit_rps, rate_limit_burst, ignore_query_string, cors_origins,
               hotlink_allow_referers, origin_timeout_ms, custom_headers,
               COALESCE(origins, '[]'::jsonb) AS origins, backup_origin_host, backup_origin_port, backup_origin_proto,
               cc_enabled, cc_rps, cc_burst, cc_ban_after, cc_ban_seconds, cc_mode, cc_allow_ips
        FROM domains
        ORDER BY name
        "#,
    )
    .fetch_all(pool)
    .await
}

pub async fn get_domain_full_by_name(
    pool: &PgPool,
    name: &str,
) -> sqlx::Result<Option<DomainFullRow>> {
    sqlx::query_as::<_, DomainFullRow>(
        r#"
        SELECT id, name, origin_host, origin_port, origin_proto, ssl_enabled, status,
               rate_limit_rps, rate_limit_burst, ignore_query_string, cors_origins,
               hotlink_allow_referers, origin_timeout_ms, custom_headers,
               COALESCE(origins, '[]'::jsonb) AS origins, backup_origin_host, backup_origin_port, backup_origin_proto,
               cc_enabled, cc_rps, cc_burst, cc_ban_after, cc_ban_seconds, cc_mode, cc_allow_ips
        FROM domains WHERE name = $1
        "#,
    )
    .bind(name)
    .fetch_optional(pool)
    .await
}

pub async fn list_rules_flat(pool: &PgPool) -> sqlx::Result<Vec<CacheRuleRow>> {
    sqlx::query_as::<_, CacheRuleRow>(
        r#"
        SELECT id, domain_id, path_pattern, match_type, ttl_seconds, priority, action, swr_seconds,
               enabled, match_methods, match_query, browser_ttl_seconds, ignore_query, ignore_cookie, match_content_type, note
        FROM cache_rules
        ORDER BY domain_id, priority DESC, path_pattern
        "#,
    )
    .fetch_all(pool)
    .await
}

// ---------------------------------------------------------------------------
// WAF
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WafSettingsRow {
    pub domain_id: Uuid,
    pub enabled: bool,
    pub mode: String,
    pub sqli: bool,
    pub xss: bool,
    pub traversal: bool,
    pub scanners: bool,
    pub rce: bool,
    pub ssrf: bool,
    pub xxe: bool,
    pub log4shell: bool,
    pub crlf: bool,
    pub challenge_difficulty: i32,
    pub challenge_ttl_secs: i32,
    pub security_level: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WafRuleRow {
    pub id: Uuid,
    pub domain_id: Uuid,
    pub name: String,
    pub field: String,
    pub operator: String,
    pub value: String,
    pub action: String,
    pub priority: i32,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WafIpRow {
    pub id: Uuid,
    pub domain_id: Uuid,
    pub kind: String,
    pub ip: String,
    pub note: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WafEventRow {
    pub id: i64,
    pub ts: DateTime<Utc>,
    pub domain: String,
    pub node_id: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub action: String,
    pub category: String,
    pub rule_name: String,
    pub mode: String,
}

pub async fn get_waf_settings(
    pool: &PgPool,
    domain_id: Uuid,
) -> sqlx::Result<Option<WafSettingsRow>> {
    sqlx::query_as::<_, WafSettingsRow>(
        r#"
        SELECT domain_id, enabled, mode, sqli, xss, traversal, scanners,
               rce, ssrf, xxe, log4shell, crlf,
               challenge_difficulty, challenge_ttl_secs, security_level
        FROM waf_settings WHERE domain_id = $1
        "#,
    )
    .bind(domain_id)
    .fetch_optional(pool)
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn upsert_waf_settings(
    pool: &PgPool,
    domain_id: Uuid,
    enabled: bool,
    mode: &str,
    sqli: bool,
    xss: bool,
    traversal: bool,
    scanners: bool,
    rce: bool,
    ssrf: bool,
    xxe: bool,
    log4shell: bool,
    crlf: bool,
    challenge_difficulty: i32,
    challenge_ttl_secs: i32,
    security_level: &str,
) -> sqlx::Result<WafSettingsRow> {
    sqlx::query_as::<_, WafSettingsRow>(
        r#"
        INSERT INTO waf_settings
            (domain_id, enabled, mode, sqli, xss, traversal, scanners,
             rce, ssrf, xxe, log4shell, crlf,
             challenge_difficulty, challenge_ttl_secs, security_level)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        ON CONFLICT (domain_id) DO UPDATE SET
          enabled = EXCLUDED.enabled,
          mode = EXCLUDED.mode,
          sqli = EXCLUDED.sqli,
          xss = EXCLUDED.xss,
          traversal = EXCLUDED.traversal,
          scanners = EXCLUDED.scanners,
          rce = EXCLUDED.rce,
          ssrf = EXCLUDED.ssrf,
          xxe = EXCLUDED.xxe,
          log4shell = EXCLUDED.log4shell,
          crlf = EXCLUDED.crlf,
          challenge_difficulty = EXCLUDED.challenge_difficulty,
          challenge_ttl_secs = EXCLUDED.challenge_ttl_secs,
          security_level = EXCLUDED.security_level,
          updated_at = NOW()
        RETURNING domain_id, enabled, mode, sqli, xss, traversal, scanners,
                  rce, ssrf, xxe, log4shell, crlf,
                  challenge_difficulty, challenge_ttl_secs, security_level
        "#,
    )
    .bind(domain_id)
    .bind(enabled)
    .bind(mode)
    .bind(sqli)
    .bind(xss)
    .bind(traversal)
    .bind(scanners)
    .bind(rce)
    .bind(ssrf)
    .bind(xxe)
    .bind(log4shell)
    .bind(crlf)
    .bind(challenge_difficulty)
    .bind(challenge_ttl_secs)
    .bind(security_level)
    .fetch_one(pool)
    .await
}

pub async fn list_waf_settings_all(pool: &PgPool) -> sqlx::Result<Vec<WafSettingsRow>> {
    sqlx::query_as::<_, WafSettingsRow>(
        r#"
        SELECT domain_id, enabled, mode, sqli, xss, traversal, scanners,
               rce, ssrf, xxe, log4shell, crlf,
               challenge_difficulty, challenge_ttl_secs, security_level
        FROM waf_settings
        "#,
    )
    .fetch_all(pool)
    .await
}

pub async fn list_waf_rules(pool: &PgPool, domain_id: Uuid) -> sqlx::Result<Vec<WafRuleRow>> {
    sqlx::query_as::<_, WafRuleRow>(
        r#"
        SELECT id, domain_id, name, field, operator, value, action, priority, enabled, created_at
        FROM waf_rules WHERE domain_id = $1
        ORDER BY priority DESC, created_at
        "#,
    )
    .bind(domain_id)
    .fetch_all(pool)
    .await
}

pub async fn list_waf_rules_all(pool: &PgPool) -> sqlx::Result<Vec<WafRuleRow>> {
    sqlx::query_as::<_, WafRuleRow>(
        r#"
        SELECT id, domain_id, name, field, operator, value, action, priority, enabled, created_at
        FROM waf_rules ORDER BY domain_id, priority DESC, created_at
        "#,
    )
    .fetch_all(pool)
    .await
}

pub async fn get_waf_rule(pool: &PgPool, id: Uuid) -> sqlx::Result<Option<WafRuleRow>> {
    sqlx::query_as::<_, WafRuleRow>(
        r#"
        SELECT id, domain_id, name, field, operator, value, action, priority, enabled, created_at
        FROM waf_rules WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn create_waf_rule(
    pool: &PgPool,
    domain_id: Uuid,
    name: &str,
    field: &str,
    operator: &str,
    value: &str,
    action: &str,
    priority: i32,
    enabled: bool,
) -> sqlx::Result<WafRuleRow> {
    sqlx::query_as::<_, WafRuleRow>(
        r#"
        INSERT INTO waf_rules (domain_id, name, field, operator, value, action, priority, enabled)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id, domain_id, name, field, operator, value, action, priority, enabled, created_at
        "#,
    )
    .bind(domain_id)
    .bind(name)
    .bind(field)
    .bind(operator)
    .bind(value)
    .bind(action)
    .bind(priority)
    .bind(enabled)
    .fetch_one(pool)
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn update_waf_rule(
    pool: &PgPool,
    id: Uuid,
    name: &str,
    field: &str,
    operator: &str,
    value: &str,
    action: &str,
    priority: i32,
    enabled: bool,
) -> sqlx::Result<Option<WafRuleRow>> {
    sqlx::query_as::<_, WafRuleRow>(
        r#"
        UPDATE waf_rules SET
          name = $2, field = $3, operator = $4, value = $5,
          action = $6, priority = $7, enabled = $8
        WHERE id = $1
        RETURNING id, domain_id, name, field, operator, value, action, priority, enabled, created_at
        "#,
    )
    .bind(id)
    .bind(name)
    .bind(field)
    .bind(operator)
    .bind(value)
    .bind(action)
    .bind(priority)
    .bind(enabled)
    .fetch_optional(pool)
    .await
}

pub async fn delete_waf_rule(pool: &PgPool, id: Uuid) -> sqlx::Result<u64> {
    let r = sqlx::query("DELETE FROM waf_rules WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

pub async fn list_waf_ips(pool: &PgPool, domain_id: Uuid) -> sqlx::Result<Vec<WafIpRow>> {
    sqlx::query_as::<_, WafIpRow>(
        r#"
        SELECT id, domain_id, kind, ip, note, created_at
        FROM waf_ip_rules WHERE domain_id = $1
        ORDER BY kind, created_at
        "#,
    )
    .bind(domain_id)
    .fetch_all(pool)
    .await
}

pub async fn list_waf_ips_all(pool: &PgPool) -> sqlx::Result<Vec<WafIpRow>> {
    sqlx::query_as::<_, WafIpRow>(
        "SELECT id, domain_id, kind, ip, note, created_at FROM waf_ip_rules ORDER BY domain_id, kind",
    )
    .fetch_all(pool)
    .await
}

pub async fn get_waf_ip(pool: &PgPool, id: Uuid) -> sqlx::Result<Option<WafIpRow>> {
    sqlx::query_as::<_, WafIpRow>(
        "SELECT id, domain_id, kind, ip, note, created_at FROM waf_ip_rules WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn create_waf_ip(
    pool: &PgPool,
    domain_id: Uuid,
    kind: &str,
    ip: &str,
    note: &str,
) -> sqlx::Result<WafIpRow> {
    sqlx::query_as::<_, WafIpRow>(
        r#"
        INSERT INTO waf_ip_rules (domain_id, kind, ip, note)
        VALUES ($1, $2, $3, $4)
        RETURNING id, domain_id, kind, ip, note, created_at
        "#,
    )
    .bind(domain_id)
    .bind(kind)
    .bind(ip)
    .bind(note)
    .fetch_one(pool)
    .await
}

pub async fn delete_waf_ip(pool: &PgPool, id: Uuid) -> sqlx::Result<u64> {
    let r = sqlx::query("DELETE FROM waf_ip_rules WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

#[derive(Debug, Clone)]
pub struct WafEventInput {
    pub domain: String,
    pub node_id: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub action: String,
    pub category: String,
    pub rule_name: String,
    pub mode: String,
}

pub async fn insert_waf_events_batch(pool: &PgPool, events: &[WafEventInput]) -> sqlx::Result<u64> {
    let mut n = 0u64;
    for e in events {
        let r = sqlx::query(
            r#"
            INSERT INTO waf_events
              (domain, node_id, client_ip, method, path, action, category, rule_name, mode)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(&e.domain)
        .bind(&e.node_id)
        .bind(&e.client_ip)
        .bind(&e.method)
        .bind(&e.path)
        .bind(&e.action)
        .bind(&e.category)
        .bind(&e.rule_name)
        .bind(&e.mode)
        .execute(pool)
        .await?;
        n += r.rows_affected();
    }
    Ok(n)
}

pub async fn list_waf_events(
    pool: &PgPool,
    domain: Option<&str>,
    limit: i64,
) -> sqlx::Result<Vec<WafEventRow>> {
    if let Some(domain) = domain.filter(|d| !d.is_empty()) {
        sqlx::query_as::<_, WafEventRow>(
            r#"
            SELECT id, ts, domain, node_id, client_ip, method, path, action, category, rule_name, mode
            FROM waf_events WHERE domain = $1
            ORDER BY ts DESC LIMIT $2
            "#,
        )
        .bind(domain)
        .bind(limit)
        .fetch_all(pool)
        .await
    } else {
        sqlx::query_as::<_, WafEventRow>(
            r#"
            SELECT id, ts, domain, node_id, client_ip, method, path, action, category, rule_name, mode
            FROM waf_events
            ORDER BY ts DESC LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(pool)
        .await
    }
}

/// Aggregated WAF events for the dashboard.
///
/// `expr` is validated against a fixed whitelist before being interpolated.
pub async fn waf_stats_group(
    pool: &PgPool,
    days: i32,
    domain: Option<&str>,
    domains: Option<Vec<String>>,
    expr: &str,
    limit: i64,
) -> sqlx::Result<Vec<(String, i64)>> {
    const DAY_EXPR: &str = "to_char(date_trunc('day', ts), 'YYYY-MM-DD')";
    let (expr, order) = match expr {
        "action" | "category" | "client_ip" | "rule_name" | "path" => (expr, "ORDER BY 2 DESC"),
        "day" => (DAY_EXPR, "ORDER BY 1 ASC"),
        _ => return Ok(Vec::new()),
    };
    let sql = format!(
        r#"
        SELECT COALESCE(NULLIF({expr}, ''), '(unknown)') AS k, COUNT(*)::bigint AS c
        FROM waf_events
        WHERE ts >= NOW() - make_interval(days => $1)
          AND ($2::text IS NULL OR domain = $2)
          AND ($3::text[] IS NULL OR domain = ANY($3))
        GROUP BY 1 {order} LIMIT $4
        "#
    );
    sqlx::query_as::<_, (String, i64)>(&sql)
        .bind(days)
        .bind(domain)
        .bind(domains)
        .bind(limit)
        .fetch_all(pool)
        .await
}

// ---------------------------------------------------------------------------
// Cross-node CC bans
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CcBanRow {
    pub domain: String,
    pub ip: String,
    pub reason: String,
    pub source: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

pub async fn upsert_cc_ban(
    pool: &PgPool,
    domain: &str,
    ip: &str,
    seconds: i64,
    reason: &str,
    source: &str,
) -> sqlx::Result<CcBanRow> {
    sqlx::query_as::<_, CcBanRow>(
        r#"
        INSERT INTO cc_bans (domain, ip, reason, source, expires_at)
        VALUES ($1, $2, $3, $4, NOW() + ($5 * INTERVAL '1 second'))
        ON CONFLICT (domain, ip) DO UPDATE SET
            expires_at = GREATEST(cc_bans.expires_at, EXCLUDED.expires_at),
            reason = EXCLUDED.reason,
            source = EXCLUDED.source,
            updated_at = NOW()
        RETURNING domain, ip, reason, source, created_at, expires_at
        "#,
    )
    .bind(domain)
    .bind(ip)
    .bind(reason)
    .bind(source)
    .bind(seconds)
    .fetch_one(pool)
    .await
}

pub async fn list_active_cc_bans(
    pool: &PgPool,
    domain: Option<&str>,
) -> sqlx::Result<Vec<CcBanRow>> {
    let _ = sqlx::query("DELETE FROM cc_bans WHERE expires_at <= NOW()")
        .execute(pool)
        .await;
    sqlx::query_as::<_, CcBanRow>(
        r#"
        SELECT domain, ip, reason, source, created_at, expires_at
        FROM cc_bans
        WHERE expires_at > NOW()
          AND ($1::text IS NULL OR domain = $1)
        ORDER BY expires_at DESC
        "#,
    )
    .bind(domain)
    .fetch_all(pool)
    .await
}

pub async fn delete_cc_ban(pool: &PgPool, domain: &str, ip: &str) -> sqlx::Result<u64> {
    let r = sqlx::query("DELETE FROM cc_bans WHERE domain = $1 AND ip = $2")
        .bind(domain)
        .bind(ip)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

/// Delete access_logs and edge_metrics older than `days` days.
pub async fn purge_old_telemetry(pool: &PgPool, days: i64) -> sqlx::Result<(u64, u64)> {
    let days = days.max(1);
    let a = sqlx::query(
        r#"DELETE FROM access_logs WHERE created_at < NOW() - ($1::text || ' days')::interval"#,
    )
    .bind(days.to_string())
    .execute(pool)
    .await?
    .rows_affected();
    let m = sqlx::query(
        r#"DELETE FROM edge_metrics WHERE reported_at < NOW() - ($1::text || ' days')::interval"#,
    )
    .bind(days.to_string())
    .execute(pool)
    .await?
    .rows_affected();
    let _ = sqlx::query(
        r#"DELETE FROM waf_events WHERE created_at < NOW() - ($1::text || ' days')::interval"#,
    )
    .bind(days.to_string())
    .execute(pool)
    .await;
    Ok((a, m))
}
