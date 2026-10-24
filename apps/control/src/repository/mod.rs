//! Database access layer

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRow {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
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
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CacheRuleRow {
    pub id: Uuid,
    pub domain_id: Uuid,
    pub path_pattern: String,
    pub ttl_seconds: i64,
    pub priority: i32,
}

pub async fn find_user_by_email(pool: &PgPool, email: &str) -> sqlx::Result<Option<UserRow>> {
    sqlx::query_as::<_, UserRow>(
        "SELECT id, email, password_hash, name, created_at FROM users WHERE email = $1",
    )
    .bind(email)
    .fetch_optional(pool)
    .await
}

pub async fn find_user_by_id(pool: &PgPool, id: Uuid) -> sqlx::Result<Option<UserRow>> {
    sqlx::query_as::<_, UserRow>(
        "SELECT id, email, password_hash, name, created_at FROM users WHERE id = $1",
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
        RETURNING id, email, password_hash, name, created_at
        "#,
    )
    .bind(email)
    .bind(password_hash)
    .bind(name)
    .fetch_one(pool)
    .await
}

pub async fn list_domains(pool: &PgPool) -> sqlx::Result<Vec<DomainRow>> {
    sqlx::query_as::<_, DomainRow>(
        r#"
        SELECT id, project_id, name, origin_host, origin_port, origin_proto,
               ssl_enabled, status, created_at
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
               ssl_enabled, status, created_at
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
               ssl_enabled, status, created_at
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
                  ssl_enabled, status, created_at
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
    let r = sqlx::query("DELETE FROM domains WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

pub async fn list_nodes(pool: &PgPool) -> sqlx::Result<Vec<NodeRow>> {
    sqlx::query_as::<_, NodeRow>(
        r#"
        SELECT id, name, region, ip, status, last_heartbeat, COALESCE(agent_url, '') as agent_url
        FROM edge_nodes
        ORDER BY name
        "#,
    )
    .fetch_all(pool)
    .await
}

pub async fn list_online_nodes_with_agent(pool: &PgPool) -> sqlx::Result<Vec<NodeRow>> {
    sqlx::query_as::<_, NodeRow>(
        r#"
        SELECT id, name, region, ip, status, last_heartbeat, COALESCE(agent_url, '') as agent_url
        FROM edge_nodes
        WHERE status = 'online' AND COALESCE(agent_url, '') <> ''
        ORDER BY name
        "#,
    )
    .fetch_all(pool)
    .await
}

pub async fn upsert_node_heartbeat(
    pool: &PgPool,
    node_key: &str,
    region: &str,
    ip: &str,
    agent_url: &str,
) -> sqlx::Result<NodeRow> {
    let existing = sqlx::query_as::<_, NodeRow>(
        r#"
        SELECT id, name, region, ip, status, last_heartbeat, COALESCE(agent_url, '') as agent_url
        FROM edge_nodes WHERE name = $1
        "#,
    )
    .bind(node_key)
    .fetch_optional(pool)
    .await?;

    if let Some(node) = existing {
        sqlx::query_as::<_, NodeRow>(
            r#"
            UPDATE edge_nodes
            SET region = $2, ip = $3, agent_url = $4, status = 'online', last_heartbeat = NOW()
            WHERE id = $1
            RETURNING id, name, region, ip, status, last_heartbeat, COALESCE(agent_url, '') as agent_url
            "#,
        )
        .bind(node.id)
        .bind(region)
        .bind(ip)
        .bind(agent_url)
        .fetch_one(pool)
        .await
    } else {
        sqlx::query_as::<_, NodeRow>(
            r#"
            INSERT INTO edge_nodes (name, region, ip, agent_url, status, last_heartbeat)
            VALUES ($1, $2, $3, $4, 'online', NOW())
            RETURNING id, name, region, ip, status, last_heartbeat, COALESCE(agent_url, '') as agent_url
            "#,
        )
        .bind(node_key)
        .bind(region)
        .bind(ip)
        .bind(agent_url)
        .fetch_one(pool)
        .await
    }
}

pub async fn list_rules_for_domain(pool: &PgPool, domain_id: Uuid) -> sqlx::Result<Vec<CacheRuleRow>> {
    sqlx::query_as::<_, CacheRuleRow>(
        r#"
        SELECT id, domain_id, path_pattern, ttl_seconds, priority
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
                  ssl_enabled, status, created_at
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
        ttl_seconds: i64,
        priority: i32,
        domain_name: String,
    }
    let rows = sqlx::query_as::<_, Row>(
        r#"
        SELECT r.id, r.domain_id, r.path_pattern, r.ttl_seconds, r.priority, d.name AS domain_name
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
                    ttl_seconds: r.ttl_seconds,
                    priority: r.priority,
                },
                r.domain_name,
            )
        })
        .collect())
}

pub async fn create_rule(
    pool: &PgPool,
    domain_id: Uuid,
    path_pattern: &str,
    ttl_seconds: i64,
    priority: i32,
) -> sqlx::Result<CacheRuleRow> {
    sqlx::query_as::<_, CacheRuleRow>(
        r#"
        INSERT INTO cache_rules (domain_id, path_pattern, ttl_seconds, priority)
        VALUES ($1, $2, $3, $4)
        RETURNING id, domain_id, path_pattern, ttl_seconds, priority
        "#,
    )
    .bind(domain_id)
    .bind(path_pattern)
    .bind(ttl_seconds)
    .bind(priority)
    .fetch_one(pool)
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
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edge_nodes WHERE status = 'online'",
    )
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

pub async fn list_active_certs_full(pool: &PgPool) -> sqlx::Result<Vec<CertRow>> {
    sqlx::query_as::<_, CertRow>(
        r#"
        SELECT id, domain_id, domain_name, cert_pem, key_pem, issuer,
               not_before, not_after, status, auto_renew, created_at
        FROM certificates
        WHERE status = 'active' AND cert_pem <> '' AND key_pem <> ''
        ORDER BY updated_at DESC
        "#,
    )
    .fetch_all(pool)
    .await
}
