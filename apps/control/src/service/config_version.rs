//! Snapshot history helpers shared by mutation handlers and the release API.

use crate::api::config::{snapshot_domain, DomainConfigResponse};
use crate::repository;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

/// Give pre-existing domains a baseline snapshot after upgrading.
pub async fn backfill_missing(pool: &PgPool) {
    let domains = match crate::repository::list_domains(pool).await {
        Ok(domains) => domains,
        Err(_) => return,
    };
    for domain in domains {
        match crate::repository::latest_version(pool, domain.id).await {
            Ok(None) => {
                let _ = record_domain(
                    pool,
                    domain.id,
                    &domain.name,
                    "system",
                    "initial.baseline",
                    "升级后初始化版本",
                )
                .await;
            }
            _ => {}
        }
    }
}

/// Persist a version after a config mutation. Identical snapshots are skipped
/// so enabling/disabling a no-op rule does not create noise.
pub async fn record_domain(
    pool: &PgPool,
    domain_id: Uuid,
    domain_name: &str,
    actor: &str,
    action: &str,
    message: &str,
) -> sqlx::Result<()> {
    let Some(snapshot) = snapshot_domain(pool, domain_name).await? else {
        return Ok(());
    };
    let value = serde_json::to_value(&snapshot).unwrap_or(Value::Null);
    let latest = repository::latest_version(pool, domain_id).await?;
    if let Some(ref latest) = latest {
        if latest.snapshot == value {
            return Ok(());
        }
    }
    let previous = latest
        .as_ref()
        .map(|v| v.snapshot.clone())
        .unwrap_or(Value::Null);
    let diff = diff_values(&previous, &value);
    repository::insert_version(
        pool,
        domain_id,
        domain_name,
        &value,
        &diff,
        action,
        actor,
        message,
    )
    .await?;
    Ok(())
}

pub async fn record_domain_by_name(
    pool: &PgPool,
    domain_name: &str,
    actor: &str,
    action: &str,
    message: &str,
) {
    let Ok(Some(row)) = repository::get_domain_by_name(pool, domain_name).await else {
        return;
    };
    if let Err(e) = record_domain(pool, row.id, &row.name, actor, action, message).await {
        tracing::warn!(domain = %domain_name, error = %e, "record config version");
    }
}

/// Currently effective snapshot for a domain: pinned version if one exists,
/// otherwise the live database state.
pub async fn effective_snapshot(
    pool: &PgPool,
    domain_name: &str,
) -> sqlx::Result<Option<DomainConfigResponse>> {
    if let Some(row) = repository::get_domain_by_name(pool, domain_name).await? {
        if let Some(version_id) = row.published_version_id {
            if let Some(version) = repository::get_version(pool, version_id).await? {
                if let Ok(snapshot) =
                    serde_json::from_value::<DomainConfigResponse>(version.snapshot)
                {
                    return Ok(Some(snapshot));
                }
            }
        }
    }
    snapshot_domain(pool, domain_name).await
}

pub async fn rollback_domain(
    pool: &PgPool,
    domain_name: &str,
    version_id: Uuid,
) -> sqlx::Result<bool> {
    let Some(version) = repository::get_version(pool, version_id).await? else {
        return Ok(false);
    };
    if version.domain_name != domain_name {
        return Ok(false);
    }
    let updated = repository::set_published_version(pool, domain_name, Some(version_id)).await?;
    Ok(updated > 0)
}

pub fn diff_values(before: &Value, after: &Value) -> Value {
    let mut out = Vec::new();
    diff_into("", before, after, &mut out);
    Value::Array(out)
}

fn diff_into(path: &str, before: &Value, after: &Value, out: &mut Vec<Value>) {
    if before == after {
        return;
    }
    match (before, after) {
        (Value::Object(a), Value::Object(b)) => {
            let mut keys: Vec<&String> = a.keys().chain(b.keys()).collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                let next = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                let av = a.get(key).unwrap_or(&Value::Null);
                let bv = b.get(key).unwrap_or(&Value::Null);
                if av.is_object() && bv.is_object() {
                    diff_into(&next, av, bv, out);
                } else if av != bv {
                    out.push(json!({"path": next, "before": av, "after": bv}));
                }
            }
        }
        _ => out.push(json!({
            "path": if path.is_empty() { "$" } else { path },
            "before": before,
            "after": after,
        })),
    }
}
