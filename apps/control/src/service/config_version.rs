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
        Err(e) => {
            // Without this the task failed silently and the missing config versions
            // were only noticed when an edge asked for one.
            tracing::warn!(error = %e, "config version backfill failed; will retry on next start");
            return;
        }
    };
    for domain in domains {
        if let Ok(None) = crate::repository::latest_version(pool, domain.id).await {
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
    }
}

/// Actions that only take a snapshot of the current state and change nothing.
///
/// A real config mutation must release a pinned version (see [`record_domain`]),
/// but recording a manual snapshot or the upgrade baseline must not, or merely
/// viewing "save a version" would silently un-freeze a rolled-back domain.
fn is_snapshot_only_action(action: &str) -> bool {
    matches!(action, "manual.snapshot" | "initial.baseline")
}

/// Persist a version after a config mutation. Identical snapshots are skipped
/// so enabling/disabling a no-op rule does not create noise.
///
/// A real mutation also clears `published_version_id`. That field pins a domain
/// to a stored snapshot, and only `rollback_version` used to set it without ever
/// updating the live row: after a rollback every later change was written to the
/// database but never reached the edge, and the API kept answering "success".
/// Editing a rolled-back domain now means "make this change live", which is the
/// behaviour an operator expects — the rollback holds until the next edit.
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
    if !is_snapshot_only_action(action) {
        // Clearing is idempotent and cheap; doing it before the "unchanged"
        // early-return below means an edit that restores the previous content
        // still un-freezes the domain.
        repository::set_published_version(pool, domain_name, None).await?;
    }
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
    let Some(row) = repository::get_domain_by_name(pool, domain_name).await? else {
        return Ok(false);
    };
    // Capture the state being replaced before pinning the target, so the
    // rollback itself can be rolled back. `record_domain` clears the pin, so this
    // must run while the current live state is still what the edge serves.
    record_domain(
        pool,
        row.id,
        domain_name,
        "system",
        "rollback.pre",
        "回滚前快照",
    )
    .await?;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Taking a snapshot of the current state must not release a pinned version,
    /// otherwise visiting "save a version" would silently undo a rollback.
    #[test]
    fn snapshot_only_actions_do_not_unfreeze() {
        assert!(is_snapshot_only_action("manual.snapshot"));
        assert!(is_snapshot_only_action("initial.baseline"));
    }

    /// Real configuration mutations must release the pin so the change reaches
    /// the edge. This list mirrors every `record_domain` / `record_waf_version`
    /// call site; a new mutation action missing from here would reintroduce the
    /// freeze, so keep it in sync when adding handlers.
    #[test]
    fn every_mutation_action_unfreezes() {
        for action in [
            // domain.rs
            "domain.create",
            "domain.update",
            "domain.status",
            "domain.settings",
            // rule.rs
            "rule.create",
            "rule.update",
            "rule.delete",
            // waf.rs
            "waf.settings",
            "waf.rule.create",
            "waf.rule.update",
            "waf.rule.delete",
            "waf.ip.create",
            "waf.ip.update",
            "waf.ip.delete",
            "waf.geo.create",
            "waf.geo.update",
            "waf.geo.delete",
        ] {
            assert!(
                !is_snapshot_only_action(action),
                "{action} is a mutation and must clear the pinned version"
            );
        }
    }

    /// `rollback.pre` is written by the rollback itself; it is a snapshot of the
    /// outgoing state, so it must not clear the pin that is about to be set.
    #[test]
    fn rollback_pre_is_treated_as_a_mutation() {
        // It runs before the pin is written, so clearing is harmless and keeps
        // the "clear on real write" rule simple.
        assert!(!is_snapshot_only_action("rollback.pre"));
    }
}
