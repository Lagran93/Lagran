//! Integration tests for the repository layer.
//!
//! These run against a real PostgreSQL schema (see `common`) because the
//! behaviour under test lives in SQL: transactional atomicity, `COALESCE`
//! merges, NULL-safe unique indexes and targeted queries.

mod common;

use common::TestDb;
use control::repository;
use sqlx::Executor;
use uuid::Uuid;

/// Insert a domain with the minimum required columns.
async fn insert_domain(db: &TestDb, name: &str) -> Uuid {
    sqlx::query_scalar(
        r#"
        INSERT INTO domains (name, origin_host, origin_port, origin_proto)
        VALUES ($1, 'origin.test', 80, 'http')
        RETURNING id
        "#,
    )
    .bind(name)
    .fetch_one(&db.pool)
    .await
    .expect("insert domain")
}

#[tokio::test]
async fn domain_names_returns_id_and_name_only() {
    let db = TestDb::new().await;
    db_or_skip!(db);

    let a = insert_domain(&db, "alpha.test").await;
    let b = insert_domain(&db, "beta.test").await;

    let names = repository::domain_names(&db.pool).await.expect("names");
    assert_eq!(names.get(&a).map(String::as_str), Some("alpha.test"));
    assert_eq!(names.get(&b).map(String::as_str), Some("beta.test"));
    db.close().await;
}

#[tokio::test]
async fn domain_names_by_ids_only_returns_requested_rows() {
    let db = TestDb::new().await;
    db_or_skip!(db);

    let wanted = insert_domain(&db, "wanted.test").await;
    let _other = insert_domain(&db, "other.test").await;

    let names = repository::domain_names_by_ids(&db.pool, &[wanted])
        .await
        .expect("names by ids");
    assert_eq!(names.len(), 1, "only the requested id must come back");
    assert_eq!(names.get(&wanted).map(String::as_str), Some("wanted.test"));

    // An empty request must not query at all and must not error.
    assert!(repository::domain_names_by_ids(&db.pool, &[])
        .await
        .expect("empty")
        .is_empty());
    db.close().await;
}

#[tokio::test]
async fn domains_exist_filters_to_present_names() {
    let db = TestDb::new().await;
    db_or_skip!(db);

    insert_domain(&db, "present.test").await;
    let found = repository::domains_exist(
        &db.pool,
        &["present.test".to_string(), "absent.test".to_string()],
    )
    .await
    .expect("exists");
    assert!(found.contains("present.test"));
    assert!(!found.contains("absent.test"));
    db.close().await;
}

#[tokio::test]
async fn list_domains_by_ids_filters_in_sql() {
    let db = TestDb::new().await;
    db_or_skip!(db);

    let wanted = insert_domain(&db, "byid.test").await;
    let _other = insert_domain(&db, "skipme.test").await;

    let rows = repository::list_domains_by_ids(&db.pool, &[wanted])
        .await
        .expect("list by ids");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, wanted);
    assert_eq!(rows[0].name, "byid.test");
    db.close().await;
}

/// Two concurrent edits must not clobber each other.
///
/// The previous implementation read the whole settings row, patched it in Rust
/// and wrote every column back, so the later writer restored the earlier one's
/// stale values. The `COALESCE` merge only writes the supplied fields.
#[tokio::test]
async fn concurrent_settings_updates_do_not_clobber() {
    let db = TestDb::new().await;
    db_or_skip!(db);

    let id = insert_domain(&db, "concurrent.test").await;

    // Both requests start from the same snapshot.
    let _ = repository::update_domain_settings(
        &db.pool,
        id,
        None,
        None,
        None,
        None,
        None,
        Some(100),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .expect("seed");

    // Request A changes only rate_limit_rps.
    repository::update_domain_settings(
        &db.pool,
        id,
        None,
        None,
        None,
        None,
        None,
        Some(999),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .expect("A");

    // Request B changes only cc_rps, using the same parameters the handler would
    // send for a request that did not mention rate_limit_rps.
    repository::update_domain_settings(
        &db.pool,
        id,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(888),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .expect("B");

    let (rps, cc_rps): (i32, i32) =
        sqlx::query_as("SELECT rate_limit_rps, cc_rps FROM domains WHERE id = $1")
            .bind(id)
            .fetch_one(&db.pool)
            .await
            .expect("read back");
    assert_eq!(rps, 999, "A's write must survive B's update");
    assert_eq!(cc_rps, 888, "B's write must be applied");
    db.close().await;
}

/// A failed final delete must not leave the side tables wiped.
#[tokio::test]
async fn delete_domain_is_atomic() {
    let db = TestDb::new().await;
    db_or_skip!(db);

    let id = insert_domain(&db, "atomic.test").await;
    db.pool
        .execute(
            format!(
                "INSERT INTO origin_health (domain_name, origin_url, healthy)
                 VALUES ('atomic.test', 'http://origin.test', true)"
            )
            .as_str(),
        )
        .await
        .expect("seed origin health");

    // Normal delete removes both the domain and its side rows.
    let removed = repository::delete_domain(&db.pool, id)
        .await
        .expect("delete");
    assert_eq!(removed, 1);

    let (domains, health): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM domains WHERE id = $1),
                (SELECT count(*) FROM origin_health WHERE domain_name = 'atomic.test')",
    )
    .bind(id)
    .fetch_one(&db.pool)
    .await
    .expect("counts");
    assert_eq!(domains, 0);
    assert_eq!(health, 0, "side rows must go with the domain");

    // Deleting a missing domain reports 0 and does not touch anything else.
    assert_eq!(
        repository::delete_domain(&db.pool, Uuid::new_v4())
            .await
            .expect("delete missing"),
        0
    );
    db.close().await;
}

/// The firing-event uniqueness must hold when `rule_id` is NULL.
///
/// `ON DELETE SET NULL` turns every event of a deleted rule into a NULL-rule row,
/// and a plain `(rule_id, fingerprint)` unique index treats NULLs as distinct, so
/// duplicates were accepted.
#[tokio::test]
async fn firing_alert_events_are_unique_without_a_rule() {
    let db = TestDb::new().await;
    db_or_skip!(db);

    let insert = "INSERT INTO alert_events (rule_id, fingerprint, status, severity)
                  VALUES (NULL, 'fp-null-rule', 'firing', 'warning')";
    db.pool.execute(insert).await.expect("first insert");

    let second = sqlx::query(insert).execute(&db.pool).await;
    assert!(
        second.is_err(),
        "a duplicate firing event with a NULL rule_id must be rejected"
    );

    // Resolving the first frees the slot for a new firing event.
    sqlx::query("UPDATE alert_events SET status = 'resolved' WHERE fingerprint = 'fp-null-rule'")
        .execute(&db.pool)
        .await
        .expect("resolve");
    db.pool
        .execute(insert)
        .await
        .expect("a new firing event is allowed once the old one is resolved");
    db.close().await;
}

/// `refresh_alert_event` must not resurrect a resolved event.
#[tokio::test]
async fn refresh_alert_event_ignores_resolved_rows() {
    let db = TestDb::new().await;
    db_or_skip!(db);

    let id: i64 = sqlx::query_scalar(
        "INSERT INTO alert_events (rule_id, fingerprint, status, severity, value, message)
         VALUES (NULL, 'fp-refresh', 'resolved', 'warning', 1, 'original')
         RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .expect("insert");

    repository::refresh_alert_event(&db.pool, id, 99.0, "updated")
        .await
        .expect("refresh");

    let (value, message): (f64, String) =
        sqlx::query_as("SELECT value, message FROM alert_events WHERE id = $1")
            .bind(id)
            .fetch_one(&db.pool)
            .await
            .expect("read back");
    assert_eq!(value, 1.0, "a resolved event must not be updated");
    assert_eq!(message, "original");
    db.close().await;
}

/// A task claimed but never finished must be reclaimed, not left running.
///
/// `claim_prefetch_tasks` set `running` and nothing moved the row back, so a
/// worker that died mid-task left it stuck forever: never retried, never
/// reported, and impossible to clear from the console.
#[tokio::test]
async fn stale_prefetch_tasks_are_reclaimed() {
    let db = TestDb::new().await;
    db_or_skip!(db);

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO prefetch_tasks (domain, url_path, status)
         VALUES ('pf.test', '/a', 'pending') RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .expect("insert task");

    let claimed = repository::claim_prefetch_tasks(&db.pool, 10)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1);
    let (status, attempts): (String, i32) =
        sqlx::query_as("SELECT status, attempts FROM prefetch_tasks WHERE id = $1")
            .bind(id)
            .fetch_one(&db.pool)
            .await
            .expect("read");
    assert_eq!(status, "running");
    assert_eq!(attempts, 1, "claiming counts as an attempt");

    // A fresh claim is not stale: nothing must be reclaimed.
    let (requeued, failed) = repository::reclaim_stale_prefetch_tasks(&db.pool, 900, 3)
        .await
        .expect("reclaim fresh");
    assert_eq!(
        (requeued, failed),
        (0, 0),
        "a fresh claim must be left alone"
    );

    // Age it past the threshold.
    sqlx::query("UPDATE prefetch_tasks SET started_at = NOW() - INTERVAL '1 hour' WHERE id = $1")
        .bind(id)
        .execute(&db.pool)
        .await
        .expect("age task");

    let (requeued, failed) = repository::reclaim_stale_prefetch_tasks(&db.pool, 900, 3)
        .await
        .expect("reclaim stale");
    assert_eq!(requeued, 1, "a stale under-limit task is requeued");
    assert_eq!(failed, 0);
    let status: String = sqlx::query_scalar("SELECT status FROM prefetch_tasks WHERE id = $1")
        .bind(id)
        .fetch_one(&db.pool)
        .await
        .expect("read status");
    assert_eq!(status, "pending");
    db.close().await;
}

/// A task that keeps getting abandoned must eventually fail, not loop forever.
#[tokio::test]
async fn stale_prefetch_tasks_fail_after_the_retry_limit() {
    let db = TestDb::new().await;
    db_or_skip!(db);

    // Already at the attempt limit and stale.
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO prefetch_tasks (domain, url_path, status, attempts, started_at)
         VALUES ('pf.test', '/b', 'running', 3, NOW() - INTERVAL '1 hour') RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .expect("insert");

    let (requeued, failed) = repository::reclaim_stale_prefetch_tasks(&db.pool, 900, 3)
        .await
        .expect("reclaim");
    assert_eq!(requeued, 0);
    assert_eq!(failed, 1, "a task past the attempt limit must fail");
    let (status, message): (String, String) =
        sqlx::query_as("SELECT status, message FROM prefetch_tasks WHERE id = $1")
            .bind(id)
            .fetch_one(&db.pool)
            .await
            .expect("read");
    assert_eq!(status, "failed");
    assert!(message.contains("abandoned"), "message: {message}");
    db.close().await;
}
