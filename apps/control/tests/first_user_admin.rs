//! The first registered account becomes the administrator.
//!
//! Cold start: `SEED_DEMO` is refused when `REQUIRE_SECURE_SECRETS=true`, so without
//! this an operator has no way to obtain an account that can administer the instance.
//! Turning `ALLOW_REGISTER` on for one registration and back off is the bootstrap.

mod common;

use common::TestDb;
use control::repository;

#[tokio::test]
async fn first_registered_user_is_admin() {
    let db = TestDb::new().await;
    if db.skipped {
        return;
    }

    let first = repository::create_user_first_is_admin(&db.pool, "first@example.com", "h", "First")
        .await
        .expect("insert first user");
    assert_eq!(first.role, "admin");
}

#[tokio::test]
async fn later_users_are_plain_users() {
    let db = TestDb::new().await;
    if db.skipped {
        return;
    }

    repository::create_user_first_is_admin(&db.pool, "a@example.com", "h", "A")
        .await
        .expect("first");
    let second = repository::create_user_first_is_admin(&db.pool, "b@example.com", "h", "B")
        .await
        .expect("second");

    assert_eq!(
        second.role, "user",
        "only the very first account may be promoted"
    );
}

/// Concurrent first registrations: exactly one admin.
///
/// The emptiness test and the INSERT are a single statement precisely so this holds
/// without a lock; two separate round trips would let both see an empty table.
#[tokio::test]
async fn concurrent_first_registrations_yield_one_admin() {
    let db = TestDb::new().await;
    if db.skipped {
        return;
    }

    let mut handles = Vec::new();
    for i in 0..8 {
        let pool = db.pool.clone();
        handles.push(tokio::spawn(async move {
            repository::create_user_first_is_admin(
                &pool,
                &format!("racer{i}@example.com"),
                "h",
                "Racer",
            )
            .await
        }));
    }
    let mut admins = 0;
    let mut created = 0;
    for handle in handles {
        if let Ok(Ok(user)) = handle.await {
            created += 1;
            if user.role == "admin" {
                admins += 1;
            }
        }
    }
    assert_eq!(created, 8, "every distinct email should be inserted");
    assert_eq!(
        admins, 1,
        "exactly one concurrent registration may be admin"
    );
}

/// A registration that loses the race must still succeed as a normal user.
#[tokio::test]
async fn losing_the_race_is_not_an_error() {
    let db = TestDb::new().await;
    if db.skipped {
        return;
    }

    let a = repository::create_user_first_is_admin(&db.pool, "a@example.com", "h", "A")
        .await
        .expect("a");
    let b = repository::create_user_first_is_admin(&db.pool, "b@example.com", "h", "B")
        .await
        .expect("b must not fail");
    assert_ne!(a.role, b.role);
    assert_eq!(b.role, "user");
}
