//! Shared harness for repository integration tests.
//!
//! Each test gets its own schema on the configured database, migrated with the
//! real migration set and dropped afterwards, so tests can run in parallel and
//! cannot see each other's rows.
//!
//! Set `TEST_DATABASE_URL` (or `DATABASE_URL`) to point at a database the test
//! user may create schemas in. When neither is set the tests skip instead of
//! failing, so `cargo test` on a machine without PostgreSQL still works.

#![allow(dead_code)]

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Executor, PgPool};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Whether a missing test database must fail instead of skipping.
fn require_database() -> bool {
    matches!(
        std::env::var("REQUIRE_TEST_DATABASE")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// A migrated schema that is dropped when the value is dropped.
pub struct TestDb {
    pub pool: PgPool,
    schema: String,
    /// Set when no database was configured; the test should return early.
    pub skipped: bool,
}

impl TestDb {
    /// Connect and create an isolated, migrated schema.
    pub async fn new() -> Self {
        let Ok(base) = std::env::var("TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .and_then(|v| {
                if v.trim().is_empty() {
                    Err(std::env::VarError::NotPresent)
                } else {
                    Ok(v)
                }
            })
        else {
            return Self::unavailable("neither TEST_DATABASE_URL nor DATABASE_URL is set");
        };

        let schema = format!(
            "lagran_test_{}_{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        );

        // Connect to the base database first and create the schema.
        let admin = match PgPoolOptions::new().max_connections(1).connect(&base).await {
            Ok(pool) => pool,
            Err(e) => {
                return Self::unavailable(&format!("cannot connect to the test database: {e}"));
            }
        };
        if let Err(e) = admin
            .execute(format!("CREATE SCHEMA IF NOT EXISTS {schema}").as_str())
            .await
        {
            let _ = admin.close().await;
            return Self::unavailable(&format!("cannot create schema {schema}: {e}"));
        }

        // Every connection in the pool must resolve unqualified names to the
        // test schema, so set the search_path per connection.
        let options = PgConnectOptions::from_str(&base)
            .expect("parse test database url")
            .options([("search_path", schema.as_str())]);
        let pool = match PgPoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
        {
            Ok(pool) => pool,
            Err(e) => {
                let _ = admin
                    .execute(format!("DROP SCHEMA IF EXISTS {schema} CASCADE").as_str())
                    .await;
                let _ = admin.close().await;
                return Self::unavailable(&format!("cannot apply search_path: {e}"));
            }
        };

        if let Err(e) = sqlx::migrate!("./migrations").run(&pool).await {
            let _ = pool.close().await;
            let _ = admin
                .execute(format!("DROP SCHEMA IF EXISTS {schema} CASCADE").as_str())
                .await;
            let _ = admin.close().await;
            return Self::unavailable(&format!("migrations failed: {e}"));
        }

        let _ = admin.close().await;
        Self {
            pool,
            schema,
            skipped: false,
        }
    }

    /// No database is available.
    ///
    /// Skipping keeps `cargo test` usable on a machine without PostgreSQL, but a
    /// silent skip in CI would report green while validating nothing. Setting
    /// `REQUIRE_TEST_DATABASE=1` turns a missing database into a failure instead.
    fn unavailable(reason: &str) -> Self {
        if require_database() {
            panic!(
                "REQUIRE_TEST_DATABASE is set but the integration database is unusable: {reason}"
            );
        }
        eprintln!("skipping integration test: {reason}");
        // A pool that is never used; tests check `skipped` before touching it.
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://unused/unused")
            .expect("lazy pool");
        Self {
            pool,
            schema: String::new(),
            skipped: true,
        }
    }
}

impl TestDb {
    /// Drop the schema and close the pool.
    ///
    /// Cleanup is explicit rather than in `Drop`: dropping a pool needs to await,
    /// and a `Drop` impl that spawns a thread and joins it deadlocks once the
    /// test's runtime starts shutting down. A test that forgets to call this
    /// leaves a schema behind, which the next run ignores.
    pub async fn close(self) {
        if self.skipped {
            return;
        }
        let schema = self.schema.clone();
        let _ = sqlx::query(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
            .execute(&self.pool)
            .await;
        let _ = self.pool.close().await;
    }
}

/// Skip the current test when no test database is configured.
///
/// Written as a macro so the early return is in the caller's scope.
#[macro_export]
macro_rules! db_or_skip {
    ($db:expr) => {
        if $db.skipped {
            eprintln!("skipping: TEST_DATABASE_URL/DATABASE_URL is not set");
            return;
        }
    };
}
