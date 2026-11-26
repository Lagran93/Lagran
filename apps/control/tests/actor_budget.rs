//! Regression guard for the actor load budget.
//!
//! One authenticated request used to cost five to seven SQL round trips: the
//! permission middleware loaded the `Actor`, discarded it, and the handler's
//! `Actor` extractor loaded it again (twice), with the newer session query
//! adding a third statement per load. After the fix the middleware publishes the
//! actor into the request extensions, `get_actor_facts` is a single statement,
//! and the counters below must show exactly one load + one reuse per request.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::TestDb;
use control::api;
use control::config::AppConfig;
use control::middleware::authz::{ACTOR_DB_LOADS, ACTOR_REUSES};
use control::repository;
use control::state::AppState;
use control::utils::issue_token;
use std::sync::atomic::Ordering;
use tower::util::ServiceExt;

#[tokio::test]
async fn one_authenticated_request_loads_the_actor_once() {
    let db = TestDb::new().await;
    if db.skipped {
        return;
    }
    let user = repository::create_user(&db.pool, "budget@example.test", "hash", "Budget")
        .await
        .expect("seed user");

    let config = AppConfig::load();
    let token = issue_token(
        user.id,
        &user.email,
        &user.name,
        &config.jwt_secret,
        1,
        user.token_version,
    )
    .expect("sign token");
    let state = AppState::new(db.pool.clone(), config, None);
    let app = api::create_router(state);

    let loads_before = ACTOR_DB_LOADS.load(Ordering::Relaxed);
    let reuses_before = ACTOR_REUSES.load(Ordering::Relaxed);

    let request = Request::builder()
        .uri("/api/v1/domains")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request");
    let response = app.oneshot(request).await.expect("router response");
    assert_eq!(response.status(), StatusCode::OK);

    let loads = ACTOR_DB_LOADS.load(Ordering::Relaxed) - loads_before;
    let reuses = ACTOR_REUSES.load(Ordering::Relaxed) - reuses_before;
    assert_eq!(
        loads, 1,
        "the actor must be loaded exactly once per authenticated request"
    );
    assert_eq!(
        reuses, 1,
        "the handler must reuse the actor resolved by the permission middleware"
    );
}
