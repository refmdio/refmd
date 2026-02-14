//! Test helpers for integration tests.
//!
//! Provides utilities for building test `AppState` instances and
//! making requests against the application router.

/// Returns `true` if a test database URL is configured.
pub fn has_test_db() -> bool {
    std::env::var("TEST_DATABASE_URL").is_ok()
}

/// Build a test database connection pool.
///
/// Requires `TEST_DATABASE_URL` to be set.
/// Panics if the database connection fails.
pub async fn build_test_pool() -> infrastructure::PgPool {
    let db_url = std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL must be set for DB integration tests");

    let db_config = infrastructure::DatabaseConfig {
        url: db_url,
        max_connections: 5,
    };

    infrastructure::create_pool(&db_config)
        .await
        .expect("failed to connect to test database")
}

/// Macro to skip a test if `TEST_DATABASE_URL` is not set.
macro_rules! require_test_db {
    () => {
        if !$crate::helpers::has_test_db() {
            eprintln!("Skipping: TEST_DATABASE_URL not set");
            return;
        }
    };
}

pub(crate) use require_test_db;
