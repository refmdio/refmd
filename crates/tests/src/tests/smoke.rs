//! Smoke tests
//!
//! Basic tests that verify the application compiles and fundamental
//! invariants hold. These tests do NOT require a database.

/// Verify that domain types can be constructed (compile-time sanity check).
#[test]
fn domain_types_construct() {
    let user_id = domain::identity::UserId::new();
    let workspace_id = domain::workspace::WorkspaceId::new();
    let document_id = domain::document::DocumentId::new();
    let device_id = domain::encryption::DeviceId::new();

    // IDs should be distinct
    assert_ne!(user_id.as_uuid(), workspace_id.as_uuid());
    assert_ne!(document_id.as_uuid(), device_id.as_uuid());
}

/// Verify that a test DB pool can be created (gated behind env var).
#[tokio::test]
async fn database_connects() {
    crate::helpers::require_test_db!();

    let pool = crate::helpers::build_test_pool().await;

    // Basic connectivity check
    let row: (i64,) = sqlx::query_as("SELECT 1")
        .fetch_one(&pool)
        .await
        .expect("SELECT 1 should succeed");
    assert_eq!(row.0, 1);
}
