//! Transactional workspace creation
//!
//! Creates a workspace with 4 default roles and the owner member in a single transaction.

use application::workspace::{
    WorkspaceCreationData, WorkspaceCreationService, WorkspaceCreationServiceError,
};
use async_trait::async_trait;
use sqlx::PgPool;
use std::sync::Arc;

/// PostgreSQL implementation of WorkspaceCreationService
#[derive(Clone)]
pub struct PgWorkspaceCreationService {
    pool: Arc<PgPool>,
}

impl PgWorkspaceCreationService {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl WorkspaceCreationService for PgWorkspaceCreationService {
    async fn create_atomic(
        &self,
        data: WorkspaceCreationData,
    ) -> Result<(), WorkspaceCreationServiceError> {
        create_workspace_atomic(&self.pool, data).await.map_err(|e| {
            // Map PostgreSQL unique_violation (23505) on the slug constraint specifically.
            // Other 23505 errors (e.g. workspace PK, role PK) are unexpected and should
            // surface as Database errors rather than being misclassified as SlugConflict.
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.code().as_deref() == Some("23505")
                    && db_err
                        .constraint()
                        .map_or(false, |c| c.contains("slug"))
                {
                    return WorkspaceCreationServiceError::SlugConflict;
                }
            }
            WorkspaceCreationServiceError::Database(e.to_string())
        })
    }
}

type PgTx<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

async fn create_workspace_atomic(
    pool: &PgPool,
    data: WorkspaceCreationData,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;

    // 1. Insert workspace
    sqlx::query!(
        r#"
        INSERT INTO workspaces (id, name, slug, description, icon, owner_id, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
        data.workspace.id.as_uuid(),
        &data.workspace.name,
        data.workspace.slug.as_str(),
        data.workspace.description.as_deref(),
        data.workspace.icon.as_deref(),
        data.workspace.owner_id.as_uuid(),
        data.workspace.created_at,
        data.workspace.updated_at,
    )
    .execute(&mut *tx)
    .await?;

    // 2. Insert 4 roles
    for role in [
        &data.owner_role,
        &data.admin_role,
        &data.editor_role,
        &data.viewer_role,
    ] {
        insert_workspace_role(&mut tx, role).await?;
    }

    // 3. Insert owner member
    sqlx::query!(
        r#"
        INSERT INTO workspace_members (workspace_id, user_id, role_id, is_default, joined_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
        data.member.workspace_id.as_uuid(),
        data.member.user_id.as_uuid(),
        data.member.role_id.as_uuid(),
        data.member.is_default,
        data.member.joined_at,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}

async fn insert_workspace_role(
    tx: &mut PgTx<'_>,
    role: &domain::workspace::WorkspaceRole,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO workspace_roles (id, workspace_id, name, base_role, is_default, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        role.id.as_uuid(),
        role.workspace_id.as_uuid(),
        &role.name,
        role.base_role.as_str(),
        role.is_default,
        role.created_at,
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}
