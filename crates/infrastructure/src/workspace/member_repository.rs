//! PostgreSQL workspace member repository implementation

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::identity::UserId;
use domain::workspace::{RoleId, WorkspaceId, WorkspaceMember, WorkspaceMemberRepository};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

/// PostgreSQL workspace member repository
#[derive(Clone)]
pub struct PgWorkspaceMemberRepository {
    pool: PgPool,
}

impl PgWorkspaceMemberRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Error)]
pub enum PgWorkspaceMemberRepositoryError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(sqlx::FromRow)]
struct WorkspaceMemberRow {
    workspace_id: Uuid,
    user_id: Uuid,
    role_id: Uuid,
    is_default: bool,
    joined_at: DateTime<Utc>,
}

impl From<WorkspaceMemberRow> for WorkspaceMember {
    fn from(row: WorkspaceMemberRow) -> Self {
        Self {
            workspace_id: WorkspaceId::from_uuid(row.workspace_id),
            user_id: UserId::from_uuid(row.user_id),
            role_id: RoleId::from_uuid(row.role_id),
            is_default: row.is_default,
            joined_at: row.joined_at,
        }
    }
}

#[async_trait]
impl WorkspaceMemberRepository for PgWorkspaceMemberRepository {
    type Error = PgWorkspaceMemberRepositoryError;

    async fn find_by_workspace_and_user(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
    ) -> Result<Option<WorkspaceMember>, Self::Error> {
        let row = sqlx::query_as::<_, WorkspaceMemberRow>(
            r#"
            SELECT workspace_id, user_id, role_id, is_default, joined_at
            FROM workspace_members
            WHERE workspace_id = $1 AND user_id = $2
            "#,
        )
        .bind(workspace_id.as_uuid())
        .bind(user_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(WorkspaceMember::from))
    }

    async fn find_by_workspace_id(&self, workspace_id: WorkspaceId) -> Result<Vec<WorkspaceMember>, Self::Error> {
        let rows = sqlx::query_as::<_, WorkspaceMemberRow>(
            r#"
            SELECT workspace_id, user_id, role_id, is_default, joined_at
            FROM workspace_members
            WHERE workspace_id = $1
            ORDER BY joined_at
            "#,
        )
        .bind(workspace_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(WorkspaceMember::from).collect())
    }

    async fn find_by_user_id(&self, user_id: UserId) -> Result<Vec<WorkspaceMember>, Self::Error> {
        let rows = sqlx::query_as::<_, WorkspaceMemberRow>(
            r#"
            SELECT workspace_id, user_id, role_id, is_default, joined_at
            FROM workspace_members
            WHERE user_id = $1
            ORDER BY joined_at
            "#,
        )
        .bind(user_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(WorkspaceMember::from).collect())
    }

    async fn find_default_by_user_id(&self, user_id: UserId) -> Result<Option<WorkspaceMember>, Self::Error> {
        let row = sqlx::query_as::<_, WorkspaceMemberRow>(
            r#"
            SELECT workspace_id, user_id, role_id, is_default, joined_at
            FROM workspace_members
            WHERE user_id = $1 AND is_default = TRUE
            "#,
        )
        .bind(user_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(WorkspaceMember::from))
    }

    async fn save(&self, member: &WorkspaceMember) -> Result<(), Self::Error> {
        sqlx::query(
            r#"
            INSERT INTO workspace_members (workspace_id, user_id, role_id, is_default, joined_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (workspace_id, user_id) DO UPDATE SET
                role_id = EXCLUDED.role_id,
                is_default = EXCLUDED.is_default
            "#,
        )
        .bind(member.workspace_id.as_uuid())
        .bind(member.user_id.as_uuid())
        .bind(member.role_id.as_uuid())
        .bind(member.is_default)
        .bind(member.joined_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, workspace_id: WorkspaceId, user_id: UserId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM workspace_members WHERE workspace_id = $1 AND user_id = $2")
            .bind(workspace_id.as_uuid())
            .bind(user_id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete_by_workspace_id(&self, workspace_id: WorkspaceId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM workspace_members WHERE workspace_id = $1")
            .bind(workspace_id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn clear_default_for_user(&self, user_id: UserId) -> Result<(), Self::Error> {
        sqlx::query("UPDATE workspace_members SET is_default = FALSE WHERE user_id = $1")
            .bind(user_id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
