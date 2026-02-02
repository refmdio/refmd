//! PostgreSQL workspace invitation repository implementation

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::identity::UserId;
use domain::workspace::{InvitationId, RoleId, WorkspaceId, WorkspaceInvitation, WorkspaceInvitationRepository};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

/// PostgreSQL workspace invitation repository
#[derive(Clone)]
pub struct PgWorkspaceInvitationRepository {
    pool: PgPool,
}

impl PgWorkspaceInvitationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Error)]
pub enum PgWorkspaceInvitationRepositoryError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(sqlx::FromRow)]
struct WorkspaceInvitationRow {
    id: Uuid,
    workspace_id: Uuid,
    token_hash: String,
    token_prefix: String,
    role_id: Uuid,
    invited_by: Uuid,
    invited_email: Option<String>,
    max_uses: Option<i32>,
    use_count: i32,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl From<WorkspaceInvitationRow> for WorkspaceInvitation {
    fn from(row: WorkspaceInvitationRow) -> Self {
        Self {
            id: InvitationId::from_uuid(row.id),
            workspace_id: WorkspaceId::from_uuid(row.workspace_id),
            token_hash: row.token_hash,
            token_prefix: row.token_prefix,
            role_id: RoleId::from_uuid(row.role_id),
            invited_by: UserId::from_uuid(row.invited_by),
            invited_email: row.invited_email,
            max_uses: row.max_uses,
            use_count: row.use_count,
            expires_at: row.expires_at,
            created_at: row.created_at,
        }
    }
}

#[async_trait]
impl WorkspaceInvitationRepository for PgWorkspaceInvitationRepository {
    type Error = PgWorkspaceInvitationRepositoryError;

    async fn find_by_id(&self, id: InvitationId) -> Result<Option<WorkspaceInvitation>, Self::Error> {
        let row = sqlx::query_as::<_, WorkspaceInvitationRow>(
            r#"
            SELECT id, workspace_id, token_hash, token_prefix, role_id, invited_by,
                   invited_email, max_uses, use_count, expires_at, created_at
            FROM workspace_invitations
            WHERE id = $1
            "#,
        )
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(WorkspaceInvitation::from))
    }

    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<WorkspaceInvitation>, Self::Error> {
        let row = sqlx::query_as::<_, WorkspaceInvitationRow>(
            r#"
            SELECT id, workspace_id, token_hash, token_prefix, role_id, invited_by,
                   invited_email, max_uses, use_count, expires_at, created_at
            FROM workspace_invitations
            WHERE token_hash = $1
            "#,
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(WorkspaceInvitation::from))
    }

    async fn find_by_workspace_id(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<WorkspaceInvitation>, Self::Error> {
        let rows = sqlx::query_as::<_, WorkspaceInvitationRow>(
            r#"
            SELECT id, workspace_id, token_hash, token_prefix, role_id, invited_by,
                   invited_email, max_uses, use_count, expires_at, created_at
            FROM workspace_invitations
            WHERE workspace_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(workspace_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(WorkspaceInvitation::from).collect())
    }

    async fn find_by_workspace_and_email(
        &self,
        workspace_id: WorkspaceId,
        email: &str,
    ) -> Result<Option<WorkspaceInvitation>, Self::Error> {
        let row = sqlx::query_as::<_, WorkspaceInvitationRow>(
            r#"
            SELECT id, workspace_id, token_hash, token_prefix, role_id, invited_by,
                   invited_email, max_uses, use_count, expires_at, created_at
            FROM workspace_invitations
            WHERE workspace_id = $1 AND invited_email = $2
            "#,
        )
        .bind(workspace_id.as_uuid())
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(WorkspaceInvitation::from))
    }

    async fn save(&self, invitation: &WorkspaceInvitation) -> Result<(), Self::Error> {
        sqlx::query(
            r#"
            INSERT INTO workspace_invitations (
                id, workspace_id, token_hash, token_prefix, role_id, invited_by,
                invited_email, max_uses, use_count, expires_at, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (id) DO UPDATE SET
                use_count = EXCLUDED.use_count,
                expires_at = EXCLUDED.expires_at
            "#,
        )
        .bind(invitation.id.as_uuid())
        .bind(invitation.workspace_id.as_uuid())
        .bind(&invitation.token_hash)
        .bind(&invitation.token_prefix)
        .bind(invitation.role_id.as_uuid())
        .bind(invitation.invited_by.as_uuid())
        .bind(&invitation.invited_email)
        .bind(invitation.max_uses)
        .bind(invitation.use_count)
        .bind(invitation.expires_at)
        .bind(invitation.created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, id: InvitationId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM workspace_invitations WHERE id = $1")
            .bind(id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete_by_workspace_id(&self, workspace_id: WorkspaceId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM workspace_invitations WHERE workspace_id = $1")
            .bind(workspace_id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete_expired(&self) -> Result<u64, Self::Error> {
        let result = sqlx::query("DELETE FROM workspace_invitations WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }
}
