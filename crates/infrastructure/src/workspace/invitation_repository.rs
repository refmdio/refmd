//! PostgreSQL workspace invitation repository implementation

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::identity::UserId;
use domain::workspace::{
    InvitationId, RoleId, WorkspaceId, WorkspaceInvitation, WorkspaceInvitationRepository,
};
use uuid::Uuid;

pg_repo_struct!(PgWorkspaceInvitationRepository);
pg_repo_error!(PgWorkspaceInvitationRepositoryError);

#[derive(sqlx::FromRow)]
struct WorkspaceInvitationRow {
    id: Uuid,
    workspace_id: Uuid,
    token_hash: String,
    token_prefix: String,
    role_id: Option<Uuid>,
    invited_by: Uuid,
    invited_email: String,
    encrypted_kek: Vec<u8>,
    kek_nonce: Vec<u8>,
    kek_version: i32,
    is_used: bool,
    revoked_at: Option<DateTime<Utc>>,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

impl From<WorkspaceInvitationRow> for WorkspaceInvitation {
    fn from(row: WorkspaceInvitationRow) -> Self {
        Self {
            id: InvitationId::from_uuid(row.id),
            workspace_id: WorkspaceId::from_uuid(row.workspace_id),
            token_hash: row.token_hash,
            token_prefix: row.token_prefix,
            role_id: row.role_id.map(RoleId::from_uuid),
            invited_by: UserId::from_uuid(row.invited_by),
            invited_email: row.invited_email,
            encrypted_kek: row.encrypted_kek,
            kek_nonce: row.kek_nonce,
            kek_version: row.kek_version,
            is_used: row.is_used,
            revoked_at: row.revoked_at,
            expires_at: row.expires_at,
            created_at: row.created_at,
        }
    }
}

#[async_trait]
impl WorkspaceInvitationRepository for PgWorkspaceInvitationRepository {
    type Error = PgWorkspaceInvitationRepositoryError;

    async fn find_by_id(
        &self,
        id: InvitationId,
    ) -> Result<Option<WorkspaceInvitation>, Self::Error> {
        let row = sqlx::query_as!(
            WorkspaceInvitationRow,
            r#"
            SELECT id, workspace_id, token_hash, token_prefix, role_id,
                   invited_by, invited_email as "invited_email!",
                   encrypted_kek as "encrypted_kek!", kek_nonce as "kek_nonce!", kek_version as "kek_version!",
                   is_used, revoked_at,
                   expires_at as "expires_at!", created_at
            FROM workspace_invitations
            WHERE id = $1
            "#,
            id.as_uuid()
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(WorkspaceInvitation::from))
    }

    async fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<WorkspaceInvitation>, Self::Error> {
        let row = sqlx::query_as!(
            WorkspaceInvitationRow,
            r#"
            SELECT id, workspace_id, token_hash, token_prefix, role_id,
                   invited_by, invited_email as "invited_email!",
                   encrypted_kek as "encrypted_kek!", kek_nonce as "kek_nonce!", kek_version as "kek_version!",
                   is_used, revoked_at,
                   expires_at as "expires_at!", created_at
            FROM workspace_invitations
            WHERE token_hash = $1
            "#,
            token_hash
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(WorkspaceInvitation::from))
    }

    async fn find_active_by_workspace_id(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<WorkspaceInvitation>, Self::Error> {
        let rows = sqlx::query_as!(
            WorkspaceInvitationRow,
            r#"
            SELECT i.id, i.workspace_id, i.token_hash, i.token_prefix, i.role_id,
                   i.invited_by, i.invited_email as "invited_email!",
                   i.encrypted_kek as "encrypted_kek!", i.kek_nonce as "kek_nonce!", i.kek_version as "kek_version!",
                   i.is_used, i.revoked_at,
                   i.expires_at as "expires_at!", i.created_at
            FROM workspace_invitations i
            JOIN workspaces w ON w.id = i.workspace_id
            WHERE i.workspace_id = $1
              AND i.revoked_at IS NULL
              AND i.expires_at > NOW()
              AND i.is_used = FALSE
              AND i.role_id IS NOT NULL
              AND i.kek_version >= w.min_kek_version
            ORDER BY i.created_at DESC
            "#,
            workspace_id.as_uuid()
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(WorkspaceInvitation::from).collect())
    }

    async fn save(&self, invitation: &WorkspaceInvitation) -> Result<(), Self::Error> {
        sqlx::query!(
            r#"
            INSERT INTO workspace_invitations (
                id, workspace_id, token_hash, token_prefix, role_id,
                invited_by, invited_email, encrypted_kek, kek_nonce, kek_version,
                is_used, revoked_at, expires_at, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            "#,
            invitation.id.as_uuid(),
            invitation.workspace_id.as_uuid(),
            &invitation.token_hash,
            &invitation.token_prefix,
            invitation.role_id.map(|r| r.as_uuid()),
            invitation.invited_by.as_uuid(),
            &invitation.invited_email,
            &invitation.encrypted_kek[..],
            &invitation.kek_nonce[..],
            invitation.kek_version,
            invitation.is_used,
            invitation.revoked_at,
            invitation.expires_at,
            invitation.created_at,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn revoke(
        &self,
        id: InvitationId,
        workspace_id: WorkspaceId,
    ) -> Result<bool, Self::Error> {
        let result = sqlx::query!(
            r#"
            UPDATE workspace_invitations
            SET revoked_at = NOW()
            WHERE id = $1
              AND workspace_id = $2
              AND revoked_at IS NULL
            "#,
            id.as_uuid(),
            workspace_id.as_uuid()
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn count_by_role_id(
        &self,
        workspace_id: WorkspaceId,
        role_id: RoleId,
    ) -> Result<i64, Self::Error> {
        let count = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM workspace_invitations
            WHERE workspace_id = $1
              AND role_id = $2
            "#,
            workspace_id.as_uuid(),
            role_id.as_uuid()
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
    }

    async fn revoke_all_active(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<i64, Self::Error> {
        let result = sqlx::query_scalar!(
            r#"
            WITH revoked AS (
                UPDATE workspace_invitations
                SET revoked_at = NOW()
                WHERE workspace_id = $1
                  AND revoked_at IS NULL
                  AND expires_at > NOW()
                  AND is_used = FALSE
                RETURNING id
            )
            SELECT COUNT(*) as "count!" FROM revoked
            "#,
            workspace_id.as_uuid()
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }
}
