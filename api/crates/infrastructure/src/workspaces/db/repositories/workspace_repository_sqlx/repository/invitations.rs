use super::*;

impl SqlxWorkspaceRepository {
    pub(super) async fn create_invitation_impl(
        &self,
        workspace_id: Uuid,
        email: &str,
        role_kind: WorkspaceRoleKind,
        system_role: Option<WorkspaceSystemRole>,
        custom_role_id: Option<Uuid>,
        invited_by: Uuid,
        token: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> anyhow::Result<WorkspaceInvitationRecord> {
        let row = sqlx::query(
            r#"INSERT INTO workspace_invitations (
                    workspace_id,
                    email,
                    role_kind,
                    system_role,
                    custom_role_id,
                    invited_by,
                    token,
                    expires_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING id, workspace_id, email, role_kind, system_role, custom_role_id,
                          invited_by, token, expires_at, accepted_by, accepted_at, revoked_at,
                          created_at, encrypted_kek_for_invite, kek_version"#,
        )
        .bind(workspace_id)
        .bind(email)
        .bind(role_kind.as_str())
        .bind(system_role.map(|r| r.as_str()))
        .bind(custom_role_id)
        .bind(invited_by)
        .bind(token)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await?;
        self.map_invitation_row(&row)
    }
    pub(super) async fn list_invitations_impl(
        &self,
        workspace_id: Uuid,
    ) -> anyhow::Result<Vec<WorkspaceInvitationRecord>> {
        let rows = sqlx::query(
            r#"SELECT id, workspace_id, email, role_kind, system_role, custom_role_id,
                      invited_by, token, expires_at, accepted_by, accepted_at, revoked_at,
                      created_at, encrypted_kek_for_invite, kek_version
               FROM workspace_invitations
               WHERE workspace_id = $1
               ORDER BY created_at DESC"#,
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| self.map_invitation_row(&row))
            .collect::<anyhow::Result<Vec<_>>>()
    }
    pub(super) async fn accept_invitation_impl(
        &self,
        token: &str,
        user_id: Uuid,
        user_email: &str,
    ) -> anyhow::Result<WorkspaceInvitationRecord> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            r#"SELECT id, workspace_id, email, role_kind, system_role, custom_role_id,
                      invited_by, token, expires_at, accepted_by, accepted_at, revoked_at,
                      created_at, encrypted_kek_for_invite, kek_version
               FROM workspace_invitations
               WHERE token = $1
               FOR UPDATE"#,
        )
        .bind(token)
        .fetch_optional(tx.as_mut())
        .await?;

        let Some(row) = row else {
            bail!("invitation_not_found");
        };
        let mut record = self.map_invitation_row(&row)?;
        if record.revoked_at.is_some() {
            bail!("invitation_revoked");
        }
        if record.accepted_at.is_some() {
            bail!("invitation_already_accepted");
        }
        if record
            .expires_at
            .is_some_and(|expires| expires < Utc::now())
        {
            bail!("invitation_expired");
        }
        if record.email.trim().to_lowercase() != user_email.trim().to_lowercase() {
            bail!("invitation_email_mismatch");
        }

        let now = Utc::now();
        sqlx::query(
            r#"UPDATE workspace_invitations
               SET accepted_by = $2, accepted_at = $3
               WHERE id = $1"#,
        )
        .bind(record.id)
        .bind(user_id)
        .bind(now)
        .execute(tx.as_mut())
        .await?;

        sqlx::query(
            r#"INSERT INTO workspace_members (
                    workspace_id,
                    user_id,
                    role_kind,
                    system_role,
                    custom_role_id,
                    invited_by,
                    is_default
                )
                VALUES ($1, $2, $3, $4, $5, $6, false)
                ON CONFLICT (workspace_id, user_id) DO UPDATE SET
                    role_kind = EXCLUDED.role_kind,
                    system_role = EXCLUDED.system_role,
                    custom_role_id = EXCLUDED.custom_role_id"#,
        )
        .bind(record.workspace_id)
        .bind(user_id)
        .bind(record.role_kind.as_str())
        .bind(record.system_role.map(|role| role.as_str()))
        .bind(record.custom_role_id)
        .bind(record.invited_by)
        .execute(tx.as_mut())
        .await?;

        tx.commit().await?;
        record.accepted_by = Some(user_id);
        record.accepted_at = Some(now);
        Ok(record)
    }
    pub(super) async fn revoke_invitation_impl(
        &self,
        workspace_id: Uuid,
        invitation_id: Uuid,
    ) -> anyhow::Result<Option<WorkspaceInvitationRecord>> {
        let row = sqlx::query(
            r#"UPDATE workspace_invitations
                   SET revoked_at = now()
                   WHERE id = $1 AND workspace_id = $2 AND revoked_at IS NULL AND accepted_at IS NULL
                   RETURNING id, workspace_id, email, role_kind, system_role, custom_role_id,
                             invited_by, token, expires_at, accepted_by, accepted_at, revoked_at,
                             created_at, encrypted_kek_for_invite, kek_version"#,
        )
        .bind(invitation_id)
        .bind(workspace_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| self.map_invitation_row(&row)).transpose()
    }

    /// Update invitation with encrypted KEK
    pub(super) async fn update_invitation_kek_impl(
        &self,
        workspace_id: Uuid,
        invitation_id: Uuid,
        encrypted_kek_for_invite: &str,
        kek_version: i32,
    ) -> anyhow::Result<Option<WorkspaceInvitationRecord>> {
        let row = sqlx::query(
            r#"UPDATE workspace_invitations
                   SET encrypted_kek_for_invite = $3, kek_version = $4
                   WHERE id = $1 AND workspace_id = $2 AND revoked_at IS NULL AND accepted_at IS NULL
                   RETURNING id, workspace_id, email, role_kind, system_role, custom_role_id,
                             invited_by, token, expires_at, accepted_by, accepted_at, revoked_at,
                             created_at, encrypted_kek_for_invite, kek_version"#,
        )
        .bind(invitation_id)
        .bind(workspace_id)
        .bind(encrypted_kek_for_invite)
        .bind(kek_version)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| self.map_invitation_row(&row)).transpose()
    }
}
