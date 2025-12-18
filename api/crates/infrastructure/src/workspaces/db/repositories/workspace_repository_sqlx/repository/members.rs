use super::*;

impl SqlxWorkspaceRepository {
    pub(super) async fn add_member_impl(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        role_kind: WorkspaceRoleKind,
        system_role: Option<WorkspaceSystemRole>,
        custom_role_id: Option<Uuid>,
    ) -> anyhow::Result<WorkspaceMemberRow> {
        let row = sqlx::query(
            r#"INSERT INTO workspace_members (workspace_id, user_id, role_kind, system_role, custom_role_id, invited_by)
               VALUES ($1, $2, $3, $4, $5, $2)
               ON CONFLICT (workspace_id, user_id) DO UPDATE SET
                 role_kind = EXCLUDED.role_kind,
                 system_role = EXCLUDED.system_role,
                 custom_role_id = EXCLUDED.custom_role_id
               RETURNING workspace_id, user_id, role_kind, system_role, custom_role_id, is_default"#,
        )
        .bind(workspace_id)
        .bind(user_id)
        .bind(role_kind.as_str())
        .bind(system_role.map(|r| r.as_str()))
        .bind(custom_role_id)
        .fetch_one(&self.pool)
        .await?;
        let role_kind_raw: String = row.get("role_kind");
        let system_role_raw: Option<String> = row.try_get("system_role").ok();
        Ok(WorkspaceMemberRow {
            workspace_id: row.get("workspace_id"),
            user_id: row.get("user_id"),
            role_kind: Self::parse_role_kind(&role_kind_raw)?,
            system_role: Self::parse_system_role(system_role_raw.as_deref())?,
            custom_role_id: row.try_get("custom_role_id").ok(),
            is_default: row.get("is_default"),
        })
    }
    pub(super) async fn set_default_workspace_impl(
        &self,
        user_id: Uuid,
        workspace_id: Uuid,
    ) -> Result<WorkspaceMemberRow, WorkspaceSetDefaultError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|err| WorkspaceSetDefaultError::Unexpected(err.into()))?;
        sqlx::query(r#"UPDATE workspace_members SET is_default = false WHERE user_id = $1"#)
            .bind(user_id)
            .execute(tx.as_mut())
            .await
            .map_err(|err| WorkspaceSetDefaultError::Unexpected(err.into()))?;

        let row = sqlx::query(
            r#"UPDATE workspace_members
               SET is_default = true
               WHERE workspace_id = $1 AND user_id = $2
               RETURNING workspace_id, user_id, role_kind, system_role, custom_role_id, is_default"#,
        )
        .bind(workspace_id)
        .bind(user_id)
        .fetch_optional(tx.as_mut())
        .await
        .map_err(|err| WorkspaceSetDefaultError::Unexpected(err.into()))?;

        let Some(row) = row else {
            tx.rollback().await.ok();
            return Err(WorkspaceSetDefaultError::MembershipNotFound);
        };

        sqlx::query(r#"UPDATE users SET default_workspace_id = $1 WHERE id = $2"#)
            .bind(workspace_id)
            .bind(user_id)
            .execute(tx.as_mut())
            .await
            .map_err(|err| WorkspaceSetDefaultError::Unexpected(err.into()))?;

        tx.commit()
            .await
            .map_err(|err| WorkspaceSetDefaultError::Unexpected(err.into()))?;
        let role_kind_raw: String = row.get("role_kind");
        let system_role_raw: Option<String> = row.try_get("system_role").ok();
        Ok(WorkspaceMemberRow {
            workspace_id: row.get("workspace_id"),
            user_id: row.get("user_id"),
            role_kind: Self::parse_role_kind(&role_kind_raw)
                .map_err(|e| WorkspaceSetDefaultError::Unexpected(e.into()))?,
            system_role: Self::parse_system_role(system_role_raw.as_deref())
                .map_err(|e| WorkspaceSetDefaultError::Unexpected(e.into()))?,
            custom_role_id: row.try_get("custom_role_id").ok(),
            is_default: row.get("is_default"),
        })
    }
    pub(super) async fn list_members_impl(
        &self,
        workspace_id: Uuid,
    ) -> anyhow::Result<Vec<WorkspaceMemberDetail>> {
        let rows = sqlx::query(
            r#"SELECT m.workspace_id,
                      m.user_id,
                      m.role_kind,
                      m.system_role,
                      m.custom_role_id,
                      m.is_default,
                      u.email,
                      u.name
               FROM workspace_members m
               JOIN users u ON u.id = m.user_id
               WHERE m.workspace_id = $1
               ORDER BY u.name"#,
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let role_kind_raw: String = row.get("role_kind");
                let system_role_raw: Option<String> = row.try_get("system_role").ok();
                Ok(WorkspaceMemberDetail {
                    workspace_id: row.get("workspace_id"),
                    user_id: row.get("user_id"),
                    role_kind: Self::parse_role_kind(&role_kind_raw)?,
                    system_role: Self::parse_system_role(system_role_raw.as_deref())?,
                    custom_role_id: row.try_get("custom_role_id").ok(),
                    is_default: row.get("is_default"),
                    user_email: row.get("email"),
                    user_name: row.get("name"),
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?)
    }
    pub(super) async fn get_member_detail_impl(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
    ) -> anyhow::Result<Option<WorkspaceMemberDetail>> {
        let row = sqlx::query(
            r#"SELECT m.workspace_id,
                      m.user_id,
                      m.role_kind,
                      m.system_role,
                      m.custom_role_id,
                      m.is_default,
                      u.email,
                      u.name
               FROM workspace_members m
               JOIN users u ON u.id = m.user_id
               WHERE m.workspace_id = $1 AND m.user_id = $2"#,
        )
        .bind(workspace_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            None => Ok(None),
            Some(row) => {
                let role_kind_raw: String = row.get("role_kind");
                let system_role_raw: Option<String> = row.try_get("system_role").ok();
                Ok(Some(WorkspaceMemberDetail {
                    workspace_id: row.get("workspace_id"),
                    user_id: row.get("user_id"),
                    role_kind: Self::parse_role_kind(&role_kind_raw)?,
                    system_role: Self::parse_system_role(system_role_raw.as_deref())?,
                    custom_role_id: row.try_get("custom_role_id").ok(),
                    is_default: row.get("is_default"),
                    user_email: row.get("email"),
                    user_name: row.get("name"),
                }))
            }
        }
    }
    pub(super) async fn update_member_role_impl(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        role_kind: WorkspaceRoleKind,
        system_role: Option<WorkspaceSystemRole>,
        custom_role_id: Option<Uuid>,
    ) -> anyhow::Result<WorkspaceMemberRow> {
        let row = sqlx::query(
            r#"UPDATE workspace_members
               SET role_kind = $3,
                   system_role = $4,
                   custom_role_id = $5
               WHERE workspace_id = $1 AND user_id = $2
               RETURNING workspace_id, user_id, role_kind, system_role, custom_role_id, is_default"#,
        )
        .bind(workspace_id)
        .bind(user_id)
        .bind(role_kind.as_str())
        .bind(system_role.map(|r| r.as_str()))
        .bind(custom_role_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            bail!("membership_not_found");
        };
        let role_kind_raw: String = row.get("role_kind");
        let system_role_raw: Option<String> = row.try_get("system_role").ok();
        Ok(WorkspaceMemberRow {
            workspace_id: row.get("workspace_id"),
            user_id: row.get("user_id"),
            role_kind: Self::parse_role_kind(&role_kind_raw)?,
            system_role: Self::parse_system_role(system_role_raw.as_deref())?,
            custom_role_id: row.try_get("custom_role_id").ok(),
            is_default: row.get("is_default"),
        })
    }
    pub(super) async fn get_member_with_permissions_impl(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
    ) -> anyhow::Result<Option<WorkspacePermissionRecord>> {
        let rows = sqlx::query(
            r#"SELECT m.workspace_id,
                      m.user_id,
                      m.role_kind,
                      m.system_role,
                      m.custom_role_id,
                      r.base_role,
                      p.permission,
                      p.allowed
               FROM workspace_members m
               LEFT JOIN workspace_roles r ON r.id = m.custom_role_id
               LEFT JOIN workspace_role_permissions p ON p.workspace_role_id = r.id
               WHERE m.workspace_id = $1 AND m.user_id = $2"#,
        )
        .bind(workspace_id)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        if rows.is_empty() {
            return Ok(None);
        }

        let first = &rows[0];
        let role_kind_raw: String = first.get("role_kind");
        let system_role_raw: Option<String> = first.try_get("system_role").ok();
        let custom_base_role_raw: Option<String> = first.try_get("base_role").ok();
        let mut record = WorkspacePermissionRecord {
            workspace_id: first.get("workspace_id"),
            user_id: first.get("user_id"),
            role_kind: Self::parse_role_kind(&role_kind_raw)?,
            system_role: Self::parse_system_role(system_role_raw.as_deref())?,
            custom_role_id: first.try_get("custom_role_id").ok(),
            custom_base_role: match custom_base_role_raw {
                None => None,
                Some(raw) => Some(Self::parse_base_role(&raw)?),
            },
            overrides: Vec::new(),
        };

        for row in rows {
            if let (Some(permission), Some(allowed)) = (
                row.try_get::<Option<String>, _>("permission")
                    .ok()
                    .flatten(),
                row.try_get::<Option<bool>, _>("allowed").ok().flatten(),
            ) {
                record
                    .overrides
                    .push(PermissionOverride::new(permission, allowed));
            }
        }

        Ok(Some(record))
    }
    pub(super) async fn count_system_role_members_impl(
        &self,
        workspace_id: Uuid,
        system_role: WorkspaceSystemRole,
    ) -> anyhow::Result<i64> {
        let count = sqlx::query_scalar(
            r#"SELECT COUNT(1)::BIGINT
               FROM workspace_members
               WHERE workspace_id = $1
                 AND role_kind = 'system'
                 AND system_role = $2"#,
        )
        .bind(workspace_id)
        .bind(system_role.as_str())
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }
    pub(super) async fn delete_member_impl(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            r#"DELETE FROM workspace_members
               WHERE workspace_id = $1 AND user_id = $2"#,
        )
        .bind(workspace_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}
