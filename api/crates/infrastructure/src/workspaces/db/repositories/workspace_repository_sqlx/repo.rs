use anyhow::bail;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use application::workspaces::ports::workspace_repository::{
    WorkspaceInvitationRecord, WorkspaceListItem, WorkspaceMemberDetail, WorkspaceMemberRow,
    WorkspacePermissionRecord, WorkspaceRepository, WorkspaceRoleRecord, WorkspaceRow,
    WorkspaceSetDefaultError,
};
use domain::workspaces::permissions::PermissionOverride;
use domain::workspaces::roles::{WorkspaceBaseRole, WorkspaceRoleKind, WorkspaceSystemRole};

use super::SqlxWorkspaceRepository;
#[async_trait]
impl WorkspaceRepository for SqlxWorkspaceRepository {
    async fn list_for_user(&self, user_id: Uuid) -> anyhow::Result<Vec<WorkspaceListItem>> {
        let rows = sqlx::query(
            r#"SELECT w.id,
                      w.name,
                      w.slug,
                      w.icon,
                      w.description,
                      w.is_personal,
                      m.role_kind,
                      m.system_role,
                      m.custom_role_id,
                      m.is_default
                FROM workspace_members m
                JOIN workspaces w ON w.id = m.workspace_id
               WHERE m.user_id = $1
               ORDER BY w.created_at"#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| {
                let role_kind_raw: String = r.get("role_kind");
                let system_role_raw: Option<String> = r.try_get("system_role").ok();
                Ok(WorkspaceListItem {
                    id: r.get("id"),
                    name: r.get("name"),
                    slug: r.get("slug"),
                    icon: r.try_get("icon").ok(),
                    description: r.try_get("description").ok(),
                    is_personal: r.get("is_personal"),
                    role_kind: Self::parse_role_kind(&role_kind_raw)?,
                    system_role: Self::parse_system_role(system_role_raw.as_deref())?,
                    custom_role_id: r.try_get("custom_role_id").ok(),
                    is_default: r.get("is_default"),
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()
    }

    async fn create_workspace(
        &self,
        creator_id: Uuid,
        name: &str,
        slug: &str,
        icon: Option<&str>,
        description: Option<&str>,
        is_personal: bool,
    ) -> anyhow::Result<WorkspaceRow> {
        let row = sqlx::query(
            r#"INSERT INTO workspaces (id, name, slug, icon, description, created_by, is_personal)
               VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6)
               RETURNING id, name, slug, icon, description, is_personal"#,
        )
        .bind(name)
        .bind(slug)
        .bind(icon)
        .bind(description)
        .bind(creator_id)
        .bind(is_personal)
        .fetch_one(&self.pool)
        .await?;
        Ok(WorkspaceRow {
            id: row.get("id"),
            name: row.get("name"),
            slug: row.get("slug"),
            icon: row.try_get("icon").ok(),
            description: row.try_get("description").ok(),
            is_personal: row.get("is_personal"),
        })
    }

    async fn get_workspace(&self, workspace_id: Uuid) -> anyhow::Result<Option<WorkspaceRow>> {
        let row = sqlx::query(
            r#"SELECT id, name, slug, icon, description, is_personal
               FROM workspaces
               WHERE id = $1"#,
        )
        .bind(workspace_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| WorkspaceRow {
            id: row.get("id"),
            name: row.get("name"),
            slug: row.get("slug"),
            icon: row.try_get("icon").ok(),
            description: row.try_get("description").ok(),
            is_personal: row.get("is_personal"),
        }))
    }

    async fn create_workspace_with_id(
        &self,
        workspace_id: Uuid,
        created_by: Option<Uuid>,
        name: &str,
        slug: &str,
        icon: Option<&str>,
        description: Option<&str>,
        is_personal: bool,
    ) -> anyhow::Result<WorkspaceRow> {
        let row = sqlx::query(
            r#"INSERT INTO workspaces (id, name, slug, icon, description, created_by, is_personal)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               RETURNING id, name, slug, icon, description, is_personal"#,
        )
        .bind(workspace_id)
        .bind(name)
        .bind(slug)
        .bind(icon)
        .bind(description)
        .bind(created_by)
        .bind(is_personal)
        .fetch_one(&self.pool)
        .await?;
        Ok(WorkspaceRow {
            id: row.get("id"),
            name: row.get("name"),
            slug: row.get("slug"),
            icon: row.try_get("icon").ok(),
            description: row.try_get("description").ok(),
            is_personal: row.get("is_personal"),
        })
    }

    async fn add_member(
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

    async fn set_default_workspace(
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

    async fn list_members(&self, workspace_id: Uuid) -> anyhow::Result<Vec<WorkspaceMemberDetail>> {
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

    async fn get_member_detail(
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

    async fn update_member_role(
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

    async fn get_member_with_permissions(
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

    async fn count_system_role_members(
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

    async fn list_roles(&self, workspace_id: Uuid) -> anyhow::Result<Vec<WorkspaceRoleRecord>> {
        let rows = sqlx::query(
            r#"SELECT r.id,
                      r.workspace_id,
                      r.name,
                      r.description,
                      r.base_role,
                      r.priority,
                      p.permission,
                      p.allowed
               FROM workspace_roles r
               LEFT JOIN workspace_role_permissions p ON p.workspace_role_id = r.id
               WHERE r.workspace_id = $1
               ORDER BY r.priority, r.created_at"#,
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await?;
        self.collect_roles(rows)
    }

    async fn create_role(
        &self,
        workspace_id: Uuid,
        name: &str,
        base_role: WorkspaceBaseRole,
        description: Option<&str>,
        priority: i32,
        overrides: &[PermissionOverride],
    ) -> anyhow::Result<WorkspaceRoleRecord> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            r#"INSERT INTO workspace_roles (workspace_id, name, base_role, description, priority)
               VALUES ($1, $2, $3, $4, $5)
               RETURNING id, workspace_id, name, description, base_role, priority"#,
        )
        .bind(workspace_id)
        .bind(name)
        .bind(base_role.as_str())
        .bind(description)
        .bind(priority)
        .fetch_one(tx.as_mut())
        .await?;
        let role_id: Uuid = row.get("id");
        self.replace_role_permissions_tx(tx.as_mut(), role_id, overrides)
            .await?;
        tx.commit().await?;
        Ok(WorkspaceRoleRecord {
            id: role_id,
            workspace_id: row.get("workspace_id"),
            name: row.get("name"),
            description: row.try_get("description").ok(),
            base_role,
            priority: row.get("priority"),
            overrides: overrides.to_vec(),
        })
    }

    async fn update_role(
        &self,
        workspace_id: Uuid,
        role_id: Uuid,
        name: Option<&str>,
        base_role: Option<WorkspaceBaseRole>,
        description: Option<&str>,
        priority: Option<i32>,
        overrides: Option<&[PermissionOverride]>,
    ) -> anyhow::Result<WorkspaceRoleRecord> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            r#"UPDATE workspace_roles
               SET name = COALESCE($3, name),
                   base_role = COALESCE($4, base_role),
                   description = COALESCE($5, description),
                   priority = COALESCE($6, priority)
               WHERE id = $2 AND workspace_id = $1
               RETURNING id, workspace_id, name, description, base_role, priority"#,
        )
        .bind(workspace_id)
        .bind(role_id)
        .bind(name)
        .bind(base_role.map(|b| b.as_str()))
        .bind(description)
        .bind(priority)
        .fetch_optional(tx.as_mut())
        .await?;
        let Some(row) = row else {
            bail!("role_not_found");
        };
        if let Some(overrides) = overrides {
            self.replace_role_permissions_tx(tx.as_mut(), role_id, overrides)
                .await?;
        }
        tx.commit().await?;
        let overrides_vec = if let Some(overrides) = overrides {
            overrides.to_vec()
        } else {
            self.fetch_role_overrides(role_id).await?
        };
        Ok(WorkspaceRoleRecord {
            id: row.get("id"),
            workspace_id: row.get("workspace_id"),
            name: row.get("name"),
            description: row.try_get("description").ok(),
            base_role: Self::parse_base_role(&row.get::<String, _>("base_role"))?,
            priority: row.get("priority"),
            overrides: overrides_vec,
        })
    }

    async fn delete_role(&self, workspace_id: Uuid, role_id: Uuid) -> anyhow::Result<bool> {
        let result = sqlx::query(
            r#"DELETE FROM workspace_roles
               WHERE id = $1 AND workspace_id = $2"#,
        )
        .bind(role_id)
        .bind(workspace_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_workspace(&self, workspace_id: Uuid) -> anyhow::Result<bool> {
        let result = sqlx::query("DELETE FROM workspaces WHERE id = $1")
            .bind(workspace_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn get_role(
        &self,
        workspace_id: Uuid,
        role_id: Uuid,
    ) -> anyhow::Result<Option<WorkspaceRoleRecord>> {
        let rows = sqlx::query(
            r#"SELECT r.id,
                      r.workspace_id,
                      r.name,
                      r.description,
                      r.base_role,
                      r.priority,
                      p.permission,
                      p.allowed
               FROM workspace_roles r
               LEFT JOIN workspace_role_permissions p ON p.workspace_role_id = r.id
               WHERE r.workspace_id = $1 AND r.id = $2"#,
        )
        .bind(workspace_id)
        .bind(role_id)
        .fetch_all(&self.pool)
        .await?;
        let mut roles = self.collect_roles(rows)?;
        Ok(roles.pop())
    }

    async fn delete_member(&self, workspace_id: Uuid, user_id: Uuid) -> anyhow::Result<bool> {
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

    async fn update_workspace(
        &self,
        workspace_id: Uuid,
        name: Option<&str>,
        icon: Option<&str>,
        description: Option<&str>,
    ) -> anyhow::Result<Option<WorkspaceRow>> {
        let row = sqlx::query(
            r#"UPDATE workspaces
               SET name = COALESCE($2, name),
                   icon = COALESCE($3, icon),
                   description = COALESCE($4, description),
                   updated_at = now()
               WHERE id = $1
               RETURNING id, name, slug, icon, description, is_personal"#,
        )
        .bind(workspace_id)
        .bind(name)
        .bind(icon)
        .bind(description)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| WorkspaceRow {
            id: row.get("id"),
            name: row.get("name"),
            slug: row.get("slug"),
            icon: row.try_get("icon").ok(),
            description: row.try_get("description").ok(),
            is_personal: row.get("is_personal"),
        }))
    }

    async fn create_invitation(
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
                          created_at"#,
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

    async fn list_invitations(
        &self,
        workspace_id: Uuid,
    ) -> anyhow::Result<Vec<WorkspaceInvitationRecord>> {
        let rows = sqlx::query(
            r#"SELECT id, workspace_id, email, role_kind, system_role, custom_role_id,
                      invited_by, token, expires_at, accepted_by, accepted_at, revoked_at,
                      created_at
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

    async fn accept_invitation(
        &self,
        token: &str,
        user_id: Uuid,
        user_email: &str,
    ) -> anyhow::Result<WorkspaceInvitationRecord> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            r#"SELECT id, workspace_id, email, role_kind, system_role, custom_role_id,
                      invited_by, token, expires_at, accepted_by, accepted_at, revoked_at,
                      created_at
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

    async fn revoke_invitation(
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
                             created_at"#,
        )
        .bind(invitation_id)
        .bind(workspace_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| self.map_invitation_row(&row)).transpose()
    }

    async fn list_all_workspace_ids(&self) -> anyhow::Result<Vec<Uuid>> {
        let rows = sqlx::query("SELECT id FROM workspaces ORDER BY created_at")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|row| row.get("id")).collect())
    }
}
