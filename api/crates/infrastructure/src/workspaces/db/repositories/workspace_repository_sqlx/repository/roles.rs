use super::*;

impl SqlxWorkspaceRepository {
    pub(super) async fn list_roles_impl(
        &self,
        workspace_id: Uuid,
    ) -> anyhow::Result<Vec<WorkspaceRoleRecord>> {
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
    pub(super) async fn create_role_impl(
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
    pub(super) async fn update_role_impl(
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
    pub(super) async fn delete_role_impl(
        &self,
        workspace_id: Uuid,
        role_id: Uuid,
    ) -> anyhow::Result<bool> {
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
    pub(super) async fn get_role_impl(
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
}
