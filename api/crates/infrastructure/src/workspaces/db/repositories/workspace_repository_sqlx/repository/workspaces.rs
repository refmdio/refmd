use super::*;

impl SqlxWorkspaceRepository {
    pub(super) async fn list_for_user_impl(
        &self,
        user_id: Uuid,
    ) -> anyhow::Result<Vec<WorkspaceListItem>> {
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
    pub(super) async fn create_workspace_impl(
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
    pub(super) async fn get_workspace_impl(
        &self,
        workspace_id: Uuid,
    ) -> anyhow::Result<Option<WorkspaceRow>> {
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
    pub(super) async fn create_workspace_with_id_impl(
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
    pub(super) async fn update_workspace_impl(
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
    pub(super) async fn delete_workspace_impl(&self, workspace_id: Uuid) -> anyhow::Result<bool> {
        let result = sqlx::query("DELETE FROM workspaces WHERE id = $1")
            .bind(workspace_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
    pub(super) async fn list_all_workspace_ids_impl(&self) -> anyhow::Result<Vec<Uuid>> {
        let rows = sqlx::query("SELECT id FROM workspaces ORDER BY created_at")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|row| row.get("id")).collect())
    }
}
