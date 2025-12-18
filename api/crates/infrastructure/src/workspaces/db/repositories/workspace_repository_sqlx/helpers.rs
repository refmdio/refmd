use std::collections::HashMap;

use anyhow::Context;
use chrono::{DateTime, Utc};
use sqlx::{PgConnection, Row, postgres::PgRow};
use uuid::Uuid;

use application::workspaces::ports::workspace_repository::{
    WorkspaceInvitationRecord, WorkspaceRoleRecord,
};
use domain::workspaces::permissions::PermissionOverride;
use domain::workspaces::roles::{WorkspaceBaseRole, WorkspaceRoleKind, WorkspaceSystemRole};

use super::SqlxWorkspaceRepository;

impl SqlxWorkspaceRepository {
    pub(super) fn collect_roles(
        &self,
        rows: Vec<PgRow>,
    ) -> anyhow::Result<Vec<WorkspaceRoleRecord>> {
        let mut map: HashMap<Uuid, WorkspaceRoleRecord> = HashMap::new();
        for row in rows {
            let role_id: Uuid = row.get("id");
            let base_role_raw: String = row.get("base_role");
            let entry = map.entry(role_id).or_insert_with(|| WorkspaceRoleRecord {
                id: role_id,
                workspace_id: row.get("workspace_id"),
                name: row.get("name"),
                description: row.try_get("description").ok(),
                base_role: WorkspaceBaseRole::Viewer,
                priority: row.get("priority"),
                overrides: Vec::new(),
            });
            entry.base_role = Self::parse_base_role(&base_role_raw).with_context(|| {
                format!("invalid workspace_roles.base_role for role_id={role_id}")
            })?;
            if let (Some(permission), Some(allowed)) = (
                row.try_get::<Option<String>, _>("permission")
                    .ok()
                    .flatten(),
                row.try_get::<Option<bool>, _>("allowed").ok().flatten(),
            ) {
                entry
                    .overrides
                    .push(PermissionOverride::new(permission, allowed));
            }
        }
        Ok(map
            .into_values()
            .map(|mut record| {
                record
                    .overrides
                    .sort_by(|a, b| a.permission.cmp(&b.permission));
                record
            })
            .collect())
    }

    pub(super) async fn replace_role_permissions_tx(
        &self,
        tx: &mut PgConnection,
        role_id: Uuid,
        overrides: &[PermissionOverride],
    ) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM workspace_role_permissions WHERE workspace_role_id = $1")
            .bind(role_id)
            .execute(&mut *tx)
            .await?;
        for item in overrides {
            sqlx::query(
                r#"INSERT INTO workspace_role_permissions (workspace_role_id, permission, allowed)
                   VALUES ($1, $2, $3)"#,
            )
            .bind(role_id)
            .bind(item.permission.as_str())
            .bind(item.allowed)
            .execute(&mut *tx)
            .await?;
        }
        Ok(())
    }

    pub(super) async fn fetch_role_overrides(
        &self,
        role_id: Uuid,
    ) -> anyhow::Result<Vec<PermissionOverride>> {
        let rows = sqlx::query(
            r#"SELECT permission, allowed
               FROM workspace_role_permissions
               WHERE workspace_role_id = $1"#,
        )
        .bind(role_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .filter_map(|row| {
                row.try_get::<Option<String>, _>("permission")
                    .ok()
                    .flatten()
                    .map(|perm| PermissionOverride::new(perm, row.get("allowed")))
            })
            .collect())
    }

    pub(super) fn map_invitation_row(
        &self,
        row: &PgRow,
    ) -> anyhow::Result<WorkspaceInvitationRecord> {
        let role_kind_raw: String = row.get("role_kind");
        let system_role_raw: Option<String> = row.try_get("system_role").ok();
        Ok(WorkspaceInvitationRecord {
            id: row.get("id"),
            workspace_id: row.get("workspace_id"),
            email: row.get("email"),
            role_kind: Self::parse_role_kind(&role_kind_raw)?,
            system_role: Self::parse_system_role(system_role_raw.as_deref())?,
            custom_role_id: row.try_get("custom_role_id").ok().flatten(),
            invited_by: row.get("invited_by"),
            token: row.get("token"),
            expires_at: row
                .try_get::<Option<DateTime<Utc>>, _>("expires_at")
                .ok()
                .flatten(),
            accepted_by: row.try_get("accepted_by").ok().flatten(),
            accepted_at: row
                .try_get::<Option<DateTime<Utc>>, _>("accepted_at")
                .ok()
                .flatten(),
            revoked_at: row
                .try_get::<Option<DateTime<Utc>>, _>("revoked_at")
                .ok()
                .flatten(),
            created_at: row.get("created_at"),
        })
    }

    pub(super) fn parse_role_kind(raw: &str) -> anyhow::Result<WorkspaceRoleKind> {
        WorkspaceRoleKind::from_str(raw).ok_or_else(|| anyhow::anyhow!("invalid_role_kind"))
    }

    pub(super) fn parse_system_role(
        raw: Option<&str>,
    ) -> anyhow::Result<Option<WorkspaceSystemRole>> {
        let Some(raw) = raw else {
            return Ok(None);
        };
        WorkspaceSystemRole::from_str(raw)
            .ok_or_else(|| anyhow::anyhow!("invalid_system_role"))
            .map(Some)
    }

    pub(super) fn parse_base_role(raw: &str) -> anyhow::Result<WorkspaceBaseRole> {
        WorkspaceBaseRole::from_str(raw).ok_or_else(|| anyhow::anyhow!("invalid_base_role"))
    }
}
