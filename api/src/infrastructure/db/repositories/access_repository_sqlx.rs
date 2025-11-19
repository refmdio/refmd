use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::application::ports::access_repository::{AccessRepository, DocumentUserAccess};
use crate::domain::workspaces::permissions::{
    PermissionSet, apply_custom_overrides, system_role_permissions,
};
use crate::infrastructure::db::PgPool;

pub struct SqlxAccessRepository {
    pub pool: PgPool,
}

impl SqlxAccessRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AccessRepository for SqlxAccessRepository {
    async fn resolve_user_document_access(
        &self,
        doc_id: Uuid,
        user_id: Uuid,
    ) -> anyhow::Result<Option<DocumentUserAccess>> {
        let rows = sqlx::query(
            r#"SELECT d.workspace_id,
                      d.archived_at,
                      m.role_kind,
                      m.system_role,
                      m.custom_role_id,
                      r.base_role AS custom_base_role,
                      p.permission,
                      p.allowed
               FROM documents d
               JOIN workspace_members m
                 ON m.workspace_id = d.workspace_id
                AND m.user_id = $2
               LEFT JOIN workspace_roles r ON r.id = m.custom_role_id
               LEFT JOIN workspace_role_permissions p ON p.workspace_role_id = r.id
               WHERE d.id = $1"#,
        )
        .bind(doc_id)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        if rows.is_empty() {
            return Ok(None);
        }

        let first = &rows[0];
        let workspace_id = first.get("workspace_id");
        let archived = first
            .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("archived_at")
            .ok()
            .flatten()
            .is_some();

        let role_kind: String = first.get("role_kind");
        let system_role = first
            .try_get::<Option<String>, _>("system_role")
            .ok()
            .flatten();
        let custom_base_role = first
            .try_get::<Option<String>, _>("custom_base_role")
            .ok()
            .flatten();

        let mut overrides = Vec::new();
        for row in rows {
            if let (Some(permission), Some(allowed)) = (
                row.try_get::<Option<String>, _>("permission")
                    .ok()
                    .flatten(),
                row.try_get::<Option<bool>, _>("allowed").ok().flatten(),
            ) {
                overrides.push((permission, allowed));
            }
        }

        let permissions = build_permission_set(
            &role_kind,
            system_role.as_deref(),
            custom_base_role.as_deref(),
            overrides,
        );

        Ok(Some(DocumentUserAccess {
            workspace_id,
            is_archived: archived,
            permissions,
        }))
    }

    async fn is_document_public(&self, doc_id: Uuid) -> anyhow::Result<bool> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(1) FROM public_documents WHERE document_id = $1",
        )
        .bind(doc_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(count > 0)
    }

    async fn is_document_archived(&self, doc_id: Uuid) -> anyhow::Result<bool> {
        let archived = sqlx::query_scalar::<_, bool>(
            "SELECT archived_at IS NOT NULL FROM documents WHERE id = $1",
        )
        .bind(doc_id)
        .fetch_optional(&self.pool)
        .await?
        .unwrap_or(false);
        Ok(archived)
    }
}

fn build_permission_set(
    role_kind: &str,
    system_role: Option<&str>,
    custom_base_role: Option<&str>,
    overrides: Vec<(String, bool)>,
) -> PermissionSet {
    let set = match role_kind {
        "system" => {
            let role = system_role.unwrap_or("viewer");
            system_role_permissions(role)
        }
        "custom" => {
            let base = custom_base_role.unwrap_or("viewer");
            system_role_permissions(base)
        }
        _ => system_role_permissions("viewer"),
    };
    if overrides.is_empty() {
        set
    } else {
        apply_custom_overrides(set, overrides)
    }
}
