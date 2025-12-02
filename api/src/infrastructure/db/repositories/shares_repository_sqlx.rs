use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::application::ports::share_access_port::ShareAccessPort;
use crate::application::ports::shares_repository::{ShareMountRow, ShareRow, SharesRepository};
use crate::infrastructure::db::PgPool;

pub struct SqlxSharesRepository {
    pub pool: PgPool,
}

impl SqlxSharesRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn fetch_share_resolution(
        &self,
        token: &str,
    ) -> anyhow::Result<
        Option<(
            Uuid,
            String,
            Option<chrono::DateTime<chrono::Utc>>,
            Uuid,
            String,
        )>,
    > {
        let row = sqlx::query(
            r#"SELECT s.id as share_id, s.permission, s.expires_at, d.id as shared_id, d.type as shared_type
               FROM shares s
               JOIN documents d ON s.document_id = d.id
               WHERE s.token = $1"#,
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| {
            (
                r.get("share_id"),
                r.get("permission"),
                r.try_get("expires_at").ok(),
                r.get("shared_id"),
                r.get("shared_type"),
            )
        }))
    }
}

#[async_trait]
impl SharesRepository for SqlxSharesRepository {
    async fn create_share(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        document_id: Uuid,
        permission: &str,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> anyhow::Result<(String, Uuid, String)> {
        // Verify ownership and type
        let dtype: String =
            sqlx::query_scalar("SELECT type FROM documents WHERE id = $1 AND workspace_id = $2")
                .bind(document_id)
                .bind(workspace_id)
                .fetch_optional(&self.pool)
                .await?
                .ok_or_else(|| anyhow::anyhow!("forbidden"))?;
        let token = Uuid::new_v4().to_string();
        let row = sqlx::query("INSERT INTO shares (document_id, token, permission, created_by, expires_at) VALUES ($1, $2, $3, $4, $5) RETURNING id, token")
            .bind(document_id)
            .bind(&token)
            .bind(permission)
            .bind(actor_id)
            .bind(expires_at)
            .fetch_one(&self.pool)
            .await?;
        let token_saved: String = row.get("token");
        let share_id: Uuid = row.get("id");
        if dtype == "folder" {
            // Materialize per-document shares for folder subtree
            let _created: i64 = sqlx::query_scalar(
                r#"
                WITH RECURSIVE subtree AS (
                  SELECT id, type FROM documents WHERE id = $1
                  UNION ALL
                  SELECT d.id, d.type FROM documents d JOIN subtree sb ON d.parent_id = sb.id
                ),
                targets AS (
                  SELECT id FROM subtree WHERE type <> 'folder'
                ),
                inserted AS (
                  INSERT INTO shares (document_id, token, permission, created_by, expires_at, parent_share_id)
                  SELECT t.id, gen_random_uuid()::text, $2, $3, $4, $5
                  FROM targets t
                  WHERE NOT EXISTS (SELECT 1 FROM shares s2 WHERE s2.document_id = t.id AND s2.created_by = $3)
                  RETURNING 1
                )
                SELECT COALESCE(COUNT(*),0) FROM inserted
                "#
            )
            .bind(document_id)
            .bind(permission)
            .bind(actor_id)
            .bind(expires_at)
            .bind(share_id)
            .fetch_one(&self.pool)
            .await?;
        }
        Ok((token_saved, share_id, dtype))
    }

    async fn list_document_shares(
        &self,
        workspace_id: Uuid,
        document_id: Uuid,
    ) -> anyhow::Result<Vec<ShareRow>> {
        let rows = sqlx::query(
            r#"SELECT s.id, s.token, s.permission, s.expires_at, s.parent_share_id, s.created_at,
                      d.id as document_id, d.title as document_title, d.type as document_type
               FROM shares s JOIN documents d ON d.id = s.document_id
               WHERE s.document_id = $1 AND d.workspace_id = $2
               ORDER BY s.created_at DESC"#,
        )
        .bind(document_id)
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows.into_iter() {
            out.push(ShareRow {
                id: r.get("id"),
                token: r.get("token"),
                permission: r.get("permission"),
                expires_at: r.try_get("expires_at").ok(),
                parent_share_id: r.try_get("parent_share_id").ok(),
                document_id: r.get("document_id"),
                document_type: r.get("document_type"),
                document_title: r.get("document_title"),
                created_at: r.get("created_at"),
            });
        }
        Ok(out)
    }

    async fn delete_share(&self, workspace_id: Uuid, token: &str) -> anyhow::Result<bool> {
        let res = sqlx::query(
            "DELETE FROM shares s USING documents d WHERE s.token = $1 AND s.document_id = d.id AND d.workspace_id = $2",
        )
            .bind(token)
            .bind(workspace_id)
            .execute(&self.pool)
            .await?;
        let deleted = res.rows_affected() > 0;
        if deleted {
            // Remove any saved mounts referencing this share token across workspaces
            sqlx::query("DELETE FROM share_mounts WHERE share_token = $1")
                .bind(token)
                .execute(&self.pool)
                .await?;
        }
        Ok(deleted)
    }

    async fn list_share_mounts(&self, workspace_id: Uuid) -> anyhow::Result<Vec<ShareMountRow>> {
        // Clean up mounts whose share token no longer exists or has expired
        sqlx::query(
            r#"
            DELETE FROM share_mounts sm
            WHERE sm.workspace_id = $1
              AND NOT EXISTS (
                SELECT 1
                FROM shares s
                WHERE s.token = sm.share_token
                  AND (s.expires_at IS NULL OR s.expires_at > now())
              )
            "#,
        )
        .bind(workspace_id)
        .execute(&self.pool)
        .await?;

        let rows = sqlx::query(
            r#"SELECT id, share_token, target_document_id, target_document_type, target_title, permission, parent_folder_id, created_at
               FROM share_mounts
               WHERE workspace_id = $1
               ORDER BY created_at DESC"#,
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows.into_iter() {
            out.push(ShareMountRow {
                id: r.get("id"),
                token: r.get("share_token"),
                target_document_id: r.get("target_document_id"),
                target_document_type: r.get("target_document_type"),
                target_title: r.get("target_title"),
                permission: r.get("permission"),
                parent_folder_id: r.try_get("parent_folder_id").ok(),
                created_at: r.get("created_at"),
            });
        }
        Ok(out)
    }

    async fn create_share_mount(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        token: &str,
        target_document_id: Uuid,
        target_document_type: &str,
        target_title: &str,
        permission: &str,
        parent_folder_id: Option<Uuid>,
    ) -> anyhow::Result<ShareMountRow> {
        if let Some(parent_id) = parent_folder_id {
            let exists = sqlx::query_scalar::<_, i64>(
                "SELECT 1 FROM documents WHERE id = $1 AND workspace_id = $2 AND type = 'folder'",
            )
            .bind(parent_id)
            .bind(workspace_id)
            .fetch_optional(&self.pool)
            .await?;
            if exists.is_none() {
                anyhow::bail!("invalid_parent");
            }
        }
        let row = sqlx::query(
            r#"
            INSERT INTO share_mounts (workspace_id, created_by, share_token, target_document_id, target_document_type, target_title, permission, parent_folder_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (workspace_id, share_token, target_document_id)
            DO UPDATE SET target_title = EXCLUDED.target_title,
                          permission = EXCLUDED.permission,
                          parent_folder_id = EXCLUDED.parent_folder_id
            RETURNING id, share_token, target_document_id, target_document_type, target_title, permission, parent_folder_id, created_at
            "#,
        )
        .bind(workspace_id)
        .bind(actor_id)
        .bind(token)
        .bind(target_document_id)
        .bind(target_document_type)
        .bind(target_title)
        .bind(permission)
        .bind(parent_folder_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(ShareMountRow {
            id: row.get("id"),
            token: row.get("share_token"),
            target_document_id: row.get("target_document_id"),
            target_document_type: row.get("target_document_type"),
            target_title: row.get("target_title"),
            permission: row.get("permission"),
            parent_folder_id: row.try_get("parent_folder_id").ok(),
            created_at: row.get("created_at"),
        })
    }

    async fn delete_share_mount(&self, workspace_id: Uuid, mount_id: Uuid) -> anyhow::Result<bool> {
        let res = sqlx::query("DELETE FROM share_mounts WHERE id = $1 AND workspace_id = $2")
            .bind(mount_id)
            .bind(workspace_id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn validate_share_token(
        &self,
        token: &str,
    ) -> anyhow::Result<Option<(Uuid, String, Option<chrono::DateTime<chrono::Utc>>, String)>> {
        let row = sqlx::query(
            r#"SELECT s.document_id, s.permission, s.expires_at, d.title
               FROM shares s JOIN documents d ON d.id = s.document_id
               WHERE s.token = $1"#,
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| {
            (
                r.get("document_id"),
                r.get("permission"),
                r.try_get("expires_at").ok(),
                r.get("title"),
            )
        }))
    }

    async fn list_applicable_shares_for_doc(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
    ) -> anyhow::Result<Vec<(String, String, Option<chrono::DateTime<chrono::Utc>>)>> {
        let rows = sqlx::query(
            r#"SELECT s.token, s.permission, s.expires_at
               FROM shares s
               JOIN documents d ON d.id = s.document_id
               WHERE s.document_id = $1 AND d.workspace_id = $2"#,
        )
        .bind(doc_id)
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get("token"),
                    r.get("permission"),
                    r.try_get("expires_at").ok(),
                )
            })
            .collect())
    }

    async fn list_active_shares(&self, workspace_id: Uuid) -> anyhow::Result<Vec<ShareRow>> {
        let rows = sqlx::query(
            r#"SELECT s.id, s.token, s.permission, s.expires_at, s.created_at, s.parent_share_id,
                      d.id as document_id, d.title as document_title, d.type as document_type
               FROM shares s
               JOIN documents d ON d.id = s.document_id
               WHERE d.workspace_id = $1 AND (s.expires_at IS NULL OR s.expires_at > now())
               ORDER BY s.created_at DESC"#,
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows.into_iter() {
            out.push(ShareRow {
                id: r.get("id"),
                token: r.get("token"),
                permission: r.get("permission"),
                expires_at: r.try_get("expires_at").ok(),
                parent_share_id: r.try_get("parent_share_id").ok(),
                document_id: r.get("document_id"),
                document_type: r.get("document_type"),
                document_title: r.get("document_title"),
                created_at: r.get("created_at"),
            });
        }
        Ok(out)
    }

    async fn resolve_share_by_token(
        &self,
        token: &str,
    ) -> anyhow::Result<
        Option<(
            Uuid,
            String,
            Option<chrono::DateTime<chrono::Utc>>,
            Uuid,
            String,
        )>,
    > {
        self.fetch_share_resolution(token).await
    }

    async fn get_share_document_meta(
        &self,
        token: &str,
    ) -> anyhow::Result<Option<(Uuid, Uuid, Uuid)>> {
        let row = sqlx::query(
            "SELECT d.id as document_id, d.owner_id, d.workspace_id FROM shares s JOIN documents d ON d.id = s.document_id WHERE s.token = $1",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| {
            (
                r.get("document_id"),
                r.get("owner_id"),
                r.get("workspace_id"),
            )
        }))
    }

    async fn list_subtree_nodes(
        &self,
        root_id: Uuid,
    ) -> anyhow::Result<
        Vec<(
            Uuid,
            String,
            String,
            Option<Uuid>,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        )>,
    > {
        let rows = sqlx::query(
            r#"
            WITH RECURSIVE subtree AS (
                SELECT id, title, type, parent_id, created_at, updated_at FROM documents WHERE id = $1
                UNION ALL
                SELECT d.id, d.title, d.type, d.parent_id, d.created_at, d.updated_at
                FROM documents d JOIN subtree s ON d.parent_id = s.id
            )
            SELECT id, title, type, parent_id, created_at, updated_at FROM subtree
            "#
        )
        .bind(root_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get("id"),
                    r.get("title"),
                    r.get("type"),
                    r.try_get("parent_id").ok(),
                    r.get("created_at"),
                    r.get("updated_at"),
                )
            })
            .collect())
    }

    async fn list_materialized_children(&self, parent_share_id: Uuid) -> anyhow::Result<Vec<Uuid>> {
        let ids = sqlx::query_scalar("SELECT document_id FROM shares WHERE parent_share_id = $1 AND (expires_at IS NULL OR expires_at > now())")
            .bind(parent_share_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(ids)
    }

    async fn materialize_folder_share(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        token: &str,
    ) -> anyhow::Result<i64> {
        let row = sqlx::query(
            r#"SELECT s.id as share_id, s.permission, s.expires_at, d.id as folder_id, d.workspace_id, d.type
               FROM shares s JOIN documents d ON d.id = s.document_id
               WHERE s.token = $1"#
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        let row = match row {
            Some(r) => r,
            None => anyhow::bail!("not_found"),
        };
        let workspace: Uuid = row.get("workspace_id");
        if workspace != workspace_id {
            anyhow::bail!("forbidden");
        }
        let dtype: String = row.get("type");
        if dtype != "folder" {
            anyhow::bail!("bad_request");
        }
        let folder_id: Uuid = row.get("folder_id");
        let share_id: Uuid = row.get("share_id");
        let permission: String = row.get("permission");
        let expires_at: Option<chrono::DateTime<chrono::Utc>> = row.try_get("expires_at").ok();

        let created = sqlx::query_scalar::<_, i64>(
            r#"
            WITH RECURSIVE subtree AS (
              SELECT id, type FROM documents WHERE id = $1
              UNION ALL
              SELECT d.id, d.type FROM documents d JOIN subtree sb ON d.parent_id = sb.id
            ),
            targets AS (
              SELECT id FROM subtree WHERE type <> 'folder'
            ),
            inserted AS (
              INSERT INTO shares (document_id, token, permission, created_by, expires_at, parent_share_id)
              SELECT t.id, gen_random_uuid()::text, $3, $4, $5, $2
              FROM targets t
              WHERE NOT EXISTS (SELECT 1 FROM shares s2 WHERE s2.document_id = t.id AND s2.created_by = $4)
              RETURNING 1
            )
            SELECT COALESCE(COUNT(*),0) FROM inserted
            "#
        )
        .bind(folder_id)
        .bind(share_id)
        .bind(&permission)
        .bind(actor_id)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await?;
        Ok(created)
    }

    async fn revoke_subtree_shares(
        &self,
        workspace_id: Uuid,
        root_id: Uuid,
    ) -> anyhow::Result<i64> {
        let deleted = sqlx::query_scalar::<_, i64>(
            r#"
            WITH RECURSIVE subtree AS (
                SELECT id FROM documents WHERE id = $1 AND workspace_id = $2
                UNION ALL
                SELECT d.id
                FROM documents d
                JOIN subtree sb ON d.parent_id = sb.id
                WHERE d.workspace_id = $2
            ),
            removed AS (
                DELETE FROM shares s
                USING subtree sb
                WHERE s.document_id = sb.id
                  AND s.created_by = $2
                RETURNING 1
            )
            SELECT COALESCE(COUNT(*), 0) FROM removed
            "#,
        )
        .bind(root_id)
        .bind(workspace_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(deleted)
    }
}

#[async_trait]
impl ShareAccessPort for SqlxSharesRepository {
    async fn resolve_share_by_token(
        &self,
        token: &str,
    ) -> anyhow::Result<
        Option<(
            Uuid,
            String,
            Option<chrono::DateTime<chrono::Utc>>,
            Uuid,
            String,
        )>,
    > {
        self.fetch_share_resolution(token).await
    }

    async fn get_materialized_permission(
        &self,
        parent_share_id: Uuid,
        doc_id: Uuid,
    ) -> anyhow::Result<Option<String>> {
        let perm = sqlx::query_scalar::<_, String>(
            "SELECT permission FROM shares WHERE parent_share_id = $1 AND document_id = $2 AND (expires_at IS NULL OR expires_at > now())",
        )
        .bind(parent_share_id)
        .bind(doc_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(perm)
    }
}
