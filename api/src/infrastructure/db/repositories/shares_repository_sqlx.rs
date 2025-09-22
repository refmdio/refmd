use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::application::ports::share_access_port::ShareAccessPort;
use crate::application::ports::shares_repository::{ShareRow, SharesRepository};
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
        owner_id: Uuid,
        document_id: Uuid,
        permission: &str,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> anyhow::Result<(String, Uuid, String)> {
        // Verify ownership and type
        let dtype: String =
            sqlx::query_scalar("SELECT type FROM documents WHERE id = $1 AND owner_id = $2")
                .bind(document_id)
                .bind(owner_id)
                .fetch_optional(&self.pool)
                .await?
                .ok_or_else(|| anyhow::anyhow!("forbidden"))?;
        let token = Uuid::new_v4().to_string();
        let row = sqlx::query("INSERT INTO shares (document_id, token, permission, created_by, expires_at) VALUES ($1, $2, $3, $4, $5) RETURNING id, token")
            .bind(document_id)
            .bind(&token)
            .bind(permission)
            .bind(owner_id)
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
            .bind(owner_id)
            .bind(expires_at)
            .bind(share_id)
            .fetch_one(&self.pool)
            .await?;
        }
        Ok((token_saved, share_id, dtype))
    }

    async fn list_document_shares(
        &self,
        owner_id: Uuid,
        document_id: Uuid,
    ) -> anyhow::Result<Vec<ShareRow>> {
        let rows = sqlx::query(
            r#"SELECT s.id, s.token, s.permission, s.expires_at, s.parent_share_id, s.created_at,
                      d.id as document_id, d.title as document_title, d.type as document_type
               FROM shares s JOIN documents d ON d.id = s.document_id
               WHERE s.document_id = $1 AND d.owner_id = $2
               ORDER BY s.created_at DESC"#,
        )
        .bind(document_id)
        .bind(owner_id)
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

    async fn delete_share(&self, owner_id: Uuid, token: &str) -> anyhow::Result<bool> {
        let res = sqlx::query("DELETE FROM shares s USING documents d WHERE s.token = $1 AND s.document_id = d.id AND d.owner_id = $2")
            .bind(token)
            .bind(owner_id)
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
        owner_id: Uuid,
        doc_id: Uuid,
    ) -> anyhow::Result<Vec<(String, String, Option<chrono::DateTime<chrono::Utc>>)>> {
        let rows = sqlx::query(
            r#"SELECT s.token, s.permission, s.expires_at
               FROM shares s
               JOIN documents d ON d.id = s.document_id
               WHERE s.document_id = $1 AND d.owner_id = $2 AND s.created_by = $2"#,
        )
        .bind(doc_id)
        .bind(owner_id)
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

    async fn list_active_shares(&self, owner_id: Uuid) -> anyhow::Result<Vec<ShareRow>> {
        let rows = sqlx::query(
            r#"SELECT s.id, s.token, s.permission, s.expires_at, s.created_at, s.parent_share_id,
                      d.id as document_id, d.title as document_title, d.type as document_type
               FROM shares s
               JOIN documents d ON d.id = s.document_id
               WHERE d.owner_id = $1 AND (s.expires_at IS NULL OR s.expires_at > now())
               ORDER BY s.created_at DESC"#,
        )
        .bind(owner_id)
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

    async fn materialize_folder_share(&self, owner_id: Uuid, token: &str) -> anyhow::Result<i64> {
        let row = sqlx::query(
            r#"SELECT s.id as share_id, s.permission, s.expires_at, d.id as folder_id, d.owner_id, d.type
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
        let owner: Uuid = row.get("owner_id");
        if owner != owner_id {
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
        .bind(owner_id)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await?;
        Ok(created)
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
