use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::core::db::PgPool;
use application::core::ports::errors::PortResult;
use application::documents::ports::tagging::encrypted_tag_repository::{
    EncryptedTagEntry, EncryptedTagRepository, EncryptedTagSummary,
};

pub struct SqlxEncryptedTagRepository {
    pool: PgPool,
}

impl SqlxEncryptedTagRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl EncryptedTagRepository for SqlxEncryptedTagRepository {
    async fn list_encrypted_tags(
        &self,
        workspace_id: Uuid,
    ) -> PortResult<Vec<EncryptedTagSummary>> {
        let out: anyhow::Result<Vec<EncryptedTagSummary>> = async {
            let rows = sqlx::query(
                r#"SELECT encrypted_tag, COUNT(*) as count
                   FROM encrypted_tag_index
                   WHERE workspace_id = $1
                   GROUP BY encrypted_tag
                   ORDER BY count DESC"#,
            )
            .bind(workspace_id)
            .fetch_all(&self.pool)
            .await?;

            Ok(rows
                .into_iter()
                .map(|row| EncryptedTagSummary {
                    encrypted_tag: row.get("encrypted_tag"),
                    count: row.get("count"),
                })
                .collect())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn list_document_encrypted_tags(
        &self,
        document_id: Uuid,
    ) -> PortResult<Vec<EncryptedTagEntry>> {
        let out: anyhow::Result<Vec<EncryptedTagEntry>> = async {
            let rows = sqlx::query(
                r#"SELECT id, workspace_id, document_id, encrypted_tag, created_at
                   FROM encrypted_tag_index
                   WHERE document_id = $1
                   ORDER BY created_at"#,
            )
            .bind(document_id)
            .fetch_all(&self.pool)
            .await?;

            Ok(rows
                .into_iter()
                .map(|row| EncryptedTagEntry {
                    id: row.get("id"),
                    workspace_id: row.get("workspace_id"),
                    document_id: row.get("document_id"),
                    encrypted_tag: row.get("encrypted_tag"),
                    created_at: row.get("created_at"),
                })
                .collect())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn replace_document_encrypted_tags(
        &self,
        workspace_id: Uuid,
        document_id: Uuid,
        encrypted_tags: &[Vec<u8>],
    ) -> PortResult<Vec<EncryptedTagEntry>> {
        let out: anyhow::Result<Vec<EncryptedTagEntry>> = async {
            // Use a transaction for atomicity
            let mut tx = self.pool.begin().await?;

            // Delete existing tags for this document
            sqlx::query(r#"DELETE FROM encrypted_tag_index WHERE document_id = $1"#)
                .bind(document_id)
                .execute(&mut *tx)
                .await?;

            // Insert new tags
            let mut entries = Vec::with_capacity(encrypted_tags.len());
            for encrypted_tag in encrypted_tags {
                let row = sqlx::query(
                    r#"INSERT INTO encrypted_tag_index (workspace_id, document_id, encrypted_tag)
                       VALUES ($1, $2, $3)
                       RETURNING id, workspace_id, document_id, encrypted_tag, created_at"#,
                )
                .bind(workspace_id)
                .bind(document_id)
                .bind(encrypted_tag)
                .fetch_one(&mut *tx)
                .await?;

                entries.push(EncryptedTagEntry {
                    id: row.get("id"),
                    workspace_id: row.get("workspace_id"),
                    document_id: row.get("document_id"),
                    encrypted_tag: row.get("encrypted_tag"),
                    created_at: row.get("created_at"),
                });
            }

            tx.commit().await?;
            Ok(entries)
        }
        .await;
        out.map_err(Into::into)
    }

    async fn find_documents_by_encrypted_tag(
        &self,
        workspace_id: Uuid,
        encrypted_tag: &[u8],
    ) -> PortResult<Vec<Uuid>> {
        let out: anyhow::Result<Vec<Uuid>> = async {
            let rows = sqlx::query(
                r#"SELECT DISTINCT document_id
                   FROM encrypted_tag_index
                   WHERE workspace_id = $1 AND encrypted_tag = $2"#,
            )
            .bind(workspace_id)
            .bind(encrypted_tag)
            .fetch_all(&self.pool)
            .await?;

            Ok(rows.into_iter().map(|row| row.get("document_id")).collect())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn find_encrypted_tag(
        &self,
        workspace_id: Uuid,
        encrypted_tag: &[u8],
    ) -> PortResult<Vec<EncryptedTagSummary>> {
        let out: anyhow::Result<Vec<EncryptedTagSummary>> = async {
            let rows = sqlx::query(
                r#"SELECT encrypted_tag, COUNT(*) as count
                   FROM encrypted_tag_index
                   WHERE workspace_id = $1 AND encrypted_tag = $2
                   GROUP BY encrypted_tag"#,
            )
            .bind(workspace_id)
            .bind(encrypted_tag)
            .fetch_all(&self.pool)
            .await?;

            Ok(rows
                .into_iter()
                .map(|row| EncryptedTagSummary {
                    encrypted_tag: row.get("encrypted_tag"),
                    count: row.get("count"),
                })
                .collect())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn delete_document_encrypted_tags(&self, document_id: Uuid) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            sqlx::query(r#"DELETE FROM encrypted_tag_index WHERE document_id = $1"#)
                .bind(document_id)
                .execute(&self.pool)
                .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }
}
