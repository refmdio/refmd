use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::application::ports::tagging_repository::TaggingRepository;
use crate::infrastructure::db::PgPool;

pub struct SqlxTaggingRepository {
    pub pool: PgPool,
}

impl SqlxTaggingRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TaggingRepository for SqlxTaggingRepository {
    async fn clear_document_tags(&self, doc_id: Uuid) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM document_tags WHERE document_id = $1")
            .bind(doc_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn upsert_tag_return_id(&self, name: &str) -> anyhow::Result<i64> {
        let row = sqlx::query("INSERT INTO tags(name) VALUES ($1) ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id")
            .bind(name)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get("id"))
    }

    async fn owner_doc_exists(&self, doc_id: Uuid, owner_id: Uuid) -> anyhow::Result<bool> {
        let n = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(1) FROM documents WHERE id = $1 AND owner_id = $2",
        )
        .bind(doc_id)
        .bind(owner_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(n > 0)
    }

    async fn associate_document_tag(&self, doc_id: Uuid, tag_id: i64) -> anyhow::Result<()> {
        sqlx::query("INSERT INTO document_tags(document_id, tag_id) VALUES ($1, $2)")
            .bind(doc_id)
            .bind(tag_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
