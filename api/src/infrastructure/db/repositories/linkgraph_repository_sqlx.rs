use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::application::ports::linkgraph_repository::LinkGraphRepository;
use crate::infrastructure::db::PgPool;

pub struct SqlxLinkGraphRepository {
    pub pool: PgPool,
}

impl SqlxLinkGraphRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl LinkGraphRepository for SqlxLinkGraphRepository {
    async fn clear_links_for_source(&self, source_id: Uuid) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM document_links WHERE source_document_id = $1")
            .bind(source_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn exists_doc_for_owner(&self, doc_id: Uuid, owner_id: Uuid) -> anyhow::Result<bool> {
        let n = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(1) FROM documents WHERE id = $1 AND owner_id = $2",
        )
        .bind(doc_id)
        .bind(owner_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(n > 0)
    }

    async fn find_doc_id_by_owner_and_title(
        &self,
        owner_id: Uuid,
        title: &str,
    ) -> anyhow::Result<Option<Uuid>> {
        let row = sqlx::query(
            r#"SELECT id FROM documents 
               WHERE owner_id = $1 AND LOWER(title) = LOWER($2)
               ORDER BY updated_at DESC LIMIT 1"#,
        )
        .bind(owner_id)
        .bind(title)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.get::<Uuid, _>("id")))
    }

    async fn upsert_link(
        &self,
        source_id: Uuid,
        target_id: Uuid,
        link_type: &str,
        link_text: Option<String>,
        position_start: i32,
        position_end: i32,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"INSERT INTO document_links (
                    source_document_id, target_document_id, link_type,
                    link_text, position_start, position_end, created_at, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, now(), now())
                ON CONFLICT (source_document_id, target_document_id, position_start)
                DO UPDATE SET link_type = EXCLUDED.link_type,
                              link_text = EXCLUDED.link_text,
                              position_end = EXCLUDED.position_end,
                              updated_at = now()
            "#,
        )
        .bind(source_id)
        .bind(target_id)
        .bind(link_type)
        .bind(link_text)
        .bind(position_start)
        .bind(position_end)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
