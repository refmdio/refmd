use async_trait::async_trait;
use uuid::Uuid;

use crate::application::ports::access_repository::AccessRepository;
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
    async fn user_owns_document(&self, doc_id: Uuid, user_id: Uuid) -> anyhow::Result<bool> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(1) FROM documents WHERE id = $1 AND owner_id = $2",
        )
        .bind(doc_id)
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(count > 0)
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
}
