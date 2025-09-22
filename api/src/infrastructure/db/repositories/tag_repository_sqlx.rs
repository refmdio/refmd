use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::application::ports::tag_repository::TagRepository;
use crate::infrastructure::db::PgPool;

pub struct SqlxTagRepository {
    pub pool: PgPool,
}

impl SqlxTagRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TagRepository for SqlxTagRepository {
    async fn list_tags(
        &self,
        owner_id: Uuid,
        filter: Option<String>,
    ) -> anyhow::Result<Vec<(String, i64)>> {
        let rows = if let Some(f) = filter.filter(|s| !s.trim().is_empty()) {
            let like = format!("%{}%", f);
            sqlx::query(
                r#"SELECT t.name, COUNT(*)::BIGINT AS count
                   FROM document_tags dt
                   JOIN tags t ON t.id = dt.tag_id
                   JOIN documents d ON d.id = dt.document_id AND d.owner_id = $1
                   WHERE t.name ILIKE $2
                   GROUP BY t.name
                   ORDER BY count DESC, t.name ASC"#,
            )
            .bind(owner_id)
            .bind(like)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                r#"SELECT t.name, COUNT(*)::BIGINT AS count
                   FROM document_tags dt
                   JOIN tags t ON t.id = dt.tag_id
                   JOIN documents d ON d.id = dt.document_id AND d.owner_id = $1
                   GROUP BY t.name
                   ORDER BY count DESC, t.name ASC"#,
            )
            .bind(owner_id)
            .fetch_all(&self.pool)
            .await?
        };
        Ok(rows
            .into_iter()
            .map(|r| (r.get("name"), r.get("count")))
            .collect())
    }
}
