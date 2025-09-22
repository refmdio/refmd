use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::application::ports::public_repository::PublicRepository;
use crate::infrastructure::db::PgPool;

pub struct SqlxPublicRepository {
    pub pool: PgPool,
}

impl SqlxPublicRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PublicRepository for SqlxPublicRepository {
    async fn ensure_ownership_and_owner_name(
        &self,
        doc_id: Uuid,
        owner_id: Uuid,
    ) -> anyhow::Result<Option<(String, String)>> {
        let row = sqlx::query("SELECT d.title, u.name as owner_name FROM documents d JOIN users u ON d.owner_id = u.id WHERE d.id = $1 AND d.owner_id = $2")
            .bind(doc_id)
            .bind(owner_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| (r.get("title"), r.get("owner_name"))))
    }

    async fn upsert_public_document(&self, doc_id: Uuid, slug: &str) -> anyhow::Result<()> {
        let _ = sqlx::query("INSERT INTO public_documents (document_id, slug, published_at) VALUES ($1, $2, now()) ON CONFLICT (document_id) DO UPDATE SET slug = EXCLUDED.slug, published_at = now()")
            .bind(doc_id)
            .bind(slug)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn slug_exists(&self, slug: &str) -> anyhow::Result<bool> {
        let n =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(1) FROM public_documents WHERE slug = $1")
                .bind(slug)
                .fetch_one(&self.pool)
                .await?;
        Ok(n > 0)
    }

    async fn is_owner_document(&self, doc_id: Uuid, owner_id: Uuid) -> anyhow::Result<bool> {
        let n = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(1) FROM documents WHERE id = $1 AND owner_id = $2",
        )
        .bind(doc_id)
        .bind(owner_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(n > 0)
    }

    async fn delete_public_document(&self, doc_id: Uuid) -> anyhow::Result<bool> {
        let res = sqlx::query("DELETE FROM public_documents WHERE document_id = $1")
            .bind(doc_id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn get_publish_status(
        &self,
        owner_id: Uuid,
        doc_id: Uuid,
    ) -> anyhow::Result<Option<(String, String)>> {
        let row = sqlx::query(
            r#"SELECT p.slug, u.name as owner_name
               FROM public_documents p
               JOIN documents d ON p.document_id = d.id
               JOIN users u ON d.owner_id = u.id
               WHERE p.document_id = $1 AND d.owner_id = $2"#,
        )
        .bind(doc_id)
        .bind(owner_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| (r.get("slug"), r.get("owner_name"))))
    }

    async fn list_user_public_documents(
        &self,
        owner_name: &str,
    ) -> anyhow::Result<
        Vec<(
            Uuid,
            String,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        )>,
    > {
        let rows = sqlx::query(
            r#"SELECT d.id, d.title, d.updated_at, p.published_at
               FROM public_documents p
               JOIN documents d ON p.document_id = d.id
               JOIN users u ON d.owner_id = u.id
               WHERE u.name = $1
               ORDER BY d.updated_at DESC LIMIT 200"#,
        )
        .bind(owner_name)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get("id"),
                    r.get("title"),
                    r.get("updated_at"),
                    r.get("published_at"),
                )
            })
            .collect())
    }

    async fn get_public_meta_by_owner_and_id(
        &self,
        owner_name: &str,
        doc_id: Uuid,
    ) -> anyhow::Result<
        Option<(
            Uuid,
            String,
            Option<Uuid>,
            String,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
            Option<String>,
        )>,
    > {
        let row = sqlx::query(
            r#"SELECT d.id, d.title, d.parent_id, d.type, d.created_at, d.updated_at, d.path
               FROM public_documents p
               JOIN documents d ON p.document_id = d.id
               JOIN users u ON d.owner_id = u.id
               WHERE u.name = $1 AND d.id = $2"#,
        )
        .bind(owner_name)
        .bind(doc_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| {
            (
                r.get("id"),
                r.get("title"),
                r.try_get("parent_id").ok(),
                r.get("type"),
                r.get("created_at"),
                r.get("updated_at"),
                r.try_get("path").ok(),
            )
        }))
    }

    async fn public_exists_by_owner_and_id(
        &self,
        owner_name: &str,
        doc_id: Uuid,
    ) -> anyhow::Result<bool> {
        let n = sqlx::query_scalar::<_, i64>(
            r#"SELECT COUNT(1)
               FROM public_documents p
               JOIN documents d ON p.document_id = d.id
               JOIN users u ON d.owner_id = u.id
               WHERE u.name = $1 AND d.id = $2"#,
        )
        .bind(owner_name)
        .bind(doc_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(n > 0)
    }
}
