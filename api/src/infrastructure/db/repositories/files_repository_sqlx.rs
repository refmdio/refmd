use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::application::ports::files_repository::FilesRepository;
use crate::infrastructure::db::PgPool;

pub struct SqlxFilesRepository {
    pub pool: PgPool,
}

impl SqlxFilesRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl FilesRepository for SqlxFilesRepository {
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

    async fn insert_file(
        &self,
        doc_id: Uuid,
        filename: &str,
        content_type: Option<&str>,
        size: i64,
        storage_path: &str,
        content_hash: &str,
    ) -> anyhow::Result<Uuid> {
        let row = sqlx::query(
            r#"INSERT INTO files (document_id, filename, content_type, size, storage_path, content_hash)
               VALUES ($1, $2, $3, $4, $5, $6)
               RETURNING id"#,
        )
        .bind(doc_id)
        .bind(filename)
        .bind(content_type)
        .bind(size)
        .bind(storage_path)
        .bind(content_hash)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get("id"))
    }

    async fn get_file_meta(
        &self,
        file_id: Uuid,
    ) -> anyhow::Result<Option<(String, Option<String>, Uuid)>> {
        let row = sqlx::query(
            r#"SELECT f.storage_path, f.content_type, d.owner_id
               FROM files f JOIN documents d ON f.document_id = d.id
               WHERE f.id = $1"#,
        )
        .bind(file_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| {
            (
                r.get("storage_path"),
                r.try_get("content_type").ok(),
                r.get("owner_id"),
            )
        }))
    }

    async fn get_file_path_by_doc_and_name(
        &self,
        doc_id: Uuid,
        filename: &str,
    ) -> anyhow::Result<Option<(String, Option<String>)>> {
        let row = sqlx::query(
            r#"SELECT storage_path, content_type FROM files WHERE document_id = $1 AND filename = $2"#,
        )
        .bind(doc_id)
        .bind(filename)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| (r.get("storage_path"), r.try_get("content_type").ok())))
    }

    async fn list_storage_paths_for_document(&self, doc_id: Uuid) -> anyhow::Result<Vec<String>> {
        let rows = sqlx::query("SELECT storage_path FROM files WHERE document_id = $1")
            .bind(doc_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .filter_map(|r| r.try_get::<String, _>("storage_path").ok())
            .collect())
    }
}
