use async_trait::async_trait;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::core::db::PgPool;
use application::core::ports::errors::PortResult;
use application::documents::ports::files::files_repository::{
    FileInsert, FileMeta, FilePathMeta, FileRecord, FilesRepository, StoredFileScope,
};

pub struct SqlxFilesRepository {
    pub pool: PgPool,
}

impl SqlxFilesRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub(crate) async fn list_storage_paths_for_document_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        doc_id: Uuid,
    ) -> anyhow::Result<Vec<String>> {
        let rows = sqlx::query("SELECT storage_path FROM files WHERE document_id = $1 FOR UPDATE")
            .bind(doc_id)
            .fetch_all(tx.as_mut())
            .await?;
        Ok(rows
            .into_iter()
            .filter_map(|r| r.try_get::<String, _>("storage_path").ok())
            .collect())
    }
}

#[async_trait]
impl FilesRepository for SqlxFilesRepository {
    async fn is_workspace_document(&self, doc_id: Uuid, workspace_id: Uuid) -> PortResult<bool> {
        let out: anyhow::Result<bool> = async {
            let n = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(1) FROM documents WHERE id = $1 AND workspace_id = $2",
            )
            .bind(doc_id)
            .bind(workspace_id)
            .fetch_one(&self.pool)
            .await?;
            Ok(n > 0)
        }
        .await;
        out.map_err(Into::into)
    }

    async fn insert_file(&self, input: FileInsert<'_>) -> PortResult<Uuid> {
        let out: anyhow::Result<Uuid> = async {
            let row = sqlx::query(
                r#"INSERT INTO files (
                    document_id, filename, content_type, size, storage_path, content_hash,
                    encrypted_metadata, encrypted_metadata_nonce, encrypted_hash
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                RETURNING id"#,
            )
            .bind(input.doc_id)
            .bind(input.filename)
            .bind(input.content_type)
            .bind(input.size)
            .bind(input.storage_path)
            .bind(input.content_hash)
            .bind(input.encrypted_metadata)
            .bind(input.encrypted_metadata_nonce)
            .bind(input.encrypted_hash)
            .fetch_one(&self.pool)
            .await?;
            Ok(row.get("id"))
        }
        .await;
        out.map_err(Into::into)
    }

    async fn get_file_meta(&self, file_id: Uuid) -> PortResult<Option<FileMeta>> {
        let out: anyhow::Result<Option<FileMeta>> = async {
            let row = sqlx::query(
                r#"SELECT f.storage_path, f.content_type, f.document_id, d.workspace_id,
                          f.encrypted_metadata, f.encrypted_metadata_nonce, f.encrypted_hash
               FROM files f JOIN documents d ON f.document_id = d.id
               WHERE f.id = $1"#,
            )
            .bind(file_id)
            .fetch_optional(&self.pool)
            .await?;
            Ok(row.map(|r| FileMeta {
                storage_path: r.get("storage_path"),
                content_type: r.try_get("content_type").ok(),
                document_id: r.get("document_id"),
                workspace_id: r.get("workspace_id"),
                encrypted_metadata: r.try_get("encrypted_metadata").ok(),
                encrypted_metadata_nonce: r.try_get("encrypted_metadata_nonce").ok(),
                encrypted_hash: r.try_get("encrypted_hash").ok(),
            }))
        }
        .await;
        out.map_err(Into::into)
    }

    async fn get_file_path_by_doc_and_name(
        &self,
        doc_id: Uuid,
        filename: &str,
    ) -> PortResult<Option<FilePathMeta>> {
        let out: anyhow::Result<Option<FilePathMeta>> = async {
            let row = sqlx::query(
                r#"SELECT storage_path, content_type FROM files WHERE document_id = $1 AND filename = $2"#,
            )
            .bind(doc_id)
            .bind(filename)
            .fetch_optional(&self.pool)
            .await?;
            Ok(row.map(|r| FilePathMeta {
                storage_path: r.get("storage_path"),
                content_type: r.try_get("content_type").ok(),
            }))
        }
        .await;
        out.map_err(Into::into)
    }

    async fn list_storage_paths_for_document(&self, doc_id: Uuid) -> PortResult<Vec<String>> {
        let out: anyhow::Result<Vec<String>> = async {
            let rows = sqlx::query("SELECT storage_path FROM files WHERE document_id = $1")
                .bind(doc_id)
                .fetch_all(&self.pool)
                .await?;
            Ok(rows
                .into_iter()
                .filter_map(|r| r.try_get::<String, _>("storage_path").ok())
                .collect())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn list_files_for_document(&self, doc_id: Uuid) -> PortResult<Vec<FileRecord>> {
        let out: anyhow::Result<Vec<FileRecord>> = async {
            let rows = sqlx::query(
                r#"SELECT id, filename, content_type, size, storage_path, content_hash,
                          encrypted_metadata, encrypted_metadata_nonce, encrypted_hash
               FROM files
               WHERE document_id = $1"#,
            )
            .bind(doc_id)
            .fetch_all(&self.pool)
            .await?;
            Ok(rows
                .into_iter()
                .map(|r| FileRecord {
                    id: r.get("id"),
                    filename: r.get("filename"),
                    content_type: r.try_get("content_type").ok(),
                    size: r.get("size"),
                    storage_path: r.get("storage_path"),
                    content_hash: r.get("content_hash"),
                    encrypted_metadata: r.try_get("encrypted_metadata").ok(),
                    encrypted_metadata_nonce: r.try_get("encrypted_metadata_nonce").ok(),
                    encrypted_hash: r.try_get("encrypted_hash").ok(),
                })
                .collect())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn list_storage_paths_for_workspace(
        &self,
        workspace_id: Uuid,
    ) -> PortResult<Vec<String>> {
        let out: anyhow::Result<Vec<String>> = async {
            let rows = sqlx::query(
                r#"
            SELECT f.storage_path
            FROM files f
            JOIN documents d ON d.id = f.document_id
            WHERE d.workspace_id = $1
            "#,
            )
            .bind(workspace_id)
            .fetch_all(&self.pool)
            .await?;
            Ok(rows
                .into_iter()
                .filter_map(|r| r.try_get::<String, _>("storage_path").ok())
                .collect())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn find_by_storage_path(
        &self,
        storage_path: &str,
    ) -> PortResult<Option<StoredFileScope>> {
        let out: anyhow::Result<Option<StoredFileScope>> = async {
            let row = sqlx::query(
                r#"SELECT f.id as file_id, f.document_id, d.workspace_id
               FROM files f
               JOIN documents d ON d.id = f.document_id
               WHERE f.storage_path = $1
               LIMIT 1"#,
            )
            .bind(storage_path)
            .fetch_optional(&self.pool)
            .await?;
            Ok(row.map(|r| StoredFileScope {
                file_id: r.get("file_id"),
                document_id: r.get("document_id"),
                workspace_id: r.get("workspace_id"),
            }))
        }
        .await;
        out.map_err(Into::into)
    }

    async fn update_storage_path(&self, file_id: Uuid, storage_path: &str) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            sqlx::query(
                r#"UPDATE files SET storage_path = $2, updated_at = now()
               WHERE id = $1"#,
            )
            .bind(file_id)
            .bind(storage_path)
            .execute(&self.pool)
            .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn update_hash_and_size(
        &self,
        file_id: Uuid,
        size: i64,
        content_hash: &str,
    ) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            sqlx::query(
                r#"UPDATE files SET size = $2, content_hash = $3, updated_at = now()
               WHERE id = $1"#,
            )
            .bind(file_id)
            .bind(size)
            .bind(content_hash)
            .execute(&self.pool)
            .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn delete_by_id(&self, file_id: Uuid) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            sqlx::query("DELETE FROM files WHERE id = $1")
                .bind(file_id)
                .execute(&self.pool)
                .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }

}
