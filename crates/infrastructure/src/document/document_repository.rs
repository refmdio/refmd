//! PostgreSQL document repository implementation

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::document::{Document, DocumentId, DocumentRepository, DocumentType};
use domain::identity::UserId;
use domain::workspace::WorkspaceId;
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

/// PostgreSQL document repository
#[derive(Clone)]
pub struct PgDocumentRepository {
    pool: PgPool,
}

impl PgDocumentRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Error)]
pub enum PgDocumentRepositoryError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("corrupted data: invalid document type: {0}")]
    InvalidDocumentType(String),
}

#[derive(sqlx::FromRow)]
struct DocumentRow {
    id: Uuid,
    workspace_id: Uuid,
    parent_id: Option<Uuid>,
    title: String,
    encrypted_title: Option<Vec<u8>>,
    encrypted_title_nonce: Option<Vec<u8>>,
    slug: String,
    path: Option<String>,
    doc_type: String,
    is_encrypted: bool,
    needs_dek_rotation: bool,
    min_dek_version: i32,
    created_by: Option<Uuid>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    archived_at: Option<DateTime<Utc>>,
}

impl DocumentRow {
    fn try_into_document(self) -> Result<Document, PgDocumentRepositoryError> {
        let doc_type: DocumentType = self
            .doc_type
            .parse()
            .map_err(|_| PgDocumentRepositoryError::InvalidDocumentType(self.doc_type.clone()))?;

        Ok(Document {
            id: DocumentId::from_uuid(self.id),
            workspace_id: WorkspaceId::from_uuid(self.workspace_id),
            parent_id: self.parent_id.map(DocumentId::from_uuid),
            title: self.title,
            encrypted_title: self.encrypted_title,
            encrypted_title_nonce: self.encrypted_title_nonce,
            slug: self.slug,
            path: self.path,
            doc_type,
            is_encrypted: self.is_encrypted,
            needs_dek_rotation: self.needs_dek_rotation,
            min_dek_version: self.min_dek_version,
            created_by: self.created_by.map(UserId::from_uuid),
            created_at: self.created_at,
            updated_at: self.updated_at,
            archived_at: self.archived_at,
        })
    }
}

#[async_trait]
impl DocumentRepository for PgDocumentRepository {
    type Error = PgDocumentRepositoryError;

    async fn find_by_id(&self, id: DocumentId) -> Result<Option<Document>, Self::Error> {
        let row = sqlx::query_as::<_, DocumentRow>(
            r#"
            SELECT id, workspace_id, parent_id, title, encrypted_title, encrypted_title_nonce,
                   slug, path, doc_type, is_encrypted, needs_dek_rotation, min_dek_version,
                   created_by, created_at, updated_at, archived_at
            FROM documents
            WHERE id = $1
            "#,
        )
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.try_into_document()).transpose()
    }

    async fn find_by_workspace_and_slug(
        &self,
        workspace_id: WorkspaceId,
        slug: &str,
    ) -> Result<Option<Document>, Self::Error> {
        let row = sqlx::query_as::<_, DocumentRow>(
            r#"
            SELECT id, workspace_id, parent_id, title, encrypted_title, encrypted_title_nonce,
                   slug, path, doc_type, is_encrypted, needs_dek_rotation, min_dek_version,
                   created_by, created_at, updated_at, archived_at
            FROM documents
            WHERE workspace_id = $1 AND slug = $2
            "#,
        )
        .bind(workspace_id.as_uuid())
        .bind(slug)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.try_into_document()).transpose()
    }

    async fn find_by_workspace_id(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<Document>, Self::Error> {
        let rows = sqlx::query_as::<_, DocumentRow>(
            r#"
            SELECT id, workspace_id, parent_id, title, encrypted_title, encrypted_title_nonce,
                   slug, path, doc_type, is_encrypted, needs_dek_rotation, min_dek_version,
                   created_by, created_at, updated_at, archived_at
            FROM documents
            WHERE workspace_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(workspace_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into_document()).collect()
    }

    async fn find_by_parent_id(&self, parent_id: DocumentId) -> Result<Vec<Document>, Self::Error> {
        let rows = sqlx::query_as::<_, DocumentRow>(
            r#"
            SELECT id, workspace_id, parent_id, title, encrypted_title, encrypted_title_nonce,
                   slug, path, doc_type, is_encrypted, needs_dek_rotation, min_dek_version,
                   created_by, created_at, updated_at, archived_at
            FROM documents
            WHERE parent_id = $1
            ORDER BY title
            "#,
        )
        .bind(parent_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into_document()).collect()
    }

    async fn find_roots_by_workspace_id(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<Document>, Self::Error> {
        let rows = sqlx::query_as::<_, DocumentRow>(
            r#"
            SELECT id, workspace_id, parent_id, title, encrypted_title, encrypted_title_nonce,
                   slug, path, doc_type, is_encrypted, needs_dek_rotation, min_dek_version,
                   created_by, created_at, updated_at, archived_at
            FROM documents
            WHERE workspace_id = $1 AND parent_id IS NULL
            ORDER BY title
            "#,
        )
        .bind(workspace_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into_document()).collect()
    }

    async fn find_needing_dek_rotation(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<Document>, Self::Error> {
        let rows = sqlx::query_as::<_, DocumentRow>(
            r#"
            SELECT id, workspace_id, parent_id, title, encrypted_title, encrypted_title_nonce,
                   slug, path, doc_type, is_encrypted, needs_dek_rotation, min_dek_version,
                   created_by, created_at, updated_at, archived_at
            FROM documents
            WHERE workspace_id = $1 AND needs_dek_rotation = TRUE
            "#,
        )
        .bind(workspace_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into_document()).collect()
    }

    async fn slug_exists(
        &self,
        workspace_id: WorkspaceId,
        slug: &str,
    ) -> Result<bool, Self::Error> {
        let result = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS(SELECT 1 FROM documents WHERE workspace_id = $1 AND slug = $2)
            "#,
        )
        .bind(workspace_id.as_uuid())
        .bind(slug)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    async fn save(&self, document: &Document) -> Result<(), Self::Error> {
        sqlx::query(
            r#"
            INSERT INTO documents (
                id, workspace_id, parent_id, title, encrypted_title, encrypted_title_nonce,
                slug, path, doc_type, is_encrypted, needs_dek_rotation, min_dek_version,
                created_by, created_at, updated_at, archived_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
            ON CONFLICT (id) DO UPDATE SET
                parent_id = EXCLUDED.parent_id,
                title = EXCLUDED.title,
                encrypted_title = EXCLUDED.encrypted_title,
                encrypted_title_nonce = EXCLUDED.encrypted_title_nonce,
                path = EXCLUDED.path,
                is_encrypted = EXCLUDED.is_encrypted,
                needs_dek_rotation = EXCLUDED.needs_dek_rotation,
                min_dek_version = EXCLUDED.min_dek_version,
                updated_at = EXCLUDED.updated_at,
                archived_at = EXCLUDED.archived_at
            "#,
        )
        .bind(document.id.as_uuid())
        .bind(document.workspace_id.as_uuid())
        .bind(document.parent_id.map(|id| id.as_uuid()))
        .bind(&document.title)
        .bind(&document.encrypted_title)
        .bind(&document.encrypted_title_nonce)
        .bind(&document.slug)
        .bind(&document.path)
        .bind(document.doc_type.as_str())
        .bind(document.is_encrypted)
        .bind(document.needs_dek_rotation)
        .bind(document.min_dek_version)
        .bind(document.created_by.map(|id| id.as_uuid()))
        .bind(document.created_at)
        .bind(document.updated_at)
        .bind(document.archived_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, id: DocumentId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM documents WHERE id = $1")
            .bind(id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
