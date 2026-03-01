//! PostgreSQL document repository implementation

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::document::{Document, DocumentId, DocumentRepository, DocumentType};
use domain::identity::UserId;
use domain::workspace::WorkspaceId;
use uuid::Uuid;

pg_repo_struct!(PgDocumentRepository);
pg_repo_error!(PgDocumentRepositoryError, InvalidDocumentType(String));

/// Shared SELECT column list for document queries.
/// Keep in sync with `DocumentRow` fields.
const DOCUMENT_COLUMNS: &str = "id, workspace_id, parent_id, title, encrypted_title, encrypted_title_nonce, slug, path, doc_type, is_encrypted, needs_dek_rotation, min_dek_version, created_by, created_at, updated_at, archived_at";

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
        let sql = format!("SELECT {DOCUMENT_COLUMNS} FROM documents WHERE id = $1");
        let row = sqlx::query_as::<_, DocumentRow>(&sql)
            .bind(id.as_uuid())
            .fetch_optional(&self.pool)
            .await?;

        row.map(|r| r.try_into_document()).transpose()
    }

    async fn find_by_workspace_id(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<Document>, Self::Error> {
        let sql = format!(
            "SELECT {DOCUMENT_COLUMNS} FROM documents WHERE workspace_id = $1 ORDER BY created_at DESC"
        );
        let rows = sqlx::query_as::<_, DocumentRow>(&sql)
            .bind(workspace_id.as_uuid())
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter().map(|r| r.try_into_document()).collect()
    }

    async fn find_ids_by_workspace_id(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<DocumentId>, Self::Error> {
        let rows = sqlx::query_scalar!(
            "SELECT id FROM documents WHERE workspace_id = $1",
            workspace_id.as_uuid()
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(DocumentId::from_uuid).collect())
    }

    async fn find_by_parent_id(&self, parent_id: DocumentId) -> Result<Vec<Document>, Self::Error> {
        let sql = format!(
            "SELECT {DOCUMENT_COLUMNS} FROM documents WHERE parent_id = $1 ORDER BY title"
        );
        let rows = sqlx::query_as::<_, DocumentRow>(&sql)
            .bind(parent_id.as_uuid())
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter().map(|r| r.try_into_document()).collect()
    }

    async fn find_roots_by_workspace_id(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<Document>, Self::Error> {
        let sql = format!(
            "SELECT {DOCUMENT_COLUMNS} FROM documents WHERE workspace_id = $1 AND parent_id IS NULL ORDER BY title"
        );
        let rows = sqlx::query_as::<_, DocumentRow>(&sql)
            .bind(workspace_id.as_uuid())
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter().map(|r| r.try_into_document()).collect()
    }

    async fn find_needing_dek_rotation(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<Document>, Self::Error> {
        let sql = format!(
            "SELECT {DOCUMENT_COLUMNS} FROM documents WHERE workspace_id = $1 AND needs_dek_rotation = TRUE"
        );
        let rows = sqlx::query_as::<_, DocumentRow>(&sql)
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
        let result = sqlx::query_scalar!(
            r#"
            SELECT EXISTS(SELECT 1 FROM documents WHERE workspace_id = $1 AND slug = $2) as "exists!"
            "#,
            workspace_id.as_uuid(),
            slug
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    async fn save(&self, document: &Document) -> Result<(), Self::Error> {
        let parent_id = document.parent_id.map(|id| id.as_uuid());
        let created_by = document.created_by.map(|id| id.as_uuid());
        let doc_type_str = document.doc_type.as_str();

        let mut tx = self.pool.begin().await?;

        // Check if this is a new document (INSERT) or update (ON CONFLICT)
        let existing = sqlx::query_scalar!(
            "SELECT id FROM documents WHERE id = $1",
            document.id.as_uuid()
        )
        .fetch_optional(&mut *tx)
        .await?;

        let is_new = existing.is_none();

        if is_new {
            // New document: INSERT without active_snapshot_id (NULL).
            // The genesis snapshot will be created by the first client via WS.
            sqlx::query(
                r#"
                INSERT INTO documents (
                    id, workspace_id, parent_id, title, encrypted_title, encrypted_title_nonce,
                    slug, path, doc_type, is_encrypted, needs_dek_rotation, min_dek_version,
                    created_by, created_at, updated_at, archived_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
                "#,
            )
            .bind(document.id.as_uuid())      // $1
            .bind(document.workspace_id.as_uuid()) // $2
            .bind(parent_id)                   // $3
            .bind(&document.title)             // $4
            .bind(document.encrypted_title.as_deref()) // $5
            .bind(document.encrypted_title_nonce.as_deref()) // $6
            .bind(&document.slug)              // $7
            .bind(document.path.as_deref())    // $8
            .bind(doc_type_str)                // $9
            .bind(document.is_encrypted)       // $10
            .bind(document.needs_dek_rotation) // $11
            .bind(document.min_dek_version)    // $12
            .bind(created_by)                  // $13
            .bind(document.created_at)         // $14
            .bind(document.updated_at)         // $15
            .bind(document.archived_at)        // $16
            .execute(&mut *tx)
            .await?;
        } else {
            // Existing document: UPDATE only mutable fields (preserve active_snapshot_id)
            sqlx::query(
                r#"
                UPDATE documents SET
                    parent_id = $2,
                    title = $3,
                    encrypted_title = $4,
                    encrypted_title_nonce = $5,
                    path = $6,
                    is_encrypted = $7,
                    needs_dek_rotation = $8,
                    min_dek_version = $9,
                    updated_at = $10,
                    archived_at = $11
                WHERE id = $1
                "#,
            )
            .bind(document.id.as_uuid())
            .bind(parent_id)
            .bind(&document.title)
            .bind(document.encrypted_title.as_deref())
            .bind(document.encrypted_title_nonce.as_deref())
            .bind(document.path.as_deref())
            .bind(document.is_encrypted)
            .bind(document.needs_dek_rotation)
            .bind(document.min_dek_version)
            .bind(document.updated_at)
            .bind(document.archived_at)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    async fn delete(&self, id: DocumentId) -> Result<(), Self::Error> {
        sqlx::query!("DELETE FROM documents WHERE id = $1", id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
