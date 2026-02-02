//! PostgreSQL tag and document tag repository implementation

use async_trait::async_trait;
use domain::document::{DocumentId, DocumentTag, DocumentTagRepository, Tag, TagId, TagRepository};
use domain::workspace::WorkspaceId;
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

/// PostgreSQL tag repository
#[derive(Clone)]
pub struct PgTagRepository {
    pool: PgPool,
}

impl PgTagRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Error)]
pub enum PgTagRepositoryError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(sqlx::FromRow)]
struct TagRow {
    id: i64,
    workspace_id: Uuid,
    name: String,
}

impl From<TagRow> for Tag {
    fn from(row: TagRow) -> Self {
        Self {
            id: TagId::new(row.id),
            workspace_id: WorkspaceId::from_uuid(row.workspace_id),
            name: row.name,
        }
    }
}

#[async_trait]
impl TagRepository for PgTagRepository {
    type Error = PgTagRepositoryError;

    async fn find_by_id(&self, id: TagId) -> Result<Option<Tag>, Self::Error> {
        let row = sqlx::query_as::<_, TagRow>(
            r#"
            SELECT id, workspace_id, name
            FROM tags
            WHERE id = $1
            "#,
        )
        .bind(id.as_i64())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(Tag::from))
    }

    async fn find_by_workspace_id(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<Tag>, Self::Error> {
        let rows = sqlx::query_as::<_, TagRow>(
            r#"
            SELECT id, workspace_id, name
            FROM tags
            WHERE workspace_id = $1
            ORDER BY name
            "#,
        )
        .bind(workspace_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(Tag::from).collect())
    }

    async fn find_by_workspace_and_name(
        &self,
        workspace_id: WorkspaceId,
        name: &str,
    ) -> Result<Option<Tag>, Self::Error> {
        let row = sqlx::query_as::<_, TagRow>(
            r#"
            SELECT id, workspace_id, name
            FROM tags
            WHERE workspace_id = $1 AND name = $2
            "#,
        )
        .bind(workspace_id.as_uuid())
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(Tag::from))
    }

    async fn save(&self, tag: &Tag) -> Result<TagId, Self::Error> {
        let id = sqlx::query_scalar::<_, i64>(
            r#"
            INSERT INTO tags (workspace_id, name)
            VALUES ($1, $2)
            ON CONFLICT (workspace_id, name) DO UPDATE SET name = EXCLUDED.name
            RETURNING id
            "#,
        )
        .bind(tag.workspace_id.as_uuid())
        .bind(&tag.name)
        .fetch_one(&self.pool)
        .await?;

        Ok(TagId::new(id))
    }

    async fn delete(&self, id: TagId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM tags WHERE id = $1")
            .bind(id.as_i64())
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

/// PostgreSQL document tag repository
#[derive(Clone)]
pub struct PgDocumentTagRepository {
    pool: PgPool,
}

impl PgDocumentTagRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Error)]
pub enum PgDocumentTagRepositoryError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(sqlx::FromRow)]
struct DocumentTagRow {
    document_id: Uuid,
    tag_id: i64,
    encrypted_tag: Option<Vec<u8>>,
}

impl From<DocumentTagRow> for DocumentTag {
    fn from(row: DocumentTagRow) -> Self {
        Self {
            document_id: DocumentId::from_uuid(row.document_id),
            tag_id: TagId::new(row.tag_id),
            encrypted_tag: row.encrypted_tag,
        }
    }
}

#[async_trait]
impl DocumentTagRepository for PgDocumentTagRepository {
    type Error = PgDocumentTagRepositoryError;

    async fn find_by_document_id(
        &self,
        document_id: DocumentId,
    ) -> Result<Vec<DocumentTag>, Self::Error> {
        let rows = sqlx::query_as::<_, DocumentTagRow>(
            r#"
            SELECT document_id, tag_id, encrypted_tag
            FROM document_tags
            WHERE document_id = $1
            "#,
        )
        .bind(document_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(DocumentTag::from).collect())
    }

    async fn find_by_tag_id(&self, tag_id: TagId) -> Result<Vec<DocumentTag>, Self::Error> {
        let rows = sqlx::query_as::<_, DocumentTagRow>(
            r#"
            SELECT document_id, tag_id, encrypted_tag
            FROM document_tags
            WHERE tag_id = $1
            "#,
        )
        .bind(tag_id.as_i64())
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(DocumentTag::from).collect())
    }

    async fn save(&self, document_tag: &DocumentTag) -> Result<(), Self::Error> {
        sqlx::query(
            r#"
            INSERT INTO document_tags (document_id, tag_id, encrypted_tag)
            VALUES ($1, $2, $3)
            ON CONFLICT (document_id, tag_id) DO UPDATE SET
                encrypted_tag = EXCLUDED.encrypted_tag
            "#,
        )
        .bind(document_tag.document_id.as_uuid())
        .bind(document_tag.tag_id.as_i64())
        .bind(&document_tag.encrypted_tag)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, document_id: DocumentId, tag_id: TagId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM document_tags WHERE document_id = $1 AND tag_id = $2")
            .bind(document_id.as_uuid())
            .bind(tag_id.as_i64())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete_by_document_id(&self, document_id: DocumentId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM document_tags WHERE document_id = $1")
            .bind(document_id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
