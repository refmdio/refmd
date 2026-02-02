//! PostgreSQL document link repository implementation

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::document::{DocumentId, DocumentLink, DocumentLinkId, DocumentLinkRepository, LinkType};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

/// PostgreSQL document link repository
#[derive(Clone)]
pub struct PgDocumentLinkRepository {
    pool: PgPool,
}

impl PgDocumentLinkRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Error)]
pub enum PgDocumentLinkRepositoryError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(sqlx::FromRow)]
struct DocumentLinkRow {
    id: Uuid,
    source_id: Uuid,
    target_id: Uuid,
    link_type: String,
    link_text: Option<String>,
    created_at: DateTime<Utc>,
}

impl From<DocumentLinkRow> for DocumentLink {
    fn from(row: DocumentLinkRow) -> Self {
        Self {
            id: DocumentLinkId::from_uuid(row.id),
            source_id: DocumentId::from_uuid(row.source_id),
            target_id: DocumentId::from_uuid(row.target_id),
            link_type: LinkType::new(row.link_type),
            link_text: row.link_text,
            created_at: row.created_at,
        }
    }
}

#[async_trait]
impl DocumentLinkRepository for PgDocumentLinkRepository {
    type Error = PgDocumentLinkRepositoryError;

    async fn find_by_id(&self, id: DocumentLinkId) -> Result<Option<DocumentLink>, Self::Error> {
        let row = sqlx::query_as::<_, DocumentLinkRow>(
            r#"
            SELECT id, source_id, target_id, link_type, link_text, created_at
            FROM document_links
            WHERE id = $1
            "#,
        )
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(DocumentLink::from))
    }

    async fn find_by_source_id(&self, source_id: DocumentId) -> Result<Vec<DocumentLink>, Self::Error> {
        let rows = sqlx::query_as::<_, DocumentLinkRow>(
            r#"
            SELECT id, source_id, target_id, link_type, link_text, created_at
            FROM document_links
            WHERE source_id = $1
            ORDER BY created_at
            "#,
        )
        .bind(source_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(DocumentLink::from).collect())
    }

    async fn find_by_target_id(&self, target_id: DocumentId) -> Result<Vec<DocumentLink>, Self::Error> {
        let rows = sqlx::query_as::<_, DocumentLinkRow>(
            r#"
            SELECT id, source_id, target_id, link_type, link_text, created_at
            FROM document_links
            WHERE target_id = $1
            ORDER BY created_at
            "#,
        )
        .bind(target_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(DocumentLink::from).collect())
    }

    async fn save(&self, link: &DocumentLink) -> Result<(), Self::Error> {
        sqlx::query(
            r#"
            INSERT INTO document_links (id, source_id, target_id, link_type, link_text, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (id) DO UPDATE SET
                link_type = EXCLUDED.link_type,
                link_text = EXCLUDED.link_text
            "#,
        )
        .bind(link.id.as_uuid())
        .bind(link.source_id.as_uuid())
        .bind(link.target_id.as_uuid())
        .bind(link.link_type.as_str())
        .bind(&link.link_text)
        .bind(link.created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, id: DocumentLinkId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM document_links WHERE id = $1")
            .bind(id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete_by_source_id(&self, source_id: DocumentId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM document_links WHERE source_id = $1")
            .bind(source_id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete_by_document_id(&self, document_id: DocumentId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM document_links WHERE source_id = $1 OR target_id = $1")
            .bind(document_id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
