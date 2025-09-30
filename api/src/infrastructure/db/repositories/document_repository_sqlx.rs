use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::application::ports::document_repository::DocMeta;
use crate::application::ports::document_repository::DocumentRepository;
use crate::domain::documents::document::{
    BacklinkInfo as DomBacklinkInfo, Document as DomainDocument, OutgoingLink as DomOutgoingLink,
    SearchHit,
};
use crate::infrastructure::db::PgPool;

pub struct SqlxDocumentRepository {
    pub pool: PgPool,
}

impl SqlxDocumentRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DocumentRepository for SqlxDocumentRepository {
    async fn list_for_user(
        &self,
        user_id: Uuid,
        query: Option<String>,
        tag: Option<String>,
    ) -> anyhow::Result<Vec<DomainDocument>> {
        let rows = if let Some(t) = tag.as_ref().filter(|s| !s.trim().is_empty()) {
            sqlx::query(
                r#"SELECT d.id, d.title, d.parent_id, d.type, d.created_at, d.updated_at, d.path
                           FROM document_tags dt
                           JOIN tags t ON t.id = dt.tag_id
                           JOIN documents d ON d.id = dt.document_id
                           WHERE d.owner_id = $1 AND t.name ILIKE $2
                           ORDER BY d.updated_at DESC LIMIT 100"#,
            )
            .bind(user_id)
            .bind(t)
            .fetch_all(&self.pool)
            .await?
        } else if let Some(ref qq) = query.as_ref().filter(|s| !s.trim().is_empty()) {
            let like = format!("%{}%", qq);
            sqlx::query(
                r#"SELECT id, title, parent_id, type, created_at, updated_at, path
                           FROM documents
                           WHERE owner_id = $1 AND title ILIKE $2
                           ORDER BY updated_at DESC LIMIT 100"#,
            )
            .bind(user_id)
            .bind(like)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                r#"SELECT id, title, parent_id, type, created_at, updated_at, path
                           FROM documents
                           WHERE owner_id = $1
                           ORDER BY updated_at DESC LIMIT 100"#,
            )
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?
        };

        let items = rows
            .into_iter()
            .map(|r| DomainDocument {
                id: r.get("id"),
                title: r.get("title"),
                parent_id: r.get("parent_id"),
                doc_type: r.get("type"),
                created_at: r.get("created_at"),
                updated_at: r.get("updated_at"),
                path: r.try_get("path").ok(),
            })
            .collect();
        Ok(items)
    }

    async fn list_ids_for_user(&self, user_id: Uuid) -> anyhow::Result<Vec<Uuid>> {
        let rows = sqlx::query("SELECT id FROM documents WHERE owner_id = $1")
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|r| r.get("id")).collect())
    }

    async fn get_by_id(&self, id: Uuid) -> anyhow::Result<Option<DomainDocument>> {
        let row = sqlx::query(
            r#"SELECT id, title, parent_id, type, created_at, updated_at, path
               FROM documents WHERE id = $1"#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| DomainDocument {
            id: r.get("id"),
            title: r.get("title"),
            parent_id: r.get("parent_id"),
            doc_type: r.get("type"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
            path: r.try_get("path").ok(),
        }))
    }

    async fn search_for_user(
        &self,
        user_id: Uuid,
        query: Option<String>,
        limit: i64,
    ) -> anyhow::Result<Vec<SearchHit>> {
        let q = query.unwrap_or_default();
        let like = format!("%{}%", q);
        let rows = if q.trim().is_empty() {
            sqlx::query(
                r#"SELECT id, title, type, path, updated_at
                   FROM documents WHERE owner_id = $1
                   ORDER BY updated_at DESC
                   LIMIT $2"#,
            )
            .bind(user_id)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                r#"SELECT id, title, type, path, updated_at FROM documents
                   WHERE owner_id = $1 AND (LOWER(title) LIKE LOWER($2) OR title ILIKE $2)
                   ORDER BY CASE WHEN LOWER(title) = LOWER($3) THEN 0 ELSE 1 END, LENGTH(title), updated_at DESC
                   LIMIT $4"#
            )
                .bind(user_id)
                .bind(like)
                .bind(&q)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
        };
        let out = rows
            .into_iter()
            .map(|r| SearchHit {
                id: r.get("id"),
                title: r.get("title"),
                doc_type: r.get::<String, _>("type"),
                path: r.try_get("path").ok(),
                updated_at: r.get("updated_at"),
            })
            .collect();
        Ok(out)
    }

    async fn create_for_user(
        &self,
        user_id: Uuid,
        title: &str,
        parent_id: Option<Uuid>,
        doc_type: &str,
    ) -> anyhow::Result<DomainDocument> {
        let row = sqlx::query(
            r#"INSERT INTO documents (title, owner_id, parent_id, type, path)
               VALUES ($1, $2, $3, $4, NULL)
               RETURNING id, title, parent_id, type, created_at, updated_at, path"#,
        )
        .bind(title)
        .bind(user_id)
        .bind(parent_id)
        .bind(doc_type)
        .fetch_one(&self.pool)
        .await?;
        Ok(DomainDocument {
            id: row.get("id"),
            title: row.get("title"),
            parent_id: row.get("parent_id"),
            doc_type: row.get("type"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
            path: row.try_get("path").ok(),
        })
    }

    async fn update_title_and_parent_for_user(
        &self,
        id: Uuid,
        user_id: Uuid,
        title: Option<String>,
        parent_id: Option<Option<Uuid>>,
    ) -> anyhow::Result<Option<DomainDocument>> {
        let row = match parent_id {
            None => {
                sqlx::query(
                    r#"UPDATE documents SET
                            title = COALESCE($1, title),
                            updated_at = now()
                        WHERE id = $2 AND owner_id = $3
                        RETURNING id, title, parent_id, type, created_at, updated_at, path"#,
                )
                .bind(title)
                .bind(id)
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await?
            }
            Some(newp) => {
                sqlx::query(
                    r#"UPDATE documents SET
                            title = COALESCE($1, title),
                            parent_id = $2,
                            updated_at = now()
                        WHERE id = $3 AND owner_id = $4
                        RETURNING id, title, parent_id, type, created_at, updated_at, path"#,
                )
                .bind(title)
                .bind(newp)
                .bind(id)
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await?
            }
        };
        Ok(row.map(|r| DomainDocument {
            id: r.get("id"),
            title: r.get("title"),
            parent_id: r.get("parent_id"),
            doc_type: r.get("type"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
            path: r.try_get("path").ok(),
        }))
    }

    async fn delete_owned(&self, id: Uuid, user_id: Uuid) -> anyhow::Result<Option<String>> {
        // fetch type
        let row = sqlx::query(r#"SELECT type FROM documents WHERE id = $1 AND owner_id = $2"#)
            .bind(id)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
        let dtype: String = match row {
            Some(r) => r.get("type"),
            None => return Ok(None),
        };
        let res = sqlx::query(r#"DELETE FROM documents WHERE id = $1 AND owner_id = $2"#)
            .bind(id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        if res.rows_affected() > 0 {
            Ok(Some(dtype))
        } else {
            Ok(None)
        }
    }

    async fn backlinks_for(
        &self,
        owner_id: Uuid,
        target_id: Uuid,
    ) -> anyhow::Result<Vec<DomBacklinkInfo>> {
        let rows = sqlx::query(
            r#"SELECT d.id as document_id, d.title, d.type as document_type, d.path as file_path,
                      dl.link_type, dl.link_text, COUNT(*)::BIGINT as link_count
               FROM document_links dl
               JOIN documents d ON d.id = dl.source_document_id
               WHERE dl.target_document_id = $1 AND d.owner_id = $2
               GROUP BY d.id, d.title, d.type, d.path, dl.link_type, dl.link_text
               ORDER BY link_count DESC, d.title"#,
        )
        .bind(target_id)
        .bind(owner_id)
        .fetch_all(&self.pool)
        .await?;
        let out = rows
            .into_iter()
            .map(|r| DomBacklinkInfo {
                document_id: r.get("document_id"),
                title: r.get("title"),
                document_type: r.get("document_type"),
                file_path: r.try_get("file_path").ok(),
                link_type: r.get("link_type"),
                link_text: r.try_get("link_text").ok(),
                link_count: r.try_get("link_count").unwrap_or(1_i64),
            })
            .collect();
        Ok(out)
    }

    async fn outgoing_links_for(
        &self,
        owner_id: Uuid,
        source_id: Uuid,
    ) -> anyhow::Result<Vec<DomOutgoingLink>> {
        let rows = sqlx::query(
            r#"SELECT d.id as document_id, d.title, d.type as document_type, d.path as file_path,
                      dl.link_type, dl.link_text, dl.position_start, dl.position_end
               FROM document_links dl
               JOIN documents d ON d.id = dl.target_document_id
               WHERE dl.source_document_id = $1 AND d.owner_id = $2
               ORDER BY dl.position_start"#,
        )
        .bind(source_id)
        .bind(owner_id)
        .fetch_all(&self.pool)
        .await?;
        let out = rows
            .into_iter()
            .map(|r| DomOutgoingLink {
                document_id: r.get("document_id"),
                title: r.get("title"),
                document_type: r.get("document_type"),
                file_path: r.try_get("file_path").ok(),
                link_type: r.get("link_type"),
                link_text: r.try_get("link_text").ok(),
                position_start: r.try_get("position_start").ok(),
                position_end: r.try_get("position_end").ok(),
            })
            .collect();
        Ok(out)
    }

    async fn get_meta_for_owner(
        &self,
        doc_id: Uuid,
        owner_id: Uuid,
    ) -> anyhow::Result<Option<DocMeta>> {
        let row =
            sqlx::query("SELECT type, path, title FROM documents WHERE id = $1 AND owner_id = $2")
                .bind(doc_id)
                .bind(owner_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|r| DocMeta {
            doc_type: r.get("type"),
            path: r.try_get("path").ok(),
            title: r.get("title"),
        }))
    }
}
