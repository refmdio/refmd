use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::application::ports::document_repository::{
    DocMeta, DocumentListState, DocumentRepository, SubtreeDocument,
};
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
        state: DocumentListState,
    ) -> anyhow::Result<Vec<DomainDocument>> {
        let archived_condition = match state {
            DocumentListState::Active => "d.archived_at IS NULL",
            DocumentListState::Archived => "d.archived_at IS NOT NULL",
            DocumentListState::All => "TRUE",
        };

        let rows = if let Some(t) = tag.as_ref().filter(|s| !s.trim().is_empty()) {
            let sql = format!(
                r#"SELECT d.id, d.title, d.parent_id, d.type, d.created_at, d.updated_at, d.path,
                          d.archived_at, d.archived_by, d.archived_parent_id
                   FROM document_tags dt
                   JOIN tags t ON t.id = dt.tag_id
                   JOIN documents d ON d.id = dt.document_id
                   WHERE d.owner_id = $1 AND {archived_condition} AND t.name ILIKE $2
                   ORDER BY d.updated_at DESC LIMIT 100"#,
                archived_condition = archived_condition,
            );
            sqlx::query(&sql)
                .bind(user_id)
                .bind(t)
                .fetch_all(&self.pool)
                .await?
        } else if let Some(ref qq) = query.as_ref().filter(|s| !s.trim().is_empty()) {
            let like = format!("%{}%", qq);
            let sql = format!(
                r#"SELECT d.id, d.title, d.parent_id, d.type, d.created_at, d.updated_at, d.path,
                          d.archived_at, d.archived_by, d.archived_parent_id
                   FROM documents d
                   WHERE d.owner_id = $1 AND {archived_condition} AND d.title ILIKE $2
                   ORDER BY d.updated_at DESC LIMIT 100"#,
                archived_condition = archived_condition,
            );
            sqlx::query(&sql)
                .bind(user_id)
                .bind(like)
                .fetch_all(&self.pool)
                .await?
        } else {
            let sql = format!(
                r#"SELECT d.id, d.title, d.parent_id, d.type, d.created_at, d.updated_at, d.path,
                          d.archived_at, d.archived_by, d.archived_parent_id
                   FROM documents d
                   WHERE d.owner_id = $1 AND {archived_condition}
                   ORDER BY d.updated_at DESC LIMIT 100"#,
                archived_condition = archived_condition,
            );
            sqlx::query(&sql)
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
                archived_at: r.try_get("archived_at").ok(),
                archived_by: r.try_get("archived_by").ok(),
                archived_parent_id: r.try_get("archived_parent_id").ok(),
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

    async fn list_paths_for_user(&self, user_id: Uuid) -> anyhow::Result<Vec<String>> {
        let rows = sqlx::query(
            r#"
            SELECT path
            FROM documents
            WHERE owner_id = $1
              AND path IS NOT NULL
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .filter_map(|r| r.try_get::<String, _>("path").ok())
            .collect())
    }

    async fn get_by_id(&self, id: Uuid) -> anyhow::Result<Option<DomainDocument>> {
        let row = sqlx::query(
            r#"SELECT id, title, parent_id, type, created_at, updated_at, path,
                      archived_at, archived_by, archived_parent_id
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
            archived_at: r.try_get("archived_at").ok(),
            archived_by: r.try_get("archived_by").ok(),
            archived_parent_id: r.try_get("archived_parent_id").ok(),
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
                r#"SELECT id, title, type, path, updated_at, archived_at
                   FROM documents WHERE owner_id = $1
                   AND archived_at IS NULL
                   ORDER BY updated_at DESC
                   LIMIT $2"#,
            )
            .bind(user_id)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                r#"SELECT id, title, type, path, updated_at, archived_at FROM documents
                   WHERE owner_id = $1 AND archived_at IS NULL
                     AND (LOWER(title) LIKE LOWER($2) OR title ILIKE $2)
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
               RETURNING id, title, parent_id, type, created_at, updated_at, path,
                         archived_at, archived_by, archived_parent_id"#,
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
            archived_at: row.try_get("archived_at").ok(),
            archived_by: row.try_get("archived_by").ok(),
            archived_parent_id: row.try_get("archived_parent_id").ok(),
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
                        RETURNING id, title, parent_id, type, created_at, updated_at, path,
                                  archived_at, archived_by, archived_parent_id"#,
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
                        RETURNING id, title, parent_id, type, created_at, updated_at, path,
                                  archived_at, archived_by, archived_parent_id"#,
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
            archived_at: r.try_get("archived_at").ok(),
            archived_by: r.try_get("archived_by").ok(),
            archived_parent_id: r.try_get("archived_parent_id").ok(),
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
        let row = sqlx::query(
            "SELECT type, path, title, archived_at FROM documents WHERE id = $1 AND owner_id = $2",
        )
        .bind(doc_id)
        .bind(owner_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| DocMeta {
            doc_type: r.get("type"),
            path: r.try_get("path").ok(),
            title: r.get("title"),
            archived_at: r.try_get("archived_at").ok(),
        }))
    }

    async fn archive_subtree(
        &self,
        doc_id: Uuid,
        owner_id: Uuid,
        archived_by: Uuid,
    ) -> anyhow::Result<Option<DomainDocument>> {
        let mut tx = self.pool.begin().await?;

        let updated = sqlx::query_scalar::<_, Uuid>(
            r#"
            WITH RECURSIVE subtree AS (
                SELECT id FROM documents WHERE id = $1 AND owner_id = $2
                UNION ALL
                SELECT d.id
                FROM documents d
                JOIN subtree sb ON d.parent_id = sb.id
                WHERE d.owner_id = $2
            ),
            removed_shares AS (
                DELETE FROM shares s
                USING subtree sb
                WHERE s.document_id = sb.id
                  AND s.created_by = $2
                RETURNING 1
            ),
            updated AS (
                UPDATE documents AS d
                SET archived_at = now(),
                    archived_by = $3,
                    archived_parent_id = d.parent_id,
                    parent_id = NULL,
                    updated_at = now()
                FROM subtree sb
                WHERE d.id = sb.id AND d.archived_at IS NULL
                RETURNING d.id
            )
            SELECT id FROM updated WHERE id = $1 LIMIT 1
            "#,
        )
        .bind(doc_id)
        .bind(owner_id)
        .bind(archived_by)
        .fetch_optional(&mut *tx)
        .await?;

        let root = if let Some(root_id) = updated {
            sqlx::query(
                r#"SELECT id, title, parent_id, type, created_at, updated_at, path,
                          archived_at, archived_by, archived_parent_id
                   FROM documents WHERE id = $1"#,
            )
            .bind(root_id)
            .fetch_optional(&mut *tx)
            .await?
            .map(|r| DomainDocument {
                id: r.get("id"),
                title: r.get("title"),
                parent_id: r.get("parent_id"),
                doc_type: r.get("type"),
                created_at: r.get("created_at"),
                updated_at: r.get("updated_at"),
                path: r.try_get("path").ok(),
                archived_at: r.try_get("archived_at").ok(),
                archived_by: r.try_get("archived_by").ok(),
                archived_parent_id: r.try_get("archived_parent_id").ok(),
            })
        } else {
            None
        };

        tx.commit().await?;
        Ok(root)
    }

    async fn unarchive_subtree(
        &self,
        doc_id: Uuid,
        owner_id: Uuid,
    ) -> anyhow::Result<Option<DomainDocument>> {
        let mut tx = self.pool.begin().await?;

        let updated = sqlx::query_scalar::<_, Uuid>(
            r#"
            WITH RECURSIVE subtree AS (
                SELECT id FROM documents WHERE id = $1 AND owner_id = $2
                UNION ALL
                SELECT d.id
                FROM documents d
                JOIN subtree sb ON d.archived_parent_id = sb.id
                WHERE d.owner_id = $2
            ),
            updated AS (
                UPDATE documents AS d
                SET parent_id = archived_parent_id,
                    archived_parent_id = NULL,
                    archived_at = NULL,
                    archived_by = NULL,
                    updated_at = now()
                FROM subtree sb
                WHERE d.id = sb.id AND d.archived_at IS NOT NULL
                RETURNING d.id
            )
            SELECT id FROM updated WHERE id = $1 LIMIT 1
            "#,
        )
        .bind(doc_id)
        .bind(owner_id)
        .fetch_optional(&mut *tx)
        .await?;

        let root = if let Some(root_id) = updated {
            sqlx::query(
                r#"SELECT id, title, parent_id, type, created_at, updated_at, path,
                          archived_at, archived_by, archived_parent_id
                   FROM documents WHERE id = $1"#,
            )
            .bind(root_id)
            .fetch_optional(&mut *tx)
            .await?
            .map(|r| DomainDocument {
                id: r.get("id"),
                title: r.get("title"),
                parent_id: r.get("parent_id"),
                doc_type: r.get("type"),
                created_at: r.get("created_at"),
                updated_at: r.get("updated_at"),
                path: r.try_get("path").ok(),
                archived_at: r.try_get("archived_at").ok(),
                archived_by: r.try_get("archived_by").ok(),
                archived_parent_id: r.try_get("archived_parent_id").ok(),
            })
        } else {
            None
        };

        tx.commit().await?;
        Ok(root)
    }

    async fn list_owned_subtree_documents(
        &self,
        owner_id: Uuid,
        root_id: Uuid,
    ) -> anyhow::Result<Vec<SubtreeDocument>> {
        let rows = sqlx::query(
            r#"
            WITH RECURSIVE subtree AS (
                SELECT id, type FROM documents WHERE id = $1 AND owner_id = $2
                UNION ALL
                SELECT d.id, d.type
                FROM documents d
                JOIN subtree sb ON COALESCE(d.parent_id, d.archived_parent_id) = sb.id
                WHERE d.owner_id = $2
            )
            SELECT id, type FROM subtree
            "#,
        )
        .bind(root_id)
        .bind(owner_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| SubtreeDocument {
                id: r.get("id"),
                doc_type: r.get("type"),
            })
            .collect())
    }

    async fn get_by_owner_and_path(
        &self,
        owner_id: Uuid,
        relative_path: &str,
    ) -> anyhow::Result<Option<DomainDocument>> {
        let row = sqlx::query(
            r#"SELECT id, title, parent_id, type, created_at, updated_at, path,
                      archived_at, archived_by, archived_parent_id
               FROM documents
               WHERE owner_id = $1 AND path = $2
               LIMIT 1"#,
        )
        .bind(owner_id)
        .bind(relative_path)
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
            archived_at: r.try_get("archived_at").ok(),
            archived_by: r.try_get("archived_by").ok(),
            archived_parent_id: r.try_get("archived_parent_id").ok(),
        }))
    }
}
