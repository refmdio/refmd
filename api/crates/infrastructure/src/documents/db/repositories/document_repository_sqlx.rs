use std::borrow::Cow;

use anyhow::anyhow;
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};
use uuid::Uuid;

use application::documents::ports::document_repository::{
    DocMeta, DocumentListState, DocumentPathConflictError, DocumentRepository, SubtreeDocument,
};
use domain::documents::document::{
    BacklinkInfo as DomBacklinkInfo, Document as DomainDocument, OutgoingLink as DomOutgoingLink,
    SearchHit,
};
use domain::documents::path as doc_path;
use crate::core::db::PgPool;

pub struct SqlxDocumentRepository {
    pub pool: PgPool,
}

impl SqlxDocumentRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn map_row_to_meta(row: &PgRow) -> DocMeta {
        DocMeta {
            workspace_id: row.get("workspace_id"),
            doc_type: row.get("type"),
            path: row.try_get("path").ok(),
            slug: row.get("slug"),
            desired_path: row.get("desired_path"),
            title: row.get("title"),
            archived_at: row.try_get("archived_at").ok(),
        }
    }

    fn map_row_to_document(row: &PgRow) -> DomainDocument {
        DomainDocument {
            id: row.get("id"),
            owner_id: row.get("owner_id"),
            owner_user_id: row.try_get("owner_user_id").ok(),
            workspace_id: row.get("workspace_id"),
            title: row.get("title"),
            parent_id: row.get("parent_id"),
            doc_type: row.get("type"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
            created_by_plugin: row.try_get("created_by_plugin").ok(),
            slug: row.get("slug"),
            desired_path: row.get("desired_path"),
            path: row.try_get("path").ok(),
            created_by: row.try_get("created_by").ok(),
            archived_at: row.try_get("archived_at").ok(),
            archived_by: row.try_get("archived_by").ok(),
            archived_parent_id: row.try_get("archived_parent_id").ok(),
        }
    }

    fn hash_path(desired_path: &str) -> Vec<u8> {
        Sha256::digest(desired_path.as_bytes()).to_vec()
    }

    fn owner_relative_path(owner_id: Uuid, desired_path: &str) -> String {
        format!("{owner_id}/{}", desired_path.trim_start_matches('/'))
    }

    async fn resolve_parent_folder_id(
        &self,
        workspace_id: Uuid,
        desired_parent_path: Option<&str>,
    ) -> anyhow::Result<Option<Uuid>> {
        let Some(path) = desired_parent_path.filter(|p| !p.is_empty()) else {
            return Ok(None);
        };
        let row = sqlx::query(
            r#"SELECT id, archived_at FROM documents
               WHERE workspace_id = $1 AND desired_path = $2 AND type = 'folder'
               LIMIT 1"#,
        )
        .bind(workspace_id)
        .bind(path)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => {
                let archived_at: Option<chrono::DateTime<chrono::Utc>> =
                    row.try_get("archived_at").ok();
                if archived_at.is_some() {
                    Err(anyhow!("parent_folder_archived"))
                } else {
                    Ok(Some(row.get("id")))
                }
            }
            None => Err(anyhow!("parent_folder_not_found")),
        }
    }

    async fn update_descendant_paths_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        root_id: Uuid,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            WITH RECURSIVE tree AS (
                SELECT id, desired_path, type
                FROM documents
                WHERE id = $1
                UNION ALL
                SELECT d.id,
                       CASE
                           WHEN d.type = 'folder' THEN tree.desired_path || '/' || d.slug
                           ELSE tree.desired_path || '/' || d.slug || '.md'
                       END AS desired_path,
                       d.type
                FROM documents d
                JOIN tree ON d.parent_id = tree.id
            )
            UPDATE documents AS doc
            SET desired_path = tree.desired_path,
                path_digest = digest(tree.desired_path, 'sha256'),
                updated_at = now()
            FROM tree
            WHERE doc.id = tree.id
              AND doc.id <> $1
            "#,
        )
        .bind(root_id)
        .execute(tx.as_mut())
        .await?;
        Ok(())
    }

    fn is_unique_violation(err: &sqlx::Error) -> bool {
        match err {
            sqlx::Error::Database(db_err) => {
                matches!(db_err.code(), Some(code) if code == Cow::Borrowed("23505"))
            }
            _ => false,
        }
    }

    fn is_anyhow_unique_violation(err: &anyhow::Error) -> bool {
        err.downcast_ref::<sqlx::Error>()
            .is_some_and(|sqlx_err| Self::is_unique_violation(sqlx_err))
    }
}

#[cfg(test)]
mod tests {
    use domain::documents::path as doc_path;

    #[test]
    fn slug_preserves_unicode_and_case() {
        assert_eq!(doc_path::slugify("Main"), "Main");
        assert_eq!(doc_path::slugify("Résumé2025"), "Résumé2025");
    }

    #[test]
    fn slug_sanitizes_forbidden_chars() {
        assert_eq!(doc_path::slugify(" Foo / Bar "), "Foo - Bar");
        assert_eq!(doc_path::slugify("////"), "untitled");
    }
}

#[async_trait]
impl DocumentRepository for SqlxDocumentRepository {
    async fn list_for_user(
        &self,
        workspace_id: Uuid,
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
                r#"SELECT d.*
                   FROM document_tags dt
                   JOIN tags t ON t.id = dt.tag_id
                   JOIN documents d ON d.id = dt.document_id
                   WHERE d.workspace_id = $1 AND {archived_condition} AND t.name ILIKE $2
                   ORDER BY d.updated_at DESC LIMIT 100"#,
                archived_condition = archived_condition,
            );
            sqlx::query(&sql)
                .bind(workspace_id)
                .bind(t)
                .fetch_all(&self.pool)
                .await?
        } else if let Some(ref qq) = query.as_ref().filter(|s| !s.trim().is_empty()) {
            let like = format!("%{}%", qq);
            let sql = format!(
                r#"SELECT d.*
                   FROM documents d
                   WHERE d.workspace_id = $1 AND {archived_condition} AND d.title ILIKE $2
                   ORDER BY d.updated_at DESC LIMIT 100"#,
                archived_condition = archived_condition,
            );
            sqlx::query(&sql)
                .bind(workspace_id)
                .bind(like)
                .fetch_all(&self.pool)
                .await?
        } else {
            let sql = format!(
                r#"SELECT d.*
                   FROM documents d
                   WHERE d.workspace_id = $1 AND {archived_condition}
                   ORDER BY d.updated_at DESC LIMIT 100"#,
                archived_condition = archived_condition,
            );
            sqlx::query(&sql)
                .bind(workspace_id)
                .fetch_all(&self.pool)
                .await?
        };

        Ok(rows
            .into_iter()
            .map(|r| Self::map_row_to_document(&r))
            .collect())
    }

    async fn list_ids_for_user(&self, workspace_id: Uuid) -> anyhow::Result<Vec<Uuid>> {
        let rows = sqlx::query("SELECT id FROM documents WHERE workspace_id = $1")
            .bind(workspace_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|r| r.get("id")).collect())
    }

    async fn list_paths_for_user(&self, workspace_id: Uuid) -> anyhow::Result<Vec<String>> {
        let rows = sqlx::query(
            r#"
            SELECT path
            FROM documents
            WHERE workspace_id = $1
              AND path IS NOT NULL
              AND type <> 'folder'
            "#,
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .filter_map(|r| r.try_get::<String, _>("path").ok())
            .collect())
    }

    async fn list_workspace_documents(
        &self,
        workspace_id: Uuid,
    ) -> anyhow::Result<Vec<DomainDocument>> {
        let rows = sqlx::query("SELECT * FROM documents WHERE workspace_id = $1")
            .bind(workspace_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| Self::map_row_to_document(&r))
            .collect())
    }

    async fn get_by_id(&self, id: Uuid) -> anyhow::Result<Option<DomainDocument>> {
        let row = sqlx::query(r#"SELECT * FROM documents WHERE id = $1"#)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| Self::map_row_to_document(&r)))
    }

    async fn search_for_user(
        &self,
        workspace_id: Uuid,
        query: Option<String>,
        limit: i64,
    ) -> anyhow::Result<Vec<SearchHit>> {
        let q = query.unwrap_or_default();
        let like = format!("%{}%", q);
        let rows = if q.trim().is_empty() {
            sqlx::query(
                r#"SELECT id, title, type, path, updated_at, archived_at
                   FROM documents WHERE workspace_id = $1
                   AND archived_at IS NULL
                   ORDER BY updated_at DESC
                   LIMIT $2"#,
            )
            .bind(workspace_id)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                r#"SELECT id, title, type, path, updated_at, archived_at FROM documents
                   WHERE workspace_id = $1 AND archived_at IS NULL
                     AND (LOWER(title) LIKE LOWER($2) OR title ILIKE $2)
                   ORDER BY CASE WHEN LOWER(title) = LOWER($3) THEN 0 ELSE 1 END, LENGTH(title), updated_at DESC
                   LIMIT $4"#
            )
                .bind(workspace_id)
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
        workspace_id: Uuid,
        created_by: Uuid,
        title: &str,
        parent_id: Option<Uuid>,
        doc_type: &str,
        created_by_plugin: Option<&str>,
    ) -> anyhow::Result<DomainDocument> {
        let mut tx = self.pool.begin().await?;
        let doc = self
            .create_for_user_tx(
                &mut tx,
                workspace_id,
                created_by,
                title,
                parent_id,
                doc_type,
                created_by_plugin,
            )
            .await?;
        tx.commit().await?;
        Ok(doc)
    }

    async fn create_for_user_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        workspace_id: Uuid,
        created_by: Uuid,
        title: &str,
        parent_id: Option<Uuid>,
        doc_type: &str,
        created_by_plugin: Option<&str>,
    ) -> anyhow::Result<DomainDocument> {
        sqlx::query("SAVEPOINT document_create")
            .execute(tx.as_mut())
            .await?;
        let base_slug = doc_path::slugify(title);
        let mut attempt = 0usize;
        loop {
            let slug = doc_path::apply_slug_suffix(&base_slug, attempt);
            let parent_path = if let Some(pid) = parent_id {
                let path = sqlx::query_scalar::<_, Option<String>>(
                    "SELECT desired_path FROM documents WHERE id = $1",
                )
                .bind(pid)
                .fetch_optional(&self.pool)
                .await?
                .flatten()
                .ok_or_else(|| anyhow!("parent_document_not_found"))?;
                Some(path)
            } else {
                None
            };
            let desired_path = doc_path::build_desired_path(parent_path.as_deref(), &slug, doc_type);
            let repo_path = Self::owner_relative_path(workspace_id, &desired_path);
            let path_digest = Self::hash_path(&desired_path);
            let row = sqlx::query(
                r#"INSERT INTO documents (title, owner_id, owner_user_id, workspace_id, created_by, created_by_plugin, parent_id, type, slug, desired_path, path, path_digest)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                   RETURNING *"#,
            )
            .bind(title)
            .bind(workspace_id)
            .bind(created_by)
            .bind(workspace_id)
            .bind(created_by)
            .bind(created_by_plugin)
            .bind(parent_id)
            .bind(doc_type)
            .bind(&slug)
            .bind(&desired_path)
            .bind(&repo_path)
            .bind(&path_digest)
            .fetch_one(tx.as_mut())
            .await;
            match row {
                Ok(row) => {
                    sqlx::query("RELEASE SAVEPOINT document_create")
                        .execute(tx.as_mut())
                        .await
                        .ok();
                    return Ok(Self::map_row_to_document(&row));
                }
                Err(err) if Self::is_unique_violation(&err) => {
                    sqlx::query("ROLLBACK TO SAVEPOINT document_create")
                        .execute(tx.as_mut())
                        .await?;
                    attempt += 1;
                    continue;
                }
                Err(err) => {
                    sqlx::query("ROLLBACK TO SAVEPOINT document_create")
                        .execute(tx.as_mut())
                        .await
                        .ok();
                    if Self::is_unique_violation(&err) {
                        return Err(DocumentPathConflictError.into());
                    }
                    return Err(err.into());
                }
            }
        }
    }

    async fn update_title_and_parent_for_user(
        &self,
        id: Uuid,
        workspace_id: Uuid,
        title: Option<String>,
        parent_id: Option<Option<Uuid>>,
    ) -> anyhow::Result<Option<DomainDocument>> {
        let mut tx = self.pool.begin().await?;
        let doc = self
            .update_title_and_parent_for_user_tx(&mut tx, id, workspace_id, title, parent_id)
            .await?;
        tx.commit().await?;
        Ok(doc)
    }

    async fn update_title_and_parent_for_user_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
        workspace_id: Uuid,
        title: Option<String>,
        parent_id: Option<Option<Uuid>>,
    ) -> anyhow::Result<Option<DomainDocument>> {
        let current = sqlx::query(
            r#"SELECT title, parent_id, type, slug
               FROM documents
               WHERE id = $1 AND workspace_id = $2"#,
        )
        .bind(id)
        .bind(workspace_id)
        .fetch_optional(tx.as_mut())
        .await?;
        let Some(current) = current else {
            return Ok(None);
        };

        let next_title = title.clone().unwrap_or_else(|| current.get("title"));
        let next_parent: Option<Uuid> = match parent_id {
            None => current.get("parent_id"),
            Some(new_parent) => new_parent,
        };
        let doc_type: String = current.get("type");
        let base_slug = if title.is_some() {
            doc_path::slugify(&next_title)
        } else {
            current.get("slug")
        };

        sqlx::query("SAVEPOINT document_update")
            .execute(tx.as_mut())
            .await?;
        let mut attempt = 0usize;
        loop {
            let slug = doc_path::apply_slug_suffix(&base_slug, attempt);
            let parent_path = if let Some(pid) = next_parent {
                let path = sqlx::query_scalar::<_, Option<String>>(
                    "SELECT desired_path FROM documents WHERE id = $1",
                )
                .bind(pid)
                .fetch_optional(&self.pool)
                .await?
                .flatten()
                .ok_or_else(|| anyhow!("parent_document_not_found"))?;
                Some(path)
            } else {
                None
            };
            let desired_path = doc_path::build_desired_path(parent_path.as_deref(), &slug, &doc_type);
            let path_digest = Self::hash_path(&desired_path);
            let row = sqlx::query(
                r#"UPDATE documents SET
                        title = $1,
                        parent_id = $2,
                        slug = $3,
                        desired_path = $4,
                        path_digest = $5,
                        updated_at = now()
                    WHERE id = $6 AND workspace_id = $7
                    RETURNING *"#,
            )
            .bind(&next_title)
            .bind(next_parent)
            .bind(&slug)
            .bind(&desired_path)
            .bind(&path_digest)
            .bind(id)
            .bind(workspace_id)
            .fetch_optional(tx.as_mut())
            .await;
            match row {
                Ok(Some(row)) => {
                    let doc = Self::map_row_to_document(&row);
                    if doc.doc_type == "folder" {
                        sqlx::query("SAVEPOINT document_update_descendants")
                            .execute(tx.as_mut())
                            .await?;
                        let result =
                            self.update_descendant_paths_tx(tx, doc.id)
                                .await
                                .map_err(|err| {
                                    if Self::is_anyhow_unique_violation(&err) {
                                        anyhow::Error::new(DocumentPathConflictError)
                                    } else {
                                        err
                                    }
                                });
                        match result {
                            Ok(()) => {
                                sqlx::query("RELEASE SAVEPOINT document_update_descendants")
                                    .execute(tx.as_mut())
                                    .await
                                    .ok();
                            }
                            Err(err) => {
                                sqlx::query("ROLLBACK TO SAVEPOINT document_update_descendants")
                                    .execute(tx.as_mut())
                                    .await
                                    .ok();
                                sqlx::query("ROLLBACK TO SAVEPOINT document_update")
                                    .execute(tx.as_mut())
                                    .await
                                    .ok();
                                return Err(err);
                            }
                        }
                    }
                    sqlx::query("RELEASE SAVEPOINT document_update")
                        .execute(tx.as_mut())
                        .await
                        .ok();
                    return Ok(Some(doc));
                }
                Ok(None) => {
                    sqlx::query("RELEASE SAVEPOINT document_update")
                        .execute(tx.as_mut())
                        .await
                        .ok();
                    return Ok(None);
                }
                Err(err) if Self::is_unique_violation(&err) => {
                    sqlx::query("ROLLBACK TO SAVEPOINT document_update")
                        .execute(tx.as_mut())
                        .await?;
                    attempt += 1;
                    continue;
                }
                Err(err) => {
                    sqlx::query("ROLLBACK TO SAVEPOINT document_update")
                        .execute(tx.as_mut())
                        .await
                        .ok();
                    return Err(err.into());
                }
            }
        }
    }

    async fn delete_owned(&self, id: Uuid, workspace_id: Uuid) -> anyhow::Result<Option<String>> {
        let mut tx = self.pool.begin().await?;
        let res = self.delete_owned_tx(&mut tx, id, workspace_id).await?;
        tx.commit().await?;
        Ok(res)
    }

    async fn delete_owned_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
        workspace_id: Uuid,
    ) -> anyhow::Result<Option<String>> {
        // fetch type
        let row = sqlx::query(r#"SELECT type FROM documents WHERE id = $1 AND workspace_id = $2"#)
            .bind(id)
            .bind(workspace_id)
            .fetch_optional(tx.as_mut())
            .await?;
        let dtype: String = match row {
            Some(r) => r.get("type"),
            None => return Ok(None),
        };
        let res = sqlx::query(r#"DELETE FROM documents WHERE id = $1 AND workspace_id = $2"#)
            .bind(id)
            .bind(workspace_id)
            .execute(tx.as_mut())
            .await?;
        if res.rows_affected() > 0 {
            Ok(Some(dtype))
        } else {
            Ok(None)
        }
    }

    async fn backlinks_for(
        &self,
        workspace_id: Uuid,
        target_id: Uuid,
    ) -> anyhow::Result<Vec<DomBacklinkInfo>> {
        let rows = sqlx::query(
            r#"SELECT d.id as document_id, d.title, d.type as document_type, d.path as file_path,
                      dl.link_type, dl.link_text, COUNT(*)::BIGINT as link_count
               FROM document_links dl
               JOIN documents d ON d.id = dl.source_document_id
               WHERE dl.target_document_id = $1 AND d.workspace_id = $2
               GROUP BY d.id, d.title, d.type, d.path, dl.link_type, dl.link_text
               ORDER BY link_count DESC, d.title"#,
        )
        .bind(target_id)
        .bind(workspace_id)
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
        workspace_id: Uuid,
        source_id: Uuid,
    ) -> anyhow::Result<Vec<DomOutgoingLink>> {
        let rows = sqlx::query(
            r#"SELECT d.id as document_id, d.title, d.type as document_type, d.path as file_path,
                      dl.link_type, dl.link_text, dl.position_start, dl.position_end
               FROM document_links dl
               JOIN documents d ON d.id = dl.target_document_id
               WHERE dl.source_document_id = $1 AND d.workspace_id = $2
               ORDER BY dl.position_start"#,
        )
        .bind(source_id)
        .bind(workspace_id)
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
        workspace_id: Uuid,
    ) -> anyhow::Result<Option<DocMeta>> {
        let row = sqlx::query(
            "SELECT workspace_id, type, path, slug, desired_path, title, archived_at FROM documents WHERE id = $1 AND workspace_id = $2",
        )
        .bind(doc_id)
        .bind(workspace_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.as_ref().map(SqlxDocumentRepository::map_row_to_meta))
    }

    async fn get_meta_for_owner_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        doc_id: Uuid,
        workspace_id: Uuid,
    ) -> anyhow::Result<Option<DocMeta>> {
        let row = sqlx::query(
            "SELECT workspace_id, type, path, slug, desired_path, title, archived_at FROM documents WHERE id = $1 AND workspace_id = $2 FOR UPDATE",
        )
        .bind(doc_id)
        .bind(workspace_id)
        .fetch_optional(tx.as_mut())
        .await?;
        Ok(row.as_ref().map(SqlxDocumentRepository::map_row_to_meta))
    }

    async fn archive_subtree(
        &self,
        doc_id: Uuid,
        workspace_id: Uuid,
        archived_by: Uuid,
    ) -> anyhow::Result<Option<DomainDocument>> {
        let mut tx = self.pool.begin().await?;
        let doc = self
            .archive_subtree_tx(&mut tx, doc_id, workspace_id, archived_by)
            .await?;
        tx.commit().await?;
        Ok(doc)
    }

    async fn archive_subtree_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        doc_id: Uuid,
        workspace_id: Uuid,
        archived_by: Uuid,
    ) -> anyhow::Result<Option<DomainDocument>> {
        let updated = sqlx::query_scalar::<_, Uuid>(
            r#"
            WITH RECURSIVE subtree AS (
                SELECT id FROM documents WHERE id = $1 AND workspace_id = $2
                UNION ALL
                SELECT d.id
                FROM documents d
                JOIN subtree sb ON d.parent_id = sb.id
                WHERE d.workspace_id = $2
            ),
            removed_shares AS (
                DELETE FROM shares s
                USING subtree sb
                WHERE s.document_id = sb.id
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
        .bind(workspace_id)
        .bind(archived_by)
        .fetch_optional(tx.as_mut())
        .await?;

        let root = if let Some(root_id) = updated {
            sqlx::query(r#"SELECT * FROM documents WHERE id = $1"#)
                .bind(root_id)
                .fetch_optional(tx.as_mut())
                .await?
                .map(|r| Self::map_row_to_document(&r))
        } else {
            None
        };

        Ok(root)
    }

    async fn unarchive_subtree(
        &self,
        doc_id: Uuid,
        workspace_id: Uuid,
    ) -> anyhow::Result<Option<DomainDocument>> {
        let mut tx = self.pool.begin().await?;
        let doc = self
            .unarchive_subtree_tx(&mut tx, doc_id, workspace_id)
            .await?;
        tx.commit().await?;
        Ok(doc)
    }

    async fn unarchive_subtree_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        doc_id: Uuid,
        workspace_id: Uuid,
    ) -> anyhow::Result<Option<DomainDocument>> {
        let updated = sqlx::query_scalar::<_, Uuid>(
            r#"
            WITH RECURSIVE subtree AS (
                SELECT id FROM documents WHERE id = $1 AND workspace_id = $2
                UNION ALL
                SELECT d.id
                FROM documents d
                JOIN subtree sb ON d.archived_parent_id = sb.id
                WHERE d.workspace_id = $2
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
        .bind(workspace_id)
        .fetch_optional(tx.as_mut())
        .await?;

        let root = if let Some(root_id) = updated {
            sqlx::query(r#"SELECT * FROM documents WHERE id = $1"#)
                .bind(root_id)
                .fetch_optional(tx.as_mut())
                .await?
                .map(|r| Self::map_row_to_document(&r))
        } else {
            None
        };

        Ok(root)
    }

    async fn list_owned_subtree_documents(
        &self,
        workspace_id: Uuid,
        root_id: Uuid,
    ) -> anyhow::Result<Vec<SubtreeDocument>> {
        let rows = sqlx::query(
            r#"
            WITH RECURSIVE subtree AS (
                SELECT id, type FROM documents WHERE id = $1 AND workspace_id = $2
                UNION ALL
                SELECT d.id, d.type
                FROM documents d
                JOIN subtree sb ON COALESCE(d.parent_id, d.archived_parent_id) = sb.id
                WHERE d.workspace_id = $2
            )
            SELECT id, type FROM subtree
            "#,
        )
        .bind(root_id)
        .bind(workspace_id)
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

    async fn list_owned_subtree_documents_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        workspace_id: Uuid,
        root_id: Uuid,
    ) -> anyhow::Result<Vec<SubtreeDocument>> {
        let rows = sqlx::query(
            r#"
            WITH RECURSIVE subtree AS (
                SELECT id, type FROM documents WHERE id = $1 AND workspace_id = $2
                UNION ALL
                SELECT d.id, d.type
                FROM documents d
                JOIN subtree sb ON COALESCE(d.parent_id, d.archived_parent_id) = sb.id
                WHERE d.workspace_id = $2
            )
            SELECT id, type FROM subtree FOR UPDATE
            "#,
        )
        .bind(root_id)
        .bind(workspace_id)
        .fetch_all(tx.as_mut())
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
        workspace_id: Uuid,
        relative_path: &str,
    ) -> anyhow::Result<Option<DomainDocument>> {
        let row = sqlx::query(
            r#"SELECT *
               FROM documents
               WHERE workspace_id = $1 AND path = $2
               LIMIT 1"#,
        )
        .bind(workspace_id)
        .bind(relative_path)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| Self::map_row_to_document(&r)))
    }

    async fn update_repo_path(
        &self,
        doc_id: Uuid,
        workspace_id: Uuid,
        relative_path: &str,
    ) -> anyhow::Result<()> {
        let trimmed = relative_path.trim_start_matches('/');
        let owner_prefix = workspace_id.to_string();
        let desired_path = if let Some(rest) = trimmed.strip_prefix(&owner_prefix) {
            rest.trim_start_matches('/').to_string()
        } else {
            trimmed.to_string()
        };
        if desired_path.is_empty() {
            return Err(anyhow!("invalid_relative_path"));
        }
        let slug = doc_path::slug_from_desired_path(&desired_path)?;
        let parent_path = doc_path::parent_desired_path(&desired_path);
        let parent_id = self
            .resolve_parent_folder_id(workspace_id, parent_path.as_deref())
            .await?;
        let normalized_path = Self::owner_relative_path(workspace_id, &desired_path);
        let path_digest = Self::hash_path(&desired_path);
        sqlx::query(
            r#"UPDATE documents SET
                    path = $3,
                    desired_path = $4,
                    path_digest = $5,
                    slug = $6,
                    parent_id = $7,
                    updated_at = now()
                WHERE id = $1 AND workspace_id = $2"#,
        )
        .bind(doc_id)
        .bind(workspace_id)
        .bind(&normalized_path)
        .bind(&desired_path)
        .bind(&path_digest)
        .bind(&slug)
        .bind(parent_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
