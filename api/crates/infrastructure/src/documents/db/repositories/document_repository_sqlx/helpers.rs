use std::borrow::Cow;

use anyhow::{Context, anyhow};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};
use uuid::Uuid;

use application::documents::ports::document_repository::{
    DocMeta, DocumentPathConflictError, SubtreeDocument,
};
use domain::documents::doc_type::DocumentType;
use domain::documents::document::Document as DomainDocument;
use domain::documents::path as doc_path;
use domain::documents::title::Title;

use super::SqlxDocumentRepository;

impl SqlxDocumentRepository {
    pub(super) fn map_row_to_meta(row: &PgRow) -> anyhow::Result<DocMeta> {
        let doc_type_str: String = row.get("type");
        let doc_type =
            DocumentType::try_from(doc_type_str.as_str()).context("invalid_document_type")?;
        let slug_str: String = row.get("slug");
        let slug = doc_path::Slug::new(slug_str).context("invalid_slug")?;
        let desired_path_str: String = row.get("desired_path");
        let desired_path = doc_path::DesiredPath::new(desired_path_str);
        let title: String = row.get("title");
        Ok(DocMeta {
            workspace_id: row.get("workspace_id"),
            doc_type,
            path: row.try_get("path").ok(),
            slug,
            desired_path,
            title: Title::new(title),
            archived_at: row.try_get("archived_at").ok(),
        })
    }

    pub(super) fn map_row_to_document(row: &PgRow) -> anyhow::Result<DomainDocument> {
        let doc_type_str: String = row.get("type");
        let doc_type =
            DocumentType::try_from(doc_type_str.as_str()).context("invalid_document_type")?;
        let title: String = row.get("title");
        let slug_str: String = row.get("slug");
        let slug = doc_path::Slug::new(slug_str).context("invalid_slug")?;
        let desired_path_str: String = row.get("desired_path");
        let desired_path = doc_path::DesiredPath::new(desired_path_str);
        Ok(DomainDocument {
            id: row.get("id"),
            owner_id: row.get("owner_id"),
            owner_user_id: row.try_get("owner_user_id").ok(),
            workspace_id: row.get("workspace_id"),
            title: Title::new(title),
            parent_id: row.get("parent_id"),
            doc_type,
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
            created_by_plugin: row.try_get("created_by_plugin").ok(),
            slug,
            desired_path,
            path: row.try_get("path").ok(),
            created_by: row.try_get("created_by").ok(),
            archived_at: row.try_get("archived_at").ok(),
            archived_by: row.try_get("archived_by").ok(),
            archived_parent_id: row.try_get("archived_parent_id").ok(),
        })
    }

    pub(super) fn hash_path(desired_path: &str) -> Vec<u8> {
        Sha256::digest(desired_path.as_bytes()).to_vec()
    }

    pub(super) fn owner_relative_path(owner_id: Uuid, desired_path: &str) -> String {
        format!("{owner_id}/{}", desired_path.trim_start_matches('/'))
    }

    pub(super) async fn resolve_parent_folder_id(
        &self,
        workspace_id: Uuid,
        desired_parent_path: Option<&doc_path::DesiredPath>,
    ) -> anyhow::Result<Option<Uuid>> {
        let Some(path) = desired_parent_path
            .map(|p| p.as_str())
            .filter(|p| !p.is_empty())
        else {
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

    pub(super) async fn update_descendant_paths_tx(
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

    pub(super) fn is_unique_violation(err: &sqlx::Error) -> bool {
        match err {
            sqlx::Error::Database(db_err) => {
                matches!(db_err.code(), Some(code) if code == Cow::Borrowed("23505"))
            }
            _ => false,
        }
    }

    pub(super) fn is_anyhow_unique_violation(err: &anyhow::Error) -> bool {
        err.downcast_ref::<sqlx::Error>()
            .is_some_and(|sqlx_err| Self::is_unique_violation(sqlx_err))
    }

    pub(crate) async fn create_for_user_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        workspace_id: Uuid,
        created_by: Uuid,
        title: &Title,
        parent_id: Option<Uuid>,
        doc_type: DocumentType,
        created_by_plugin: Option<&str>,
        slug: &doc_path::Slug,
        desired_path: &doc_path::DesiredPath,
    ) -> anyhow::Result<DomainDocument> {
        sqlx::query("SAVEPOINT document_create")
            .execute(tx.as_mut())
            .await?;
        let repo_path = Self::owner_relative_path(workspace_id, desired_path.as_str());
        let path_digest = Self::hash_path(desired_path.as_str());
        let row = sqlx::query(
            r#"INSERT INTO documents (title, owner_id, owner_user_id, workspace_id, created_by, created_by_plugin, parent_id, type, slug, desired_path, path, path_digest)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
               RETURNING *"#,
        )
        .bind(title.as_str())
        .bind(workspace_id)
        .bind(created_by)
        .bind(workspace_id)
        .bind(created_by)
        .bind(created_by_plugin)
        .bind(parent_id)
        .bind(doc_type.as_str())
        .bind(slug.as_str())
        .bind(desired_path.as_str())
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
                Ok(Self::map_row_to_document(&row)?)
            }
            Err(err) => {
                if Self::is_unique_violation(&err) {
                    sqlx::query("ROLLBACK TO SAVEPOINT document_create")
                        .execute(tx.as_mut())
                        .await
                        .ok();
                    sqlx::query("RELEASE SAVEPOINT document_create")
                        .execute(tx.as_mut())
                        .await
                        .ok();
                    return Err(DocumentPathConflictError.into());
                }
                sqlx::query("ROLLBACK TO SAVEPOINT document_create")
                    .execute(tx.as_mut())
                    .await
                    .ok();
                sqlx::query("RELEASE SAVEPOINT document_create")
                    .execute(tx.as_mut())
                    .await
                    .ok();
                Err(err.into())
            }
        }
    }

    pub(crate) async fn update_title_and_parent_for_user_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
        workspace_id: Uuid,
        title: &Title,
        parent_id: Option<Option<Uuid>>,
        slug: &doc_path::Slug,
        desired_path: &doc_path::DesiredPath,
    ) -> anyhow::Result<Option<DomainDocument>> {
        sqlx::query("SAVEPOINT document_update")
            .execute(tx.as_mut())
            .await?;
        let path_digest = Self::hash_path(desired_path.as_str());
        let row = match parent_id {
            None => {
                sqlx::query(
                    r#"UPDATE documents SET
                            title = $1,
                            slug = $2,
                            desired_path = $3,
                            path_digest = $4,
                            updated_at = now()
                        WHERE id = $5 AND workspace_id = $6
                        RETURNING *"#,
                )
                .bind(title.as_str())
                .bind(slug.as_str())
                .bind(desired_path.as_str())
                .bind(&path_digest)
                .bind(id)
                .bind(workspace_id)
                .fetch_optional(tx.as_mut())
                .await
            }
            Some(new_parent) => {
                sqlx::query(
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
                .bind(title.as_str())
                .bind(new_parent)
                .bind(slug.as_str())
                .bind(desired_path.as_str())
                .bind(&path_digest)
                .bind(id)
                .bind(workspace_id)
                .fetch_optional(tx.as_mut())
                .await
            }
        };

        match row {
            Ok(Some(row)) => {
                let doc = Self::map_row_to_document(&row)?;
                if doc.doc_type == DocumentType::Folder {
                    sqlx::query("SAVEPOINT document_update_descendants")
                        .execute(tx.as_mut())
                        .await?;
                    let result = self
                        .update_descendant_paths_tx(tx, doc.id)
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
                            sqlx::query("RELEASE SAVEPOINT document_update")
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
                Ok(Some(doc))
            }
            Ok(None) => {
                sqlx::query("RELEASE SAVEPOINT document_update")
                    .execute(tx.as_mut())
                    .await
                    .ok();
                Ok(None)
            }
            Err(err) => {
                if Self::is_unique_violation(&err) {
                    sqlx::query("ROLLBACK TO SAVEPOINT document_update")
                        .execute(tx.as_mut())
                        .await
                        .ok();
                    sqlx::query("RELEASE SAVEPOINT document_update")
                        .execute(tx.as_mut())
                        .await
                        .ok();
                    return Err(DocumentPathConflictError.into());
                }
                sqlx::query("ROLLBACK TO SAVEPOINT document_update")
                    .execute(tx.as_mut())
                    .await
                    .ok();
                sqlx::query("RELEASE SAVEPOINT document_update")
                    .execute(tx.as_mut())
                    .await
                    .ok();
                Err(err.into())
            }
        }
    }

    pub(crate) async fn delete_owned_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
        workspace_id: Uuid,
    ) -> anyhow::Result<Option<DocumentType>> {
        let row = sqlx::query(r#"SELECT type FROM documents WHERE id = $1 AND workspace_id = $2"#)
            .bind(id)
            .bind(workspace_id)
            .fetch_optional(tx.as_mut())
            .await?;
        let dtype = match row {
            Some(r) => {
                let doc_type_str: String = r.get("type");
                DocumentType::try_from(doc_type_str.as_str()).context("invalid_document_type")?
            }
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

    pub(crate) async fn get_meta_for_owner_tx(
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
        row.as_ref()
            .map(SqlxDocumentRepository::map_row_to_meta)
            .transpose()
    }

    pub(crate) async fn archive_subtree_tx(
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
                .transpose()?
        } else {
            None
        };

        Ok(root)
    }

    pub(crate) async fn unarchive_subtree_tx(
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
                .transpose()?
        } else {
            None
        };

        Ok(root)
    }

    pub(crate) async fn list_owned_subtree_documents_tx(
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
        rows.into_iter()
            .map(|r| {
                let doc_type_str: String = r.get("type");
                let doc_type = DocumentType::try_from(doc_type_str.as_str())
                    .context("invalid_document_type")?;
                Ok(SubtreeDocument {
                    id: r.get("id"),
                    doc_type,
                })
            })
            .collect()
    }
}
