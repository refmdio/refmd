use anyhow::Context;
use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::core::db::PgPool;
use application::core::ports::errors::PortResult;
use application::documents::ports::publishing::public_repository::{
    PublicContentRow, PublicDocumentSummaryRow, PublicFileRow, PublicRepository, PublishStatusRow,
    StorePublicFileInput, WorkspaceTitleAndSlug,
};
use domain::documents::doc_type::DocumentType;
use domain::documents::document::Document;
use domain::documents::path as doc_path;
use domain::documents::title::Title;

pub struct SqlxPublicRepository {
    pub pool: PgPool,
}

impl SqlxPublicRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PublicRepository for SqlxPublicRepository {
    async fn ensure_workspace_title_and_slug(
        &self,
        doc_id: Uuid,
        workspace_id: Uuid,
    ) -> PortResult<Option<WorkspaceTitleAndSlug>> {
        let out: anyhow::Result<Option<WorkspaceTitleAndSlug>> = async {
            let row = sqlx::query(
                "SELECT d.title, w.slug as workspace_slug FROM documents d JOIN workspaces w ON d.workspace_id = w.id WHERE d.id = $1 AND d.workspace_id = $2",
            )
                .bind(doc_id)
                .bind(workspace_id)
                .fetch_optional(&self.pool)
                .await?;
            Ok(row.map(|r| WorkspaceTitleAndSlug {
                title: r.get("title"),
                workspace_slug: r.get("workspace_slug"),
            }))
        }
        .await;
        out.map_err(Into::into)
    }

    async fn upsert_public_document(&self, doc_id: Uuid, slug: &str, noindex: bool) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            let _ = sqlx::query("INSERT INTO public_documents (document_id, slug, noindex, published_at) VALUES ($1, $2, $3, now()) ON CONFLICT (document_id) DO UPDATE SET slug = EXCLUDED.slug, noindex = EXCLUDED.noindex, published_at = now()")
                .bind(doc_id)
                .bind(slug)
                .bind(noindex)
                .execute(&self.pool)
                .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn update_noindex(&self, doc_id: Uuid, noindex: bool) -> PortResult<bool> {
        let out: anyhow::Result<bool> = async {
            let res = sqlx::query("UPDATE public_documents SET noindex = $1 WHERE document_id = $2")
                .bind(noindex)
                .bind(doc_id)
                .execute(&self.pool)
                .await?;
            Ok(res.rows_affected() > 0)
        }
        .await;
        out.map_err(Into::into)
    }

    async fn slug_exists(&self, slug: &str) -> PortResult<bool> {
        let out: anyhow::Result<bool> = async {
            let n = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(1) FROM public_documents WHERE slug = $1",
            )
            .bind(slug)
            .fetch_one(&self.pool)
            .await?;
            Ok(n > 0)
        }
        .await;
        out.map_err(Into::into)
    }

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

    async fn delete_public_document(&self, doc_id: Uuid) -> PortResult<bool> {
        let out: anyhow::Result<bool> = async {
            let res = sqlx::query("DELETE FROM public_documents WHERE document_id = $1")
                .bind(doc_id)
                .execute(&self.pool)
                .await?;
            Ok(res.rows_affected() > 0)
        }
        .await;
        out.map_err(Into::into)
    }

    async fn get_publish_status(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
    ) -> PortResult<Option<PublishStatusRow>> {
        let out: anyhow::Result<Option<PublishStatusRow>> = async {
            let row = sqlx::query(
                r#"SELECT p.slug, p.noindex, w.slug as workspace_slug
               FROM public_documents p
               JOIN documents d ON p.document_id = d.id
               JOIN workspaces w ON d.workspace_id = w.id
               WHERE p.document_id = $1 AND d.workspace_id = $2"#,
            )
            .bind(doc_id)
            .bind(workspace_id)
            .fetch_optional(&self.pool)
            .await?;
            Ok(row.map(|r| PublishStatusRow {
                slug: r.get("slug"),
                workspace_slug: r.get("workspace_slug"),
                noindex: r.get("noindex"),
            }))
        }
        .await;
        out.map_err(Into::into)
    }

    async fn list_workspace_public_documents(
        &self,
        workspace_slug: &str,
    ) -> PortResult<Vec<PublicDocumentSummaryRow>> {
        let out: anyhow::Result<Vec<PublicDocumentSummaryRow>> = async {
            let rows = sqlx::query(
                r#"SELECT d.id, d.title, d.updated_at, p.published_at
               FROM public_documents p
               JOIN documents d ON p.document_id = d.id
               JOIN workspaces w ON d.workspace_id = w.id
               WHERE w.slug = $1
                  OR (w.is_personal AND EXISTS (
                        SELECT 1
                        FROM users u
                        WHERE u.id = w.id AND lower(u.name) = lower($1)
                  ))
               ORDER BY d.updated_at DESC LIMIT 200"#,
            )
            .bind(workspace_slug)
            .fetch_all(&self.pool)
            .await?;
            Ok(rows
                .into_iter()
                .map(|r| PublicDocumentSummaryRow {
                    id: r.get("id"),
                    title: r.get("title"),
                    updated_at: r.get("updated_at"),
                    published_at: r.get("published_at"),
                })
                .collect())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn get_public_meta_by_workspace_and_id(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
    ) -> PortResult<Option<Document>> {
        let out: anyhow::Result<Option<Document>> = async {
            let row = sqlx::query(
                r#"SELECT d.id, d.owner_id, d.owner_user_id, d.workspace_id, d.title, d.parent_id, d.type, d.created_at, d.updated_at,
                      d.slug, d.desired_path, d.path, d.created_by, d.created_by_plugin,
                      d.archived_at, d.archived_by, d.archived_parent_id
               FROM public_documents p
               JOIN documents d ON p.document_id = d.id
               JOIN workspaces w ON d.workspace_id = w.id
               WHERE (w.slug = $1
                      OR (w.is_personal AND EXISTS (
                            SELECT 1
                            FROM users u
                            WHERE u.id = w.id AND lower(u.name) = lower($1)
                      )))
                 AND d.id = $2"#,
            )
            .bind(workspace_slug)
            .bind(doc_id)
            .fetch_optional(&self.pool)
            .await?;
            row.map(|r| {
                let doc_type_str: String = r.get("type");
                let doc_type = DocumentType::try_from(doc_type_str.as_str())
                    .context("invalid_document_type")?;
                let title: String = r.get("title");
                let slug_str: String = r.get("slug");
                let slug = doc_path::Slug::new(slug_str).context("invalid_slug")?;
                let desired_path_str: String = r.get("desired_path");
                let desired_path = doc_path::DesiredPath::new(desired_path_str)
                    .context("invalid_desired_path")?;
                Ok(Document::rehydrate(
                    r.get("id"),
                    r.try_get("owner_user_id").ok(),
                    r.get("workspace_id"),
                    Title::new(title),
                    r.try_get("parent_id").ok(),
                    doc_type,
                    r.get("created_at"),
                    r.get("updated_at"),
                    r.try_get("created_by_plugin").ok(),
                    slug,
                    desired_path,
                    r.try_get("path").ok(),
                    r.try_get("created_by").ok(),
                    r.try_get("archived_at").ok(),
                    r.try_get("archived_by").ok(),
                    r.try_get("archived_parent_id").ok(),
                    r.try_get("encrypted_title").ok(),
                    r.try_get("encrypted_title_nonce").ok(),
                ))
            })
            .transpose()
        }
        .await;
        out.map_err(Into::into)
    }

    async fn public_exists_by_workspace_and_id(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
    ) -> PortResult<bool> {
        let out: anyhow::Result<bool> = async {
            let n = sqlx::query_scalar::<_, i64>(
                r#"SELECT COUNT(1)
               FROM public_documents p
               JOIN documents d ON p.document_id = d.id
               JOIN workspaces w ON d.workspace_id = w.id
               WHERE (w.slug = $1
                      OR (w.is_personal AND EXISTS (
                            SELECT 1
                            FROM users u
                            WHERE u.id = w.id AND lower(u.name) = lower($1)
                      )))
                 AND d.id = $2"#,
            )
            .bind(workspace_slug)
            .bind(doc_id)
            .fetch_one(&self.pool)
            .await?;
            Ok(n > 0)
        }
        .await;
        out.map_err(Into::into)
    }

    async fn get_noindex_by_workspace_and_id(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
    ) -> PortResult<Option<bool>> {
        let out: anyhow::Result<Option<bool>> = async {
            let row = sqlx::query_scalar::<_, bool>(
                r#"SELECT p.noindex
               FROM public_documents p
               JOIN documents d ON p.document_id = d.id
               JOIN workspaces w ON d.workspace_id = w.id
               WHERE (w.slug = $1
                      OR (w.is_personal AND EXISTS (
                            SELECT 1
                            FROM users u
                            WHERE u.id = w.id AND lower(u.name) = lower($1)
                      )))
                 AND d.id = $2"#,
            )
            .bind(workspace_slug)
            .bind(doc_id)
            .fetch_optional(&self.pool)
            .await?;
            Ok(row)
        }
        .await;
        out.map_err(Into::into)
    }

    async fn store_public_content(
        &self,
        doc_id: Uuid,
        title: &str,
        content: &str,
        content_hash: &str,
    ) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            sqlx::query(
                r#"INSERT INTO public_document_contents (document_id, title, content, content_hash, updated_at)
                   VALUES ($1, $2, $3, $4, now())
                   ON CONFLICT (document_id) DO UPDATE SET
                       title = EXCLUDED.title,
                       content = EXCLUDED.content,
                       content_hash = EXCLUDED.content_hash,
                       updated_at = now()"#,
            )
            .bind(doc_id)
            .bind(title)
            .bind(content)
            .bind(content_hash)
            .execute(&self.pool)
            .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn get_public_content(&self, doc_id: Uuid) -> PortResult<Option<PublicContentRow>> {
        let out: anyhow::Result<Option<PublicContentRow>> = async {
            let row = sqlx::query(
                r#"SELECT document_id, title, content, content_hash, updated_at
                   FROM public_document_contents
                   WHERE document_id = $1"#,
            )
            .bind(doc_id)
            .fetch_optional(&self.pool)
            .await?;
            Ok(row.map(|r| PublicContentRow {
                document_id: r.get("document_id"),
                title: r.get("title"),
                content: r.get("content"),
                content_hash: r.get("content_hash"),
                updated_at: r.get("updated_at"),
            }))
        }
        .await;
        out.map_err(Into::into)
    }

    async fn delete_public_content(&self, doc_id: Uuid) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            sqlx::query(r#"DELETE FROM public_document_contents WHERE document_id = $1"#)
                .bind(doc_id)
                .execute(&self.pool)
                .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }

    // --- Public file methods ---

    async fn store_public_file(&self, input: StorePublicFileInput) -> PortResult<Uuid> {
        let out: anyhow::Result<Uuid> = async {
            let id: Uuid = sqlx::query_scalar(
                r#"INSERT INTO public_document_files
                   (document_id, workspace_id, file_id, original_filename, logical_filename, mime_type, size, storage_path, content_hash)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                   ON CONFLICT (document_id, file_id) DO UPDATE SET
                       original_filename = EXCLUDED.original_filename,
                       logical_filename = EXCLUDED.logical_filename,
                       mime_type = EXCLUDED.mime_type,
                       size = EXCLUDED.size,
                       storage_path = EXCLUDED.storage_path,
                       content_hash = EXCLUDED.content_hash,
                       updated_at = now()
                   RETURNING id"#,
            )
            .bind(input.document_id)
            .bind(input.workspace_id)
            .bind(input.file_id)
            .bind(&input.original_filename)
            .bind(&input.logical_filename)
            .bind(&input.mime_type)
            .bind(input.size)
            .bind(&input.storage_path)
            .bind(&input.content_hash)
            .fetch_one(&self.pool)
            .await?;
            Ok(id)
        }
        .await;
        out.map_err(Into::into)
    }

    async fn get_public_files(&self, doc_id: Uuid) -> PortResult<Vec<PublicFileRow>> {
        let out: anyhow::Result<Vec<PublicFileRow>> = async {
            let rows = sqlx::query(
                r#"SELECT id, document_id, workspace_id, file_id, original_filename, logical_filename,
                          mime_type, size, storage_path, content_hash, created_at
                   FROM public_document_files
                   WHERE document_id = $1
                   ORDER BY created_at"#,
            )
            .bind(doc_id)
            .fetch_all(&self.pool)
            .await?;
            Ok(rows
                .into_iter()
                .map(|r| PublicFileRow {
                    id: r.get("id"),
                    document_id: r.get("document_id"),
                    workspace_id: r.get("workspace_id"),
                    file_id: r.get("file_id"),
                    original_filename: r.get("original_filename"),
                    logical_filename: r.get("logical_filename"),
                    mime_type: r.get("mime_type"),
                    size: r.get("size"),
                    storage_path: r.get("storage_path"),
                    content_hash: r.get("content_hash"),
                    created_at: r.get("created_at"),
                })
                .collect())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn get_public_file(
        &self,
        doc_id: Uuid,
        file_id: Uuid,
    ) -> PortResult<Option<PublicFileRow>> {
        let out: anyhow::Result<Option<PublicFileRow>> = async {
            let row = sqlx::query(
                r#"SELECT id, document_id, workspace_id, file_id, original_filename, logical_filename,
                          mime_type, size, storage_path, content_hash, created_at
                   FROM public_document_files
                   WHERE document_id = $1 AND file_id = $2"#,
            )
            .bind(doc_id)
            .bind(file_id)
            .fetch_optional(&self.pool)
            .await?;
            Ok(row.map(|r| PublicFileRow {
                id: r.get("id"),
                document_id: r.get("document_id"),
                workspace_id: r.get("workspace_id"),
                file_id: r.get("file_id"),
                original_filename: r.get("original_filename"),
                logical_filename: r.get("logical_filename"),
                mime_type: r.get("mime_type"),
                size: r.get("size"),
                storage_path: r.get("storage_path"),
                content_hash: r.get("content_hash"),
                created_at: r.get("created_at"),
            }))
        }
        .await;
        out.map_err(Into::into)
    }

    async fn get_public_file_by_logical_filename(
        &self,
        doc_id: Uuid,
        logical_filename: &str,
    ) -> PortResult<Option<PublicFileRow>> {
        let out: anyhow::Result<Option<PublicFileRow>> = async {
            let row = sqlx::query(
                r#"SELECT id, document_id, workspace_id, file_id, original_filename, logical_filename,
                          mime_type, size, storage_path, content_hash, created_at
                   FROM public_document_files
                   WHERE document_id = $1 AND logical_filename = $2"#,
            )
            .bind(doc_id)
            .bind(logical_filename)
            .fetch_optional(&self.pool)
            .await?;
            Ok(row.map(|r| PublicFileRow {
                id: r.get("id"),
                document_id: r.get("document_id"),
                workspace_id: r.get("workspace_id"),
                file_id: r.get("file_id"),
                original_filename: r.get("original_filename"),
                logical_filename: r.get("logical_filename"),
                mime_type: r.get("mime_type"),
                size: r.get("size"),
                storage_path: r.get("storage_path"),
                content_hash: r.get("content_hash"),
                created_at: r.get("created_at"),
            }))
        }
        .await;
        out.map_err(Into::into)
    }

    async fn delete_public_files(&self, doc_id: Uuid) -> PortResult<usize> {
        let out: anyhow::Result<usize> = async {
            let res = sqlx::query(r#"DELETE FROM public_document_files WHERE document_id = $1"#)
                .bind(doc_id)
                .execute(&self.pool)
                .await?;
            Ok(res.rows_affected() as usize)
        }
        .await;
        out.map_err(Into::into)
    }
}
