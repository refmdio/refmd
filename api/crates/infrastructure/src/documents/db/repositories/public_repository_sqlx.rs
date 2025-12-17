use anyhow::Context;
use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use application::documents::ports::publishing::public_repository::{
    PublicDocumentSummaryRow, PublicRepository, PublishStatusRow, WorkspaceTitleAndSlug,
};
use domain::documents::doc_type::DocumentType;
use domain::documents::document::Document;
use domain::documents::path as doc_path;
use domain::documents::title::Title;
use crate::core::db::PgPool;

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
    ) -> anyhow::Result<Option<WorkspaceTitleAndSlug>> {
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

    async fn upsert_public_document(&self, doc_id: Uuid, slug: &str) -> anyhow::Result<()> {
        let _ = sqlx::query("INSERT INTO public_documents (document_id, slug, published_at) VALUES ($1, $2, now()) ON CONFLICT (document_id) DO UPDATE SET slug = EXCLUDED.slug, published_at = now()")
            .bind(doc_id)
            .bind(slug)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn slug_exists(&self, slug: &str) -> anyhow::Result<bool> {
        let n =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(1) FROM public_documents WHERE slug = $1")
                .bind(slug)
                .fetch_one(&self.pool)
                .await?;
        Ok(n > 0)
    }

    async fn is_workspace_document(
        &self,
        doc_id: Uuid,
        workspace_id: Uuid,
    ) -> anyhow::Result<bool> {
        let n = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(1) FROM documents WHERE id = $1 AND workspace_id = $2",
        )
        .bind(doc_id)
        .bind(workspace_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(n > 0)
    }

    async fn delete_public_document(&self, doc_id: Uuid) -> anyhow::Result<bool> {
        let res = sqlx::query("DELETE FROM public_documents WHERE document_id = $1")
            .bind(doc_id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn get_publish_status(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
    ) -> anyhow::Result<Option<PublishStatusRow>> {
        let row = sqlx::query(
            r#"SELECT p.slug, w.slug as workspace_slug
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
        }))
    }

    async fn list_workspace_public_documents(
        &self,
        workspace_slug: &str,
    ) -> anyhow::Result<Vec<PublicDocumentSummaryRow>> {
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

    async fn get_public_meta_by_workspace_and_id(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
    ) -> anyhow::Result<Option<Document>> {
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
            let doc_type =
                DocumentType::try_from(doc_type_str.as_str()).context("invalid_document_type")?;
            let title: String = r.get("title");
            let slug_str: String = r.get("slug");
            let slug = doc_path::Slug::new(slug_str).context("invalid_slug")?;
            let desired_path_str: String = r.get("desired_path");
            let desired_path = doc_path::DesiredPath::new(desired_path_str);
            Ok(Document {
                id: r.get("id"),
                owner_id: r.get("owner_id"),
                owner_user_id: r.try_get("owner_user_id").ok(),
                workspace_id: r.get("workspace_id"),
                title: Title::new(title),
                parent_id: r.try_get("parent_id").ok(),
                doc_type,
                created_at: r.get("created_at"),
                updated_at: r.get("updated_at"),
                slug,
                desired_path,
                path: r.try_get("path").ok(),
                created_by: r.try_get("created_by").ok(),
                created_by_plugin: r.try_get("created_by_plugin").ok(),
                archived_at: r.try_get("archived_at").ok(),
                archived_by: r.try_get("archived_by").ok(),
                archived_parent_id: r.try_get("archived_parent_id").ok(),
            })
        })
        .transpose()
    }

    async fn public_exists_by_workspace_and_id(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
    ) -> anyhow::Result<bool> {
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
}
