use anyhow::{Context, anyhow};
use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use application::documents::ports::document_repository::{
    DocMeta, DocumentListState, DocumentRepository, SubtreeDocument,
};
use domain::documents::doc_type::DocumentType;
use domain::documents::document::{
    BacklinkInfo as DomBacklinkInfo, Document as DomainDocument, OutgoingLink as DomOutgoingLink,
    SearchHit,
};
use domain::documents::path as doc_path;
use domain::documents::title::Title;

use super::SqlxDocumentRepository;

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
            );
            sqlx::query(&sql)
                .bind(workspace_id)
                .fetch_all(&self.pool)
                .await?
        };

        rows.into_iter()
            .map(|r| Self::map_row_to_document(&r))
            .collect()
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
        rows.into_iter()
            .map(|r| Self::map_row_to_document(&r))
            .collect()
    }

    async fn get_by_id(&self, id: Uuid) -> anyhow::Result<Option<DomainDocument>> {
        let row = sqlx::query(r#"SELECT * FROM documents WHERE id = $1"#)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|r| Self::map_row_to_document(&r)).transpose()
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
                   LIMIT $4"#,
            )
            .bind(workspace_id)
            .bind(like)
            .bind(&q)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        };
        rows.into_iter()
            .map(|r| {
                let doc_type_str: String = r.get("type");
                let doc_type = DocumentType::try_from(doc_type_str.as_str())
                    .context("invalid_document_type")?;
                let title: String = r.get("title");
                Ok(SearchHit {
                    id: r.get("id"),
                    title: Title::new(title),
                    doc_type,
                    path: r.try_get("path").ok(),
                    updated_at: r.get("updated_at"),
                })
            })
            .collect()
    }

    async fn create_for_user(
        &self,
        workspace_id: Uuid,
        created_by: Uuid,
        title: &Title,
        parent_id: Option<Uuid>,
        doc_type: DocumentType,
        created_by_plugin: Option<&str>,
        slug: &doc_path::Slug,
        desired_path: &doc_path::DesiredPath,
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
                slug,
                desired_path,
            )
            .await?;
        tx.commit().await?;
        Ok(doc)
    }

    async fn update_title_and_parent_for_user(
        &self,
        id: Uuid,
        workspace_id: Uuid,
        title: &Title,
        parent_id: Option<Option<Uuid>>,
        slug: &doc_path::Slug,
        desired_path: &doc_path::DesiredPath,
    ) -> anyhow::Result<Option<DomainDocument>> {
        let mut tx = self.pool.begin().await?;
        let doc = self
            .update_title_and_parent_for_user_tx(
                &mut tx,
                id,
                workspace_id,
                title,
                parent_id,
                slug,
                desired_path,
            )
            .await?;
        tx.commit().await?;
        Ok(doc)
    }

    async fn delete_owned(
        &self,
        id: Uuid,
        workspace_id: Uuid,
    ) -> anyhow::Result<Option<DocumentType>> {
        let mut tx = self.pool.begin().await?;
        let res = self.delete_owned_tx(&mut tx, id, workspace_id).await?;
        tx.commit().await?;
        Ok(res)
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
        rows.into_iter()
            .map(|r| {
                let doc_type_str: String = r.get("document_type");
                let document_type = DocumentType::try_from(doc_type_str.as_str())
                    .context("invalid_document_type")?;
                let title: String = r.get("title");
                Ok(DomBacklinkInfo {
                    document_id: r.get("document_id"),
                    title: Title::new(title),
                    document_type,
                    file_path: r.try_get("file_path").ok(),
                    link_type: r.get("link_type"),
                    link_text: r.try_get("link_text").ok(),
                    link_count: r.try_get("link_count").unwrap_or(1_i64),
                })
            })
            .collect()
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
        rows.into_iter()
            .map(|r| {
                let doc_type_str: String = r.get("document_type");
                let document_type = DocumentType::try_from(doc_type_str.as_str())
                    .context("invalid_document_type")?;
                let title: String = r.get("title");
                Ok(DomOutgoingLink {
                    document_id: r.get("document_id"),
                    title: Title::new(title),
                    document_type,
                    file_path: r.try_get("file_path").ok(),
                    link_type: r.get("link_type"),
                    link_text: r.try_get("link_text").ok(),
                    position_start: r.try_get("position_start").ok(),
                    position_end: r.try_get("position_end").ok(),
                })
            })
            .collect()
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
        row.as_ref()
            .map(SqlxDocumentRepository::map_row_to_meta)
            .transpose()
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
        row.map(|r| Self::map_row_to_document(&r)).transpose()
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
        let desired_path = doc_path::DesiredPath::new(desired_path);
        let slug = doc_path::slug_from_desired_path(&desired_path)?;
        let parent_path = doc_path::parent_desired_path(&desired_path);
        let parent_id = self
            .resolve_parent_folder_id(workspace_id, parent_path.as_ref())
            .await?;
        let normalized_path = Self::owner_relative_path(workspace_id, desired_path.as_str());
        let path_digest = Self::hash_path(desired_path.as_str());
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
        .bind(desired_path.as_str())
        .bind(&path_digest)
        .bind(slug.as_str())
        .bind(parent_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
