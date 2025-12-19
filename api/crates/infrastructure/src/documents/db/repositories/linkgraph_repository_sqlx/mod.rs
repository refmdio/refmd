use anyhow::Context;
use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::core::db::PgPool;
use application::core::ports::errors::PortResult;
use application::documents::ports::linkgraph_repository::LinkGraphRepository;
use domain::documents::doc_type::DocumentType;
use domain::documents::document::{BacklinkInfo, OutgoingLink};
use domain::documents::title::Title;

pub struct SqlxLinkGraphRepository {
    pub pool: PgPool,
}

impl SqlxLinkGraphRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl LinkGraphRepository for SqlxLinkGraphRepository {
    async fn clear_links_for_source(&self, source_id: Uuid) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            sqlx::query("DELETE FROM document_links WHERE source_document_id = $1")
                .bind(source_id)
                .execute(&self.pool)
                .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn exists_doc_for_owner(&self, doc_id: Uuid, owner_id: Uuid) -> PortResult<bool> {
        let out: anyhow::Result<bool> = async {
            let n = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(1) FROM documents WHERE id = $1 AND owner_id = $2",
            )
            .bind(doc_id)
            .bind(owner_id)
            .fetch_one(&self.pool)
            .await?;
            Ok(n > 0)
        }
        .await;
        out.map_err(Into::into)
    }

    async fn find_doc_id_by_owner_and_title(
        &self,
        owner_id: Uuid,
        title: &str,
    ) -> PortResult<Option<Uuid>> {
        let out: anyhow::Result<Option<Uuid>> = async {
            let row = sqlx::query(
                r#"SELECT id FROM documents 
               WHERE owner_id = $1 AND LOWER(title) = LOWER($2)
               ORDER BY updated_at DESC LIMIT 1"#,
            )
            .bind(owner_id)
            .bind(title)
            .fetch_optional(&self.pool)
            .await?;
            Ok(row.map(|r| r.get::<Uuid, _>("id")))
        }
        .await;
        out.map_err(Into::into)
    }

    async fn upsert_link(
        &self,
        source_id: Uuid,
        target_id: Uuid,
        link_type: &str,
        link_text: Option<String>,
        position_start: i32,
        position_end: i32,
    ) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            sqlx::query(
                r#"INSERT INTO document_links (
                    source_document_id, target_document_id, link_type,
                    link_text, position_start, position_end, created_at, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, now(), now())
                ON CONFLICT (source_document_id, target_document_id, position_start)
                DO UPDATE SET link_type = EXCLUDED.link_type,
                              link_text = EXCLUDED.link_text,
                              position_end = EXCLUDED.position_end,
                              updated_at = now()
            "#,
            )
            .bind(source_id)
            .bind(target_id)
            .bind(link_type)
            .bind(link_text)
            .bind(position_start)
            .bind(position_end)
            .execute(&self.pool)
            .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn backlinks_for(
        &self,
        workspace_id: Uuid,
        target_id: Uuid,
    ) -> PortResult<Vec<BacklinkInfo>> {
        let out: anyhow::Result<Vec<BacklinkInfo>> = async {
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
                    Ok(BacklinkInfo {
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
        .await;
        out.map_err(Into::into)
    }

    async fn outgoing_links_for(
        &self,
        workspace_id: Uuid,
        source_id: Uuid,
    ) -> PortResult<Vec<OutgoingLink>> {
        let out: anyhow::Result<Vec<OutgoingLink>> = async {
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
                    Ok(OutgoingLink {
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
        .await;
        out.map_err(Into::into)
    }
}
