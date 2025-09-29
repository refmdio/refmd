use sqlx::Row;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::infrastructure::db::PgPool;

pub fn sanitize_title(name: &str) -> String {
    let mut s = name.trim().to_string();
    let invalid = ['/', '\\', ':', '*', '?', '"', '<', '>', '|', '\0'];
    for ch in invalid {
        s = s.replace(ch, "-");
    }
    s = s.replace(' ', "_");
    if s.len() > 100 {
        s.truncate(100);
    }
    if s.is_empty() {
        s = "untitled".into();
    }
    s
}

pub async fn build_doc_dir(
    pool: &PgPool,
    uploads_root: &Path,
    doc_id: Uuid,
) -> anyhow::Result<PathBuf> {
    // Fetch document chain to root
    let mut dir = uploads_root.to_path_buf();
    // owner_id
    let row = sqlx::query("SELECT owner_id, parent_id FROM documents WHERE id = $1")
        .bind(doc_id)
        .fetch_optional(pool)
        .await?;
    let row = row.ok_or_else(|| anyhow::anyhow!("Document not found"))?;
    let owner_id: Uuid = row.get("owner_id");
    let mut parent_id: Option<Uuid> = row.try_get("parent_id").ok();
    dir.push(owner_id.to_string());

    let mut comps: Vec<String> = Vec::new();
    while let Some(pid) = parent_id {
        if let Some(r) = sqlx::query("SELECT title, parent_id, type FROM documents WHERE id = $1")
            .bind(pid)
            .fetch_optional(pool)
            .await?
        {
            let t: String = r.get("type");
            if t == "folder" {
                let title: String = r.get("title");
                comps.push(sanitize_title(&title));
            }
            parent_id = r.try_get("parent_id").ok();
        } else {
            break;
        }
    }
    comps.reverse();
    for c in comps {
        dir.push(c);
    }
    Ok(dir)
}

pub async fn build_doc_file_path(
    pool: &PgPool,
    uploads_root: &Path,
    doc_id: Uuid,
) -> anyhow::Result<PathBuf> {
    // fetch title, type first
    let row = sqlx::query("SELECT title, type FROM documents WHERE id = $1")
        .bind(doc_id)
        .fetch_one(pool)
        .await?;
    let title: String = row.get("title");
    let dtype: String = row.get("type");
    let mut dir = build_doc_dir(pool, uploads_root, doc_id).await?;
    if dtype != "folder" {
        let filename = format!("{}.md", sanitize_title(&title));
        dir.push(filename);
    }
    Ok(dir)
}

pub fn relative_from_uploads(uploads_root: &Path, full: &Path) -> String {
    let base = uploads_root;
    match full.strip_prefix(base) {
        Ok(rel) => rel.to_string_lossy().to_string(),
        Err(_) => full.to_string_lossy().to_string(),
    }
}

pub async fn move_doc_paths(
    pool: &PgPool,
    uploads_root: &Path,
    doc_id: Uuid,
) -> anyhow::Result<()> {
    let row = sqlx::query("SELECT type, path FROM documents WHERE id = $1")
        .bind(doc_id)
        .fetch_optional(pool)
        .await?;
    let row = match row {
        Some(r) => r,
        None => return Ok(()),
    };
    let dtype: String = row.get("type");
    if dtype == "folder" {
        return Ok(());
    }
    let old_rel: Option<String> = row.try_get("path").ok();

    let new_full = build_doc_file_path(pool, uploads_root, doc_id).await?;
    if let Some(parent) = new_full.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }

    // Move .md if exists
    if let Some(old_rel) = old_rel.clone() {
        let old_full = uploads_root.join(&old_rel);
        if tokio::fs::try_exists(&old_full).await.unwrap_or(false) {
            let _ = tokio::fs::rename(&old_full, &new_full).await;
        }
    }

    // Move only attachments belonging to this document
    if let Some(old_rel) = old_rel {
        let old_dir = uploads_root
            .join(&old_rel)
            .parent()
            .map(|p| p.to_path_buf());
        let new_dir = new_full.parent().map(|p| p.to_path_buf());
        if let (Some(_od), Some(nd)) = (old_dir, new_dir) {
            // Get list of files belonging to this document from DB
            let files =
                sqlx::query("SELECT filename, storage_path FROM files WHERE document_id = $1")
                    .bind(doc_id)
                    .fetch_all(pool)
                    .await?;

            if !files.is_empty() {
                let dst_attachments = nd.join("attachments");
                let _ = tokio::fs::create_dir_all(&dst_attachments).await;

                for row in files {
                    let filename: String = row.get("filename");
                    let old_path: String = row.get("storage_path");
                    let old_full = uploads_root.join(&old_path);

                    // Only move if file exists and is in the old attachments directory
                    if tokio::fs::try_exists(&old_full).await.unwrap_or(false) {
                        let new_path = dst_attachments.join(&filename);
                        let _ = tokio::fs::rename(&old_full, &new_path).await;

                        // Update DB with new path
                        let new_rel = relative_from_uploads(uploads_root, &new_path);
                        let _ = sqlx::query("UPDATE files SET storage_path = $2 WHERE document_id = $1 AND filename = $3")
                            .bind(doc_id)
                            .bind(new_rel)
                            .bind(&filename)
                            .execute(pool).await;
                    }
                }
            }
        }
    }

    // Update documents.path
    let new_rel = relative_from_uploads(uploads_root, &new_full);
    let _ = sqlx::query("UPDATE documents SET path = $2, updated_at = now() WHERE id = $1")
        .bind(doc_id)
        .bind(&new_rel)
        .execute(pool)
        .await;
    Ok(())
}

pub async fn list_descendant_docs(pool: &PgPool, folder_id: Uuid) -> anyhow::Result<Vec<Uuid>> {
    // recursive CTE to get non-folder descendants
    let rows = sqlx::query(
        r#"
        WITH RECURSIVE dt(id) AS (
            SELECT id FROM documents WHERE parent_id = $1
            UNION ALL
            SELECT d.id FROM documents d JOIN dt ON d.parent_id = dt.id
        )
        SELECT id FROM documents WHERE id IN (SELECT id FROM dt) AND type <> 'folder'
        "#,
    )
    .bind(folder_id)
    .fetch_all(pool)
    .await?;
    let ids = rows
        .into_iter()
        .filter_map(|r| r.try_get::<Uuid, _>("id").ok())
        .collect();
    Ok(ids)
}

pub async fn move_folder_subtree(
    pool: &PgPool,
    uploads_root: &Path,
    folder_id: Uuid,
) -> anyhow::Result<usize> {
    let ids = list_descendant_docs(pool, folder_id).await?;
    for id in &ids {
        let _ = move_doc_paths(pool, uploads_root, *id).await;
    }
    Ok(ids.len())
}

pub async fn delete_doc_physical(
    pool: &PgPool,
    uploads_root: &Path,
    doc_id: Uuid,
) -> anyhow::Result<()> {
    let row = sqlx::query("SELECT type, path FROM documents WHERE id = $1")
        .bind(doc_id)
        .fetch_optional(pool)
        .await?;
    let row = match row {
        Some(r) => r,
        None => return Ok(()),
    };
    let dtype: String = row.get("type");
    if dtype == "folder" {
        return Ok(());
    }

    // Delete the document file itself
    if let Some(rel) = row.try_get::<String, _>("path").ok() {
        let full = uploads_root.join(&rel);
        let _ = tokio::fs::remove_file(&full).await;
    }

    // Delete only attachments belonging to this document
    let files = sqlx::query("SELECT storage_path FROM files WHERE document_id = $1")
        .bind(doc_id)
        .fetch_all(pool)
        .await?;

    for file_row in files {
        if let Ok(storage_path) = file_row.try_get::<String, _>("storage_path") {
            let file_path = uploads_root.join(&storage_path);
            if tokio::fs::try_exists(&file_path).await.unwrap_or(false) {
                let _ = tokio::fs::remove_file(&file_path).await;
            }
        }
    }

    Ok(())
}

pub async fn delete_folder_physical(
    pool: &PgPool,
    uploads_root: &Path,
    folder_id: Uuid,
) -> anyhow::Result<usize> {
    let ids = list_descendant_docs(pool, folder_id).await?;
    for id in &ids {
        let _ = delete_doc_physical(pool, uploads_root, *id).await;
    }
    Ok(ids.len())
}
