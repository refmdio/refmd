use sqlx::Row;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::db::PgPool;

fn pathbuf_to_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn owner_relative_buf(owner_id: Uuid, desired_path: &str, archived: bool) -> PathBuf {
    let mut rel = PathBuf::from(owner_id.to_string());
    if archived {
        rel.push("Archives");
    }
    let trimmed = desired_path.trim_start_matches('/');
    if !trimmed.is_empty() {
        rel.push(trimmed);
    }
    rel
}

fn owner_relative_parent_buf(owner_id: Uuid, desired_path: &str, archived: bool) -> PathBuf {
    let mut rel = PathBuf::from(owner_id.to_string());
    if archived {
        rel.push("Archives");
    }
    let trimmed = desired_path.trim_start_matches('/');
    if trimmed.is_empty() {
        return rel;
    }
    let mut desired = PathBuf::from(trimmed);
    if desired.file_name().is_some() {
        desired.pop();
    }
    if !desired.as_os_str().is_empty() {
        rel.push(desired);
    }
    rel
}

pub fn owner_relative_from_desired(owner_id: Uuid, desired_path: &str, archived: bool) -> String {
    pathbuf_to_string(&owner_relative_buf(owner_id, desired_path, archived))
}

pub fn owner_relative_parent_from_desired(
    owner_id: Uuid,
    desired_path: &str,
    archived: bool,
) -> String {
    pathbuf_to_string(&owner_relative_parent_buf(owner_id, desired_path, archived))
}

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
    let row = sqlx::query(
        "SELECT owner_id, desired_path, type, archived_at FROM documents WHERE id = $1",
    )
    .bind(doc_id)
    .fetch_optional(pool)
    .await?;
    let row = row.ok_or_else(|| anyhow::anyhow!("Document not found"))?;
    let owner_id: Uuid = row.get("owner_id");
    let desired_path: String = row.get("desired_path");
    let dtype: String = row.get("type");
    let archived = row
        .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("archived_at")
        .ok()
        .flatten()
        .is_some();

    let rel = if dtype == "folder" {
        owner_relative_buf(owner_id, &desired_path, archived)
    } else {
        owner_relative_parent_buf(owner_id, &desired_path, archived)
    };

    Ok(uploads_root.join(rel))
}

pub async fn build_doc_file_path(
    pool: &PgPool,
    uploads_root: &Path,
    doc_id: Uuid,
) -> anyhow::Result<PathBuf> {
    let row = sqlx::query(
        "SELECT owner_id, desired_path, type, archived_at FROM documents WHERE id = $1",
    )
    .bind(doc_id)
    .fetch_one(pool)
    .await?;
    let dtype: String = row.get("type");
    if dtype == "folder" {
        anyhow::bail!("folder_has_no_markdown_path");
    }
    let owner_id: Uuid = row.get("owner_id");
    let desired_path: String = row.get("desired_path");
    let archived = row
        .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("archived_at")
        .ok()
        .flatten()
        .is_some();
    let rel = owner_relative_buf(owner_id, &desired_path, archived);
    Ok(uploads_root.join(rel))
}

pub fn relative_from_uploads(uploads_root: &Path, full: &Path) -> String {
    let base = uploads_root;
    match full.strip_prefix(base) {
        Ok(rel) => rel.to_string_lossy().to_string(),
        Err(_) => full.to_string_lossy().to_string(),
    }
}

// Convert uploads-relative path to repo-relative path and extract workspace_id.
// Example: "{user_uuid}/docs/foo.md" -> (user_uuid, "docs/foo.md")
fn split_owner_and_repo_path(rel: &str) -> Option<(Uuid, String)> {
    let trimmed = rel.trim_start_matches('/');
    let mut it = trimmed.splitn(2, '/');
    let owner = it.next()?;
    let rest = it.next().unwrap_or("").to_string();
    let owner_id = Uuid::parse_str(owner).ok()?;
    Some((owner_id, rest))
}

async fn mark_dirty_upsert_internal(
    pool: &PgPool,
    workspace_id: Uuid,
    repo_path: &str,
    is_text: bool,
    content_hash: Option<&str>,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"INSERT INTO git_dirty_files (workspace_id, path, is_text, op, content_hash)
            VALUES ($1, $2, $3, 'upsert', $4)
            ON CONFLICT (workspace_id, path)
            DO UPDATE SET op = EXCLUDED.op,
                          is_text = EXCLUDED.is_text,
                          content_hash = EXCLUDED.content_hash,
                          created_at = now()"#,
    )
    .bind(workspace_id)
    .bind(repo_path)
    .bind(is_text)
    .bind(content_hash)
    .execute(pool)
    .await?;
    Ok(())
}

async fn mark_dirty_delete_internal(
    pool: &PgPool,
    workspace_id: Uuid,
    repo_path: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"INSERT INTO git_dirty_files (workspace_id, path, is_text, op, content_hash)
            VALUES ($1, $2, false, 'delete', NULL)
            ON CONFLICT (workspace_id, path)
            DO UPDATE SET op = EXCLUDED.op,
                          created_at = now()"#,
    )
    .bind(workspace_id)
    .bind(repo_path)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn mark_dirty_upsert_abs_path(
    pool: &PgPool,
    uploads_root: &Path,
    abs_path: &Path,
    is_text: bool,
    content_hash: Option<&str>,
) -> anyhow::Result<()> {
    if crate::storage::dirty_tracking_suppressed() {
        return Ok(());
    }
    let rel = relative_from_uploads(uploads_root, abs_path).replace('\\', "/");
    if let Some((workspace_id, repo_path)) = split_owner_and_repo_path(&rel) {
        if !repo_path.is_empty() {
            let _ =
                mark_dirty_upsert_internal(pool, workspace_id, &repo_path, is_text, content_hash)
                    .await;
        }
    }
    Ok(())
}

pub async fn mark_dirty_upsert_relative(
    pool: &PgPool,
    relative: &str,
    is_text: bool,
    content_hash: Option<&str>,
) -> anyhow::Result<()> {
    if crate::storage::dirty_tracking_suppressed() {
        return Ok(());
    }
    let rel = relative.trim_start_matches('/');
    if let Some((workspace_id, repo_path)) = split_owner_and_repo_path(rel) {
        if !repo_path.is_empty() {
            let _ =
                mark_dirty_upsert_internal(pool, workspace_id, &repo_path, is_text, content_hash)
                    .await;
        }
    }
    Ok(())
}

pub async fn mark_dirty_delete_relative(pool: &PgPool, relative: &str) -> anyhow::Result<()> {
    if crate::storage::dirty_tracking_suppressed() {
        return Ok(());
    }
    let rel = relative.trim_start_matches('/');
    if let Some((workspace_id, repo_path)) = split_owner_and_repo_path(rel) {
        if !repo_path.is_empty() {
            let _ = mark_dirty_delete_internal(pool, workspace_id, &repo_path).await;
        }
    }
    Ok(())
}

pub async fn move_doc_paths(
    pool: &PgPool,
    uploads_root: &Path,
    doc_id: Uuid,
) -> anyhow::Result<()> {
    let row = sqlx::query(
        "SELECT owner_id, type, path, desired_path, archived_at FROM documents WHERE id = $1",
    )
    .bind(doc_id)
    .fetch_optional(pool)
    .await?;
    let row = match row {
        Some(r) => r,
        None => return Ok(()),
    };
    let owner_id: Uuid = row.get("owner_id");
    let dtype: String = row.get("type");
    if dtype == "folder" {
        return Ok(());
    }
    let old_rel: Option<String> = row.try_get("path").ok();
    let desired_path: String = row.get("desired_path");
    let archived = row
        .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("archived_at")
        .ok()
        .flatten()
        .is_some();
    let target_rel = owner_relative_from_desired(owner_id, &desired_path, archived);
    let target_abs = uploads_root.join(&target_rel);

    if let Some(parent) = target_abs.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }

    // Move .md if exists
    if let Some(old_rel) = old_rel.clone() {
        if old_rel != target_rel {
            let old_full = uploads_root.join(&old_rel);
            if tokio::fs::try_exists(&old_full).await.unwrap_or(false) {
                let _ = tokio::fs::rename(&old_full, &target_abs).await;
            }
            // Mark old path as deleted (repo-relative)
            let _ = mark_dirty_delete_relative(pool, &old_rel).await;
        }
    }

    // Move only attachments belonging to this document
    let new_dir = target_abs.parent().map(|p| p.to_path_buf());
    if let Some(nd) = new_dir {
        // Get list of files belonging to this document from DB
        let files = sqlx::query("SELECT filename, storage_path FROM files WHERE document_id = $1")
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

                // Only move if file exists
                if tokio::fs::try_exists(&old_full).await.unwrap_or(false) {
                    let new_path = dst_attachments.join(&filename);
                    if let Some(parent) = new_path.parent() {
                        let _ = tokio::fs::create_dir_all(parent).await;
                    }
                    let _ = tokio::fs::rename(&old_full, &new_path).await;

                    // Update DB with new path
                    let new_rel = relative_from_uploads(uploads_root, &new_path);
                    let _ = sqlx::query("UPDATE files SET storage_path = $2 WHERE document_id = $1 AND filename = $3")
                        .bind(doc_id)
                        .bind(&new_rel)
                        .bind(&filename)
                        .execute(pool).await;

                    // Mark move: old delete, new upsert (binary)
                    let _ = mark_dirty_delete_relative(pool, &old_path).await;
                    let _ = mark_dirty_upsert_relative(pool, &new_rel, false, None).await;
                }
            }
        }
    }

    // Update documents.path
    // Path reconciliation shouldn't rewrite updated_at; user-visible edits already touch it
    // when the path/metadata actually changes. This keeps background projection jobs from
    // bumping the doc's last-updated timestamp.
    let _ = sqlx::query("UPDATE documents SET path = $2 WHERE id = $1")
        .bind(doc_id)
        .bind(&target_rel)
        .execute(pool)
        .await;

    // Mark new path as upsert (text)
    let _ = mark_dirty_upsert_relative(pool, &target_rel, true, None).await;
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
        // Mark delete for document markdown
        let _ = mark_dirty_delete_relative(pool, &rel).await;
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
            // Mark delete for attachment
            let _ = mark_dirty_delete_relative(pool, &storage_path).await;
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
