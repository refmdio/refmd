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
    // Fetch basic document info first
    let row = sqlx::query(
        "SELECT owner_id, parent_id, archived_at, archived_parent_id FROM documents WHERE id = $1",
    )
    .bind(doc_id)
    .fetch_optional(pool)
    .await?;
    let row = row.ok_or_else(|| anyhow::anyhow!("Document not found"))?;

    let owner_id: Uuid = row.get("owner_id");
    let archived_at: Option<chrono::DateTime<chrono::Utc>> = row
        .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("archived_at")
        .ok()
        .flatten();
    let mut dir = uploads_root.to_path_buf();
    dir.push(owner_id.to_string());

    let mut current_parent: Option<Uuid> = if archived_at.is_some() {
        dir.push("Archives");
        row.try_get::<Option<Uuid>, _>("archived_parent_id")
            .ok()
            .flatten()
    } else {
        row.try_get::<Option<Uuid>, _>("parent_id").ok().flatten()
    };

    let mut components: Vec<String> = Vec::new();
    while let Some(pid) = current_parent {
        let parent = sqlx::query(
            "SELECT title, type, parent_id, archived_at, archived_parent_id FROM documents WHERE id = $1",
        )
        .bind(pid)
        .fetch_optional(pool)
        .await?;
        let parent = match parent {
            Some(row) => row,
            None => break,
        };

        let dtype: String = parent.get("type");
        if dtype == "folder" {
            let title: String = parent.get("title");
            components.push(sanitize_title(&title));
        }
        let parent_archived: Option<chrono::DateTime<chrono::Utc>> = parent
            .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("archived_at")
            .ok()
            .flatten();
        current_parent = if parent_archived.is_some() {
            parent
                .try_get::<Option<Uuid>, _>("archived_parent_id")
                .ok()
                .flatten()
        } else {
            parent
                .try_get::<Option<Uuid>, _>("parent_id")
                .ok()
                .flatten()
        };
    }

    components.reverse();
    for component in components {
        dir.push(component);
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

pub async fn ensure_unique_doc_path(
    pool: &PgPool,
    uploads_root: &Path,
    doc_id: Uuid,
    desired_full: &Path,
) -> anyhow::Result<(PathBuf, String)> {
    let mut full = desired_full.to_path_buf();
    let parent = full
        .parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| anyhow::anyhow!("invalid desired path"))?;
    let mut file_name = full
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("invalid file name"))?
        .to_string();

    let (stem, ext) = {
        let p = Path::new(&file_name);
        let stem = p
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("document")
            .to_string();
        let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
        (stem, ext.to_string())
    };

    let mut counter: u32 = 1;
    loop {
        let rel = relative_from_uploads(uploads_root, &full);
        let row = sqlx::query("SELECT id FROM documents WHERE path = $1 LIMIT 1")
            .bind(&rel)
            .fetch_optional(pool)
            .await?;
        let ok = match row {
            None => true,
            Some(r) => {
                let other: Uuid = r.get("id");
                other == doc_id
            }
        };
        if ok {
            let rel = relative_from_uploads(uploads_root, &full);
            return Ok((full, rel));
        }

        counter += 1;
        let new_name = if ext.is_empty() {
            format!("{}-{}", stem, counter)
        } else {
            format!("{}-{}.{}", stem, counter, ext)
        };
        file_name = new_name;
        full = parent.join(&file_name);
    }
}

// Convert uploads-relative path to repo-relative path and extract user_id.
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
    user_id: Uuid,
    repo_path: &str,
    is_text: bool,
    content_hash: Option<&str>,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"INSERT INTO git_dirty_files (user_id, path, is_text, op, content_hash)
            VALUES ($1, $2, $3, 'upsert', $4)
            ON CONFLICT (user_id, path)
            DO UPDATE SET op = EXCLUDED.op,
                          is_text = EXCLUDED.is_text,
                          content_hash = EXCLUDED.content_hash,
                          created_at = now()"#,
    )
    .bind(user_id)
    .bind(repo_path)
    .bind(is_text)
    .bind(content_hash)
    .execute(pool)
    .await?;
    Ok(())
}

async fn mark_dirty_delete_internal(
    pool: &PgPool,
    user_id: Uuid,
    repo_path: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"INSERT INTO git_dirty_files (user_id, path, is_text, op, content_hash)
            VALUES ($1, $2, false, 'delete', NULL)
            ON CONFLICT (user_id, path)
            DO UPDATE SET op = EXCLUDED.op,
                          created_at = now()"#,
    )
    .bind(user_id)
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
    let rel = relative_from_uploads(uploads_root, abs_path).replace('\\', "/");
    if let Some((user_id, repo_path)) = split_owner_and_repo_path(&rel) {
        if !repo_path.is_empty() {
            let _ =
                mark_dirty_upsert_internal(pool, user_id, &repo_path, is_text, content_hash).await;
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
    let rel = relative.trim_start_matches('/');
    if let Some((user_id, repo_path)) = split_owner_and_repo_path(rel) {
        if !repo_path.is_empty() {
            let _ =
                mark_dirty_upsert_internal(pool, user_id, &repo_path, is_text, content_hash).await;
        }
    }
    Ok(())
}

pub async fn mark_dirty_delete_relative(pool: &PgPool, relative: &str) -> anyhow::Result<()> {
    let rel = relative.trim_start_matches('/');
    if let Some((user_id, repo_path)) = split_owner_and_repo_path(rel) {
        if !repo_path.is_empty() {
            let _ = mark_dirty_delete_internal(pool, user_id, &repo_path).await;
        }
    }
    Ok(())
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

    let desired_full = build_doc_file_path(pool, uploads_root, doc_id).await?;
    let (new_full, new_rel) =
        ensure_unique_doc_path(pool, uploads_root, doc_id, &desired_full).await?;
    if let Some(parent) = new_full.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }

    // Move .md if exists
    if let Some(old_rel) = old_rel.clone() {
        let old_full = uploads_root.join(&old_rel);
        if tokio::fs::try_exists(&old_full).await.unwrap_or(false) {
            let _ = tokio::fs::rename(&old_full, &new_full).await;
        }
        // Mark old path as deleted (repo-relative)
        let _ = mark_dirty_delete_relative(pool, &old_rel).await;
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

                        // Mark move: old delete, new upsert (binary)
                        let _ = mark_dirty_delete_relative(pool, &old_path).await;
                        let _ = mark_dirty_upsert_relative(
                            pool,
                            &relative_from_uploads(uploads_root, &new_path),
                            false,
                            None,
                        )
                        .await;
                    }
                }
            }
        }
    }

    // Update documents.path
    let _ = sqlx::query("UPDATE documents SET path = $2, updated_at = now() WHERE id = $1")
        .bind(doc_id)
        .bind(&new_rel)
        .execute(pool)
        .await;

    // Mark new path as upsert (text)
    let _ = mark_dirty_upsert_relative(pool, &new_rel, true, None).await;
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
