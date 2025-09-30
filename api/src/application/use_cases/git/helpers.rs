use crate::application::ports::document_repository::DocumentRepository;
use crate::application::ports::files_repository::FilesRepository;
use crate::application::ports::storage_port::StoragePort;
use uuid::Uuid;

fn strip_user_prefix(owner_id: Uuid, rel_from_uploads: &str) -> String {
    let pfx = format!("{}/", owner_id);
    if let Some(stripped) = rel_from_uploads.strip_prefix(&pfx) {
        stripped.to_string()
    } else {
        rel_from_uploads.to_string()
    }
}

/// Compute .gitignore patterns for a document or folder.
/// - For document: returns the markdown file path and attachment file paths
///   relative to the user's repository root.
/// - For folder: returns a single directory pattern with trailing '/'
pub async fn compute_doc_patterns_with<
    D: DocumentRepository + ?Sized,
    F: FilesRepository + ?Sized,
    S: StoragePort + ?Sized,
>(
    docs: &D,
    files: &F,
    storage: &S,
    node_id: Uuid,
    owner_id: Uuid,
) -> anyhow::Result<Vec<String>> {
    // Fetch document meta for owner
    let meta = docs
        .get_meta_for_owner(node_id, owner_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Document not found"))?;
    let dtype = meta.doc_type;

    // Folder: ignore the entire directory under the repo root
    if dtype == "folder" {
        let dir_full = storage.build_doc_dir(node_id).await?; // .../uploads/<owner>/<folders>
        let rel_from_uploads = storage.relative_from_uploads(&dir_full);
        let repo_rel = strip_user_prefix(owner_id, &rel_from_uploads);
        let mut pat = repo_rel;
        if !pat.ends_with('/') {
            pat.push('/');
        }
        return Ok(vec![pat]);
    }

    // Document: file path + attachment files
    let mut patterns: Vec<String> = Vec::new();

    // 1) Markdown file path
    let file_rel_from_uploads: String = if let Some(p) = meta.path {
        p
    } else {
        let full = storage.build_doc_file_path(node_id).await?;
        storage.relative_from_uploads(&full)
    };
    let file_repo_rel = strip_user_prefix(owner_id, &file_rel_from_uploads);
    patterns.push(file_repo_rel);

    // 2) Attachment paths (exact files for the document)
    let file_paths = files.list_storage_paths_for_document(node_id).await?;
    for storage_path in file_paths {
        let full = storage.absolute_from_relative(&storage_path);
        let rel_from_uploads = storage.relative_from_uploads(&full);
        let repo_rel = strip_user_prefix(owner_id, &rel_from_uploads);
        patterns.push(repo_rel);
    }

    // Dedup to keep .gitignore tidy
    patterns.sort();
    patterns.dedup();
    Ok(patterns)
}
