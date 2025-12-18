impl GitWorkspaceService {
    async fn export_markdown_for_repo_path(
        &self,
        workspace_id: Uuid,
        repo_path: &str,
    ) -> anyhow::Result<Option<(Vec<u8>, String)>> {
        let trimmed = repo_path.trim_start_matches('/');
        let mut candidates: Vec<(&str, bool)> = vec![(trimmed, false)];
        if let Some(stripped) = trimmed.strip_prefix("Archives/") {
            if !stripped.is_empty() {
                candidates.push((stripped, true));
            }
        }

        // First try by normalized repo path (documents.path). Fall back to desired_path for older records.
        let all_docs = self.docs.list_workspace_documents(workspace_id).await?;

        for (candidate, archived_only) in candidates {
            let lookup_path = format!("{}/{}", workspace_id, candidate);
            let from_path = self
                .doc_paths
                .get_by_owner_and_path(workspace_id, &lookup_path)
                .await?;

            let doc = if let Some(doc) = from_path {
                Some(doc)
            } else {
                all_docs
                    .iter()
                    .find(|d| normalize_repo_path(d.desired_path.as_str().to_string()) == candidate)
                    .cloned()
            };

            if let Some(doc) = doc {
                if doc.doc_type == DocumentType::Folder {
                    continue;
                }
                if archived_only && doc.archived_at.is_none() {
                    continue;
                }
                if let Some(export) = self.snapshot.export_current_markdown(&doc.id).await? {
                    return Ok(Some((export.bytes, export.content_hash)));
                }
            }
        }

        Ok(None)
    }
}
