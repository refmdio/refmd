use uuid::Uuid;

use crate::ports::document_repository::DocumentRepository;
use crate::ports::files_repository::FilesRepository;
use crate::ports::git_workspace::GitWorkspacePort;
use crate::ports::gitignore_port::GitignorePort;
use crate::ports::storage_port::StorageResolverPort;
use crate::use_cases::git::helpers::compute_doc_patterns_with;

pub struct IgnoreFolder<'a, G, S, F, D, W>
where
    G: GitignorePort + ?Sized,
    S: StorageResolverPort + ?Sized,
    F: FilesRepository + ?Sized,
    D: DocumentRepository + ?Sized,
    W: GitWorkspacePort + ?Sized,
{
    pub storage: &'a S,
    pub files: &'a F,
    pub docs: &'a D,
    pub gitignore: &'a G,
    pub workspace: &'a W,
}

pub struct IgnoreResult {
    pub added: usize,
    pub patterns: Vec<String>,
}

impl<'a, G, S, F, D, W> IgnoreFolder<'a, G, S, F, D, W>
where
    G: GitignorePort + ?Sized,
    S: StorageResolverPort + ?Sized,
    F: FilesRepository + ?Sized,
    D: DocumentRepository + ?Sized,
    W: GitWorkspacePort + ?Sized,
{
    pub async fn execute(
        &self,
        workspace_id: Uuid,
        folder_id: Uuid,
    ) -> anyhow::Result<IgnoreResult> {
        self.workspace
            .ensure_repository(workspace_id, "main")
            .await?;
        let patterns =
            compute_doc_patterns_with(self.docs, self.files, self.storage, folder_id, workspace_id)
                .await?;
        let dir = self.storage.user_repo_dir(workspace_id);
        let _ = self.gitignore.ensure_gitignore(&dir).await?;
        let added = self
            .gitignore
            .upsert_gitignore_patterns(&dir, &patterns)
            .await?;
        Ok(IgnoreResult { added, patterns })
    }
}
