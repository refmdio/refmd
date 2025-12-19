use std::sync::Arc;

use async_trait::async_trait;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use application::core::ports::errors::PortResult;
use application::core::ports::storage::storage_projection_queue::{
    StorageProjectionJobKind, StorageProjectionQueueTx,
};
use application::documents::ports::document_repository::{
    DocumentRepoResult, DocumentRepositoryError, DocumentRepositoryTx, SubtreeDocument,
};
use application::documents::ports::files::files_repository::FilesRepositoryTx;
use application::documents::ports::tx_runner::{
    BoxedTxResult, DocumentsTx, DocumentsTxFn, DocumentsTxRunner,
};
use domain::documents::doc_type::DocumentType;
use domain::documents::path as doc_path;
use domain::documents::title::Title;

use crate::core::db::PgPool;
use crate::documents::db::repositories::document_repository_sqlx::SqlxDocumentRepository;
use crate::documents::db::repositories::files_repository_sqlx::SqlxFilesRepository;

pub struct SqlxDocumentsTxRunner {
    pool: PgPool,
    documents_repo: Arc<SqlxDocumentRepository>,
    files_repo: Arc<SqlxFilesRepository>,
}

impl SqlxDocumentsTxRunner {
    pub fn new(
        pool: PgPool,
        documents_repo: Arc<SqlxDocumentRepository>,
        files_repo: Arc<SqlxFilesRepository>,
    ) -> Self {
        Self {
            pool,
            documents_repo,
            files_repo,
        }
    }
}

struct SqlxDocumentsTx<'repo, 'tx, 'c> {
    documents_repo: &'repo SqlxDocumentRepository,
    files_repo: &'repo SqlxFilesRepository,
    tx: &'tx mut Transaction<'c, Postgres>,
}

impl<'repo, 'tx, 'c> DocumentsTx for SqlxDocumentsTx<'repo, 'tx, 'c> {
    fn documents(&mut self) -> &mut dyn DocumentRepositoryTx {
        self
    }

    fn files(&mut self) -> &mut dyn FilesRepositoryTx {
        self
    }

    fn storage_jobs(&mut self) -> &mut dyn StorageProjectionQueueTx {
        self
    }
}

#[async_trait]
impl<'repo, 'tx, 'c> DocumentRepositoryTx for SqlxDocumentsTx<'repo, 'tx, 'c> {
    async fn create_for_user(
        &mut self,
        workspace_id: Uuid,
        created_by: Uuid,
        title: &Title,
        parent_id: Option<Uuid>,
        doc_type: DocumentType,
        created_by_plugin: Option<&str>,
        slug: &doc_path::Slug,
        desired_path: &doc_path::DesiredPath,
    ) -> DocumentRepoResult<domain::documents::document::Document> {
        self.documents_repo
            .create_for_user_tx(
                self.tx,
                workspace_id,
                created_by,
                title,
                parent_id,
                doc_type,
                created_by_plugin,
                slug,
                desired_path,
            )
            .await
    }

    async fn update_title_and_parent_for_user(
        &mut self,
        id: Uuid,
        workspace_id: Uuid,
        title: &Title,
        parent_id: Option<Option<Uuid>>,
        slug: &doc_path::Slug,
        desired_path: &doc_path::DesiredPath,
    ) -> DocumentRepoResult<Option<domain::documents::document::Document>> {
        self.documents_repo
            .update_title_and_parent_for_user_tx(
                self.tx,
                id,
                workspace_id,
                title,
                parent_id,
                slug,
                desired_path,
            )
            .await
    }

    async fn delete_owned(
        &mut self,
        id: Uuid,
        workspace_id: Uuid,
    ) -> DocumentRepoResult<Option<DocumentType>> {
        self.documents_repo
            .delete_owned_tx(self.tx, id, workspace_id)
            .await
            .map_err(DocumentRepositoryError::from)
    }

    async fn get_meta_for_owner(
        &mut self,
        doc_id: Uuid,
        workspace_id: Uuid,
    ) -> DocumentRepoResult<Option<application::documents::ports::document_repository::DocMeta>>
    {
        self.documents_repo
            .get_meta_for_owner_tx(self.tx, doc_id, workspace_id)
            .await
            .map_err(DocumentRepositoryError::from)
    }

    async fn archive_subtree(
        &mut self,
        doc_id: Uuid,
        workspace_id: Uuid,
        archived_by: Uuid,
    ) -> DocumentRepoResult<Option<domain::documents::document::Document>> {
        self.documents_repo
            .archive_subtree_tx(self.tx, doc_id, workspace_id, archived_by)
            .await
            .map_err(DocumentRepositoryError::from)
    }

    async fn unarchive_subtree(
        &mut self,
        doc_id: Uuid,
        workspace_id: Uuid,
    ) -> DocumentRepoResult<Option<domain::documents::document::Document>> {
        self.documents_repo
            .unarchive_subtree_tx(self.tx, doc_id, workspace_id)
            .await
            .map_err(DocumentRepositoryError::from)
    }

    async fn list_owned_subtree_documents(
        &mut self,
        workspace_id: Uuid,
        root_id: Uuid,
    ) -> DocumentRepoResult<Vec<SubtreeDocument>> {
        self.documents_repo
            .list_owned_subtree_documents_tx(self.tx, workspace_id, root_id)
            .await
            .map_err(DocumentRepositoryError::from)
    }
}

#[async_trait]
impl<'repo, 'tx, 'c> FilesRepositoryTx for SqlxDocumentsTx<'repo, 'tx, 'c> {
    async fn list_storage_paths_for_document(
        &mut self,
        doc_id: Uuid,
    ) -> PortResult<Vec<String>> {
        self.files_repo
            .list_storage_paths_for_document_tx(self.tx, doc_id)
            .await
            .map_err(Into::into)
    }
}

#[async_trait]
impl<'repo, 'tx, 'c> StorageProjectionQueueTx for SqlxDocumentsTx<'repo, 'tx, 'c> {
    async fn enqueue_doc_job(
        &mut self,
        workspace_id: Uuid,
        doc_id: Uuid,
        kind: StorageProjectionJobKind,
        reason: Option<&str>,
    ) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            match kind {
                StorageProjectionJobKind::DocSync | StorageProjectionJobKind::DeleteDoc => {}
                other => anyhow::bail!("job_kind {other:?} requires a folder_id"),
            }

            let job_type = kind_to_str(kind);
            sqlx::query(
                r#"
            INSERT INTO storage_projection_jobs (workspace_id, job_type, doc_id, reason, attempts, locked_at, last_error)
            VALUES ($1, $2, $3, $4, 0, NULL, NULL)
            ON CONFLICT (job_type, doc_id) WHERE doc_id IS NOT NULL
            DO UPDATE SET reason = EXCLUDED.reason,
                          locked_at = CASE
                              WHEN storage_projection_jobs.locked_at IS NULL THEN NULL
                              ELSE storage_projection_jobs.locked_at
                          END,
                          attempts = CASE
                              WHEN storage_projection_jobs.locked_at IS NULL THEN 0
                              ELSE storage_projection_jobs.attempts
                          END,
                          last_error = CASE
                              WHEN storage_projection_jobs.locked_at IS NULL THEN NULL
                              ELSE storage_projection_jobs.last_error
                          END,
                          workspace_id = EXCLUDED.workspace_id,
                          pending_retry = CASE
                              WHEN storage_projection_jobs.locked_at IS NULL THEN false
                              ELSE true
                          END,
                          updated_at = now()
            "#,
            )
            .bind(workspace_id)
            .bind(job_type)
            .bind(doc_id)
            .bind(reason)
            .execute(self.tx.as_mut())
            .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn enqueue_folder_job(
        &mut self,
        workspace_id: Uuid,
        folder_id: Uuid,
        kind: StorageProjectionJobKind,
        reason: Option<&str>,
    ) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            match kind {
                StorageProjectionJobKind::FolderSync | StorageProjectionJobKind::DeleteFolder => {}
                other => anyhow::bail!("job_kind {other:?} requires a doc_id"),
            }

            let job_type = kind_to_str(kind);
            sqlx::query(
                r#"
            INSERT INTO storage_projection_jobs (workspace_id, job_type, folder_id, reason, attempts, locked_at, last_error)
            VALUES ($1, $2, $3, $4, 0, NULL, NULL)
            ON CONFLICT (job_type, folder_id) WHERE folder_id IS NOT NULL
            DO UPDATE SET reason = EXCLUDED.reason,
                          locked_at = CASE
                              WHEN storage_projection_jobs.locked_at IS NULL THEN NULL
                              ELSE storage_projection_jobs.locked_at
                          END,
                          attempts = CASE
                              WHEN storage_projection_jobs.locked_at IS NULL THEN 0
                              ELSE storage_projection_jobs.attempts
                          END,
                          last_error = CASE
                              WHEN storage_projection_jobs.locked_at IS NULL THEN NULL
                              ELSE storage_projection_jobs.last_error
                          END,
                          workspace_id = EXCLUDED.workspace_id,
                          pending_retry = CASE
                              WHEN storage_projection_jobs.locked_at IS NULL THEN false
                              ELSE true
                          END,
                          updated_at = now()
            "#,
            )
            .bind(workspace_id)
            .bind(job_type)
            .bind(folder_id)
            .bind(reason)
            .execute(self.tx.as_mut())
            .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }
}

fn kind_to_str(kind: StorageProjectionJobKind) -> &'static str {
    match kind {
        StorageProjectionJobKind::DocSync => "doc_sync",
        StorageProjectionJobKind::FolderSync => "folder_sync",
        StorageProjectionJobKind::DeleteDoc => "delete_doc",
        StorageProjectionJobKind::DeleteFolder => "delete_folder",
    }
}

#[async_trait]
impl DocumentsTxRunner for SqlxDocumentsTxRunner {
    async fn run_boxed(&self, f: DocumentsTxFn) -> anyhow::Result<BoxedTxResult> {
        let mut tx = self.pool.begin().await?;
        let mut uow = SqlxDocumentsTx {
            documents_repo: self.documents_repo.as_ref(),
            files_repo: self.files_repo.as_ref(),
            tx: &mut tx,
        };

        let result = f(&mut uow).await;
        match result {
            Ok(out) => {
                tx.commit().await?;
                Ok(out)
            }
            Err(err) => {
                tx.rollback().await.ok();
                Err(err)
            }
        }
    }
}
