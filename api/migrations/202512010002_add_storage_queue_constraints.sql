DROP INDEX IF EXISTS idx_storage_ingest_queue_dedupe;
DROP INDEX IF EXISTS idx_storage_reconcile_jobs_unique;

ALTER TABLE storage_ingest_queue
    ADD CONSTRAINT storage_ingest_queue_user_repo_backend_unique
    UNIQUE (user_id, repo_path, backend);

ALTER TABLE storage_reconcile_jobs
    ADD CONSTRAINT storage_reconcile_jobs_user_scope_unique
    UNIQUE (user_id, scope);
