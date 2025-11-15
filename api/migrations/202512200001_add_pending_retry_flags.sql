ALTER TABLE storage_reconcile_jobs
    ADD COLUMN IF NOT EXISTS pending_retry BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE git_rebuild_jobs
    ADD COLUMN IF NOT EXISTS pending_retry BOOLEAN NOT NULL DEFAULT false;
