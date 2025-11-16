DROP INDEX IF EXISTS idx_storage_ingest_queue_dedupe;
DROP INDEX IF EXISTS idx_storage_reconcile_jobs_unique;

-- Remove duplicate ingest queue rows before enforcing the new unique constraint.
WITH ranked AS (
    SELECT
        id,
        ROW_NUMBER() OVER (
            PARTITION BY user_id, repo_path, backend
            ORDER BY created_at DESC, id DESC
        ) AS rn
    FROM storage_ingest_queue
)
DELETE FROM storage_ingest_queue
WHERE id IN (SELECT id FROM ranked WHERE rn > 1);

ALTER TABLE storage_ingest_queue
    ADD CONSTRAINT storage_ingest_queue_user_repo_backend_unique
    UNIQUE (user_id, repo_path, backend);

ALTER TABLE storage_reconcile_jobs
    ADD CONSTRAINT storage_reconcile_jobs_user_scope_unique
    UNIQUE (user_id, scope);
