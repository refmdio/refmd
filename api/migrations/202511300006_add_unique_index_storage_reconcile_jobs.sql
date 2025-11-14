-- Ensure storage_reconcile_jobs has the partial unique index required by ON CONFLICT

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind = 'i'
          AND c.relname = 'idx_storage_reconcile_jobs_unique'
    ) THEN
        EXECUTE '
            CREATE UNIQUE INDEX idx_storage_reconcile_jobs_unique
            ON storage_reconcile_jobs (user_id, scope)
            WHERE locked_at IS NULL
        ';
    END IF;
END $$;
