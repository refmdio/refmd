-- Allow storage ingest queue events to be scoped purely by workspace without
-- requiring a corresponding user row (e.g., system-driven reconcile jobs).
ALTER TABLE storage_ingest_queue
    DROP CONSTRAINT IF EXISTS storage_ingest_queue_user_id_fkey;
