ALTER TABLE storage_projection_jobs
    ADD COLUMN IF NOT EXISTS pending_retry BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE storage_ingest_queue
    ADD COLUMN IF NOT EXISTS pending_retry BOOLEAN NOT NULL DEFAULT false;
