-- Remove FK constraints that prevent doc events and storage projection jobs from surviving deletes
ALTER TABLE storage_projection_jobs
  DROP CONSTRAINT IF EXISTS storage_projection_jobs_doc_id_fkey;

ALTER TABLE storage_projection_jobs
  DROP CONSTRAINT IF EXISTS storage_projection_jobs_folder_id_fkey;

ALTER TABLE doc_events
  DROP CONSTRAINT IF EXISTS doc_events_doc_id_fkey;

-- Persist cursor positions for doc event consumers
CREATE TABLE IF NOT EXISTS doc_event_cursors (
  consumer TEXT PRIMARY KEY,
  last_event_id BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
