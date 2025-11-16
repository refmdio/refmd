CREATE TABLE storage_projection_jobs (
  id BIGSERIAL PRIMARY KEY,
  job_type TEXT NOT NULL CHECK (job_type IN ('doc_sync','folder_sync','delete_doc','delete_folder')),
  doc_id UUID NULL REFERENCES documents(id) ON DELETE CASCADE,
  folder_id UUID NULL REFERENCES documents(id) ON DELETE CASCADE,
  reason TEXT,
  attempts INT NOT NULL DEFAULT 0,
  locked_at TIMESTAMPTZ NULL,
  last_error TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_storage_projection_jobs_pending
  ON storage_projection_jobs (locked_at, created_at)
  WHERE locked_at IS NULL;

CREATE UNIQUE INDEX idx_storage_projection_jobs_doc_unique
  ON storage_projection_jobs (job_type, doc_id)
  WHERE doc_id IS NOT NULL;

CREATE UNIQUE INDEX idx_storage_projection_jobs_folder_unique
  ON storage_projection_jobs (job_type, folder_id)
  WHERE folder_id IS NOT NULL;

-- Document change events feed both projection and watchers
CREATE TABLE doc_events (
  id BIGSERIAL PRIMARY KEY,
  doc_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  payload JSONB NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_doc_events_doc_created
  ON doc_events (doc_id, created_at);

CREATE TABLE storage_ingest_queue (
  id BIGSERIAL PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  repo_path TEXT NOT NULL,
  backend TEXT NOT NULL DEFAULT 'fs',
  event_kind TEXT NOT NULL CHECK (event_kind IN ('upsert','delete')),
  content_hash TEXT NULL,
  payload JSONB NULL,
  attempts INT NOT NULL DEFAULT 0,
  locked_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_storage_ingest_queue_dedupe
  ON storage_ingest_queue (user_id, repo_path, backend)
  WHERE locked_at IS NULL;
