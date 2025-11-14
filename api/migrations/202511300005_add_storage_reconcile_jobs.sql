-- Storage reconcile jobs for orphan cleanup

CREATE TABLE storage_reconcile_jobs (
  id BIGSERIAL PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scope TEXT NOT NULL DEFAULT 'full',
  attempts INT NOT NULL DEFAULT 0,
  locked_at TIMESTAMPTZ NULL,
  last_error TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_storage_reconcile_jobs_pending
  ON storage_reconcile_jobs (locked_at, created_at)
  WHERE locked_at IS NULL;

CREATE UNIQUE INDEX idx_storage_reconcile_jobs_unique
  ON storage_reconcile_jobs (user_id, scope)
  WHERE locked_at IS NULL;
