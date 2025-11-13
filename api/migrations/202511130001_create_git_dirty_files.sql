-- Track changed files per user for incremental Git Sync
CREATE TABLE IF NOT EXISTS git_dirty_files (
  user_id UUID NOT NULL,
  path TEXT NOT NULL, -- repo-relative path (without leading user_id)
  is_text BOOLEAN NOT NULL,
  op TEXT NOT NULL CHECK (op IN ('upsert','delete')),
  content_hash TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, path)
);

CREATE INDEX IF NOT EXISTS idx_git_dirty_files_user_created
  ON git_dirty_files(user_id, created_at DESC);

