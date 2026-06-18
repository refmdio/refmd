CREATE TABLE IF NOT EXISTS document_comment_threads (
  id uuid PRIMARY KEY,
  document_id uuid NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  marker text NOT NULL,
  quote text NOT NULL DEFAULT '',
  start_line_number integer,
  end_line_number integer,
  start_offset integer,
  end_offset integer,
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,
  created_by_name text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  resolved_at timestamptz,
  resolved_by uuid REFERENCES users(id) ON DELETE SET NULL,
  UNIQUE(document_id, marker),
  CHECK (marker ~ '^<!--comment:[A-Za-z0-9_-]+-->$')
);

CREATE INDEX IF NOT EXISTS idx_document_comment_threads_document
  ON document_comment_threads(document_id, resolved_at, created_at);

CREATE TABLE IF NOT EXISTS document_comment_replies (
  id uuid PRIMARY KEY,
  thread_id uuid NOT NULL REFERENCES document_comment_threads(id) ON DELETE CASCADE,
  document_id uuid NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  body text NOT NULL,
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,
  created_by_name text,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (char_length(trim(body)) > 0)
);

CREATE INDEX IF NOT EXISTS idx_document_comment_replies_thread
  ON document_comment_replies(thread_id, created_at);
