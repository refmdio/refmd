ALTER TABLE document_comment_threads
  ADD COLUMN IF NOT EXISTS start_column integer,
  ADD COLUMN IF NOT EXISTS end_column integer,
  ADD COLUMN IF NOT EXISTS anchored boolean NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS tags text[] NOT NULL DEFAULT '{}';
