ALTER TABLE documents
  ADD COLUMN IF NOT EXISTS type TEXT NOT NULL DEFAULT 'document'
  CHECK (type IN ('document','folder'));
