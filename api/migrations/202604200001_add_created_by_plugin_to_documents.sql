ALTER TABLE documents
ADD COLUMN IF NOT EXISTS created_by_plugin TEXT NULL;

CREATE INDEX IF NOT EXISTS idx_documents_created_by_plugin
  ON documents(created_by_plugin);
