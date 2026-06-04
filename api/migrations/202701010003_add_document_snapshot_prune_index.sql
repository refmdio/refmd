CREATE INDEX IF NOT EXISTS idx_document_snapshots_doc_version_desc
  ON document_snapshots(document_id, version DESC);
