CREATE INDEX IF NOT EXISTS idx_document_snapshot_archives_doc_kind_version_desc
  ON document_snapshot_archives(document_id, kind, version DESC);
