-- Revert unique constraint back to regular index
DROP INDEX IF EXISTS idx_document_updates_document_seq;
CREATE INDEX idx_document_updates_document_seq ON document_updates(document_id, seq);
