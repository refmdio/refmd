-- Make (document_id, seq) unique to prevent concurrent duplicate seq assignments
DROP INDEX IF EXISTS idx_document_updates_document_seq;
CREATE UNIQUE INDEX idx_document_updates_document_seq ON document_updates(document_id, seq);
