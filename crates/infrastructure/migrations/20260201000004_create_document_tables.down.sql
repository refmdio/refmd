-- Drop document domain tables

-- Remove FK constraint from document_encrypted_keys
ALTER TABLE document_encrypted_keys
    DROP CONSTRAINT IF EXISTS fk_document_encrypted_keys_document;

DROP TABLE IF EXISTS document_links;
DROP TABLE IF EXISTS document_tags;
DROP TABLE IF EXISTS tags;
DROP TABLE IF EXISTS document_snapshot_archives;
DROP TABLE IF EXISTS document_snapshots;
DROP TABLE IF EXISTS document_updates;
DROP TABLE IF EXISTS documents;
