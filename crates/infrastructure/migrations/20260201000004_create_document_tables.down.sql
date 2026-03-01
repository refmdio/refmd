-- Drop document domain tables

-- Remove FK constraint from document_encrypted_keys
ALTER TABLE document_encrypted_keys
    DROP CONSTRAINT IF EXISTS fk_document_encrypted_keys_document;

-- Drop circular FK constraints before table drops
-- (documents.active_snapshot_id -> document_snapshots.id)
ALTER TABLE documents
    DROP CONSTRAINT IF EXISTS documents_active_snapshot_id_fkey;

-- (document_snapshots.document_id -> documents.id)
ALTER TABLE document_snapshots
    DROP CONSTRAINT IF EXISTS document_snapshots_document_id_fkey;

-- (document_snapshots.parent_snapshot_id -> document_snapshots.id)
ALTER TABLE document_snapshots
    DROP CONSTRAINT IF EXISTS document_snapshots_parent_snapshot_id_fkey;

DROP TABLE IF EXISTS document_links;
DROP TABLE IF EXISTS document_tags;
DROP TABLE IF EXISTS tags;
DROP TABLE IF EXISTS document_updates;
DROP TABLE IF EXISTS document_snapshots;
DROP TABLE IF EXISTS documents;
