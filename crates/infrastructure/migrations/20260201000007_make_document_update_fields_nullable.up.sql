-- Make Phase 2 fields nullable for MVP implementation
-- Phase 2 features: update_hash, signature, author_device_id

-- Remove unique constraint on update_hash first
ALTER TABLE document_updates DROP CONSTRAINT IF EXISTS document_updates_update_hash_key;

-- Make columns nullable
ALTER TABLE document_updates
    ALTER COLUMN update_hash DROP NOT NULL,
    ALTER COLUMN signature DROP NOT NULL,
    DROP CONSTRAINT IF EXISTS document_updates_author_device_id_fkey,
    ALTER COLUMN author_device_id DROP NOT NULL;

-- Re-add foreign key as nullable reference
ALTER TABLE document_updates
    ADD CONSTRAINT document_updates_author_device_id_fkey
    FOREIGN KEY (author_device_id) REFERENCES devices(id) ON DELETE SET NULL;

-- Add partial unique index for non-null update_hash
CREATE UNIQUE INDEX IF NOT EXISTS idx_document_updates_hash_unique
    ON document_updates(update_hash) WHERE update_hash IS NOT NULL;
