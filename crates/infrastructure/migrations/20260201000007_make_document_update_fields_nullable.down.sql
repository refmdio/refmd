-- Revert: Make Phase 2 fields required again
-- WARNING: This will fail if there are any NULL values in these columns

-- Drop the partial unique index
DROP INDEX IF EXISTS idx_document_updates_hash_unique;

-- Make columns NOT NULL again
ALTER TABLE document_updates
    ALTER COLUMN update_hash SET NOT NULL,
    ALTER COLUMN signature SET NOT NULL,
    DROP CONSTRAINT IF EXISTS document_updates_author_device_id_fkey,
    ALTER COLUMN author_device_id SET NOT NULL;

-- Re-add original foreign key constraint (not nullable)
ALTER TABLE document_updates
    ADD CONSTRAINT document_updates_author_device_id_fkey
    FOREIGN KEY (author_device_id) REFERENCES devices(id) ON DELETE CASCADE;

-- Re-add unique constraint on update_hash
ALTER TABLE document_updates ADD CONSTRAINT document_updates_update_hash_key UNIQUE (update_hash);
