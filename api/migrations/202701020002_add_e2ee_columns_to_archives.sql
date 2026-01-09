-- Add E2EE columns to document_snapshot_archives
-- These columns are needed for encrypted snapshot archives

ALTER TABLE document_snapshot_archives
    ADD COLUMN IF NOT EXISTS nonce BYTEA,
    ADD COLUMN IF NOT EXISTS signature BYTEA;
