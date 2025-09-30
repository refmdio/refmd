ALTER TABLE files
    ADD COLUMN IF NOT EXISTS content_hash TEXT;

CREATE INDEX IF NOT EXISTS idx_files_content_hash ON files(content_hash);
