-- Public document files table for storing decrypted attachments
-- When an E2EE document is published, its attachments are decrypted and stored here
-- for public access without requiring encryption keys.

CREATE TABLE IF NOT EXISTS public_document_files (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    file_id UUID NOT NULL,  -- Reference to the original encrypted file
    original_filename TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    size BIGINT NOT NULL,
    storage_path TEXT NOT NULL,  -- Path in storage: public/{workspace_id}/{document_id}/{file_id}
    content_hash TEXT NOT NULL,  -- SHA-256 hash for integrity
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (document_id, file_id)
);

-- Index for efficient lookup by document
CREATE INDEX IF NOT EXISTS idx_public_document_files_document_id
    ON public_document_files(document_id);

-- Index for cleanup when document is unpublished
CREATE INDEX IF NOT EXISTS idx_public_document_files_workspace_document
    ON public_document_files(workspace_id, document_id);
