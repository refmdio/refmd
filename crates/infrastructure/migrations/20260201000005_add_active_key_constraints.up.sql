-- Add unique constraints to ensure only one active key per entity

-- Ensure only one active KEK per (workspace, user, device)
CREATE UNIQUE INDEX idx_workspace_keys_single_active
ON workspace_encrypted_keys (workspace_id, user_id, device_id)
WHERE is_active = TRUE;

-- Ensure only one active DEK per document
CREATE UNIQUE INDEX idx_document_keys_single_active
ON document_encrypted_keys (document_id)
WHERE is_active = TRUE;
