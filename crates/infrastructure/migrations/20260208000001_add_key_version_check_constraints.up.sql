-- Add CHECK constraints to ensure key_version is always positive
ALTER TABLE workspace_encrypted_keys ADD CONSTRAINT chk_workspace_key_version_positive CHECK (key_version > 0);
ALTER TABLE document_encrypted_keys ADD CONSTRAINT chk_document_key_version_positive CHECK (key_version > 0);
