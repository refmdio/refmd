-- Remove nonce constraints

DROP INDEX IF EXISTS idx_workspace_keys_nonce_check;
DROP INDEX IF EXISTS idx_document_keys_nonce_check;

COMMENT ON COLUMN workspace_encrypted_keys.nonce IS NULL;
COMMENT ON COLUMN document_encrypted_keys.nonce IS NULL;
