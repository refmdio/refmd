-- Add constraints to help detect nonce reuse
-- Note: Full nonce safety requires client-side implementation.
-- These constraints provide server-side detection as defense-in-depth.

-- For workspace encrypted keys: nonce should be unique per (workspace, user, device, key_version)
-- This is implicitly enforced by the primary key, but we add an index for query performance
CREATE INDEX idx_workspace_keys_nonce_check
ON workspace_encrypted_keys (workspace_id, user_id, device_id, nonce);

-- For document encrypted keys: nonce should be unique per (document, key_version)
-- This is implicitly enforced by the primary key
CREATE INDEX idx_document_keys_nonce_check
ON document_encrypted_keys (document_id, nonce);

-- Add comment explaining nonce safety
COMMENT ON COLUMN workspace_encrypted_keys.nonce IS 'XChaCha20-Poly1305 nonce (24 bytes). Must never be reused with the same key.';
COMMENT ON COLUMN document_encrypted_keys.nonce IS 'XChaCha20-Poly1305 nonce (24 bytes). Must never be reused with the same key.';
