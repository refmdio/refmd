-- Add creator_encrypted_share_key to share_encrypted_keys table
-- This stores the share key encrypted with the creator's KEK,
-- allowing the share creator to recover the full share URL later.

ALTER TABLE share_encrypted_keys
ADD COLUMN IF NOT EXISTS creator_encrypted_share_key BYTEA,
ADD COLUMN IF NOT EXISTS creator_share_key_nonce BYTEA;

COMMENT ON COLUMN share_encrypted_keys.creator_encrypted_share_key IS 'Share key encrypted with creator KEK (for URL recovery)';
COMMENT ON COLUMN share_encrypted_keys.creator_share_key_nonce IS 'Nonce for creator_encrypted_share_key';
