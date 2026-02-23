-- Add CHECK constraints for invitation KEK/token fields per design doc

-- kek_nonce must be 24 bytes (XChaCha20-Poly1305 nonce)
ALTER TABLE workspace_invitations
  ADD CONSTRAINT chk_kek_nonce_length CHECK (kek_nonce IS NULL OR length(kek_nonce) = 24);

-- kek_version must be positive
ALTER TABLE workspace_invitations
  ADD CONSTRAINT chk_kek_version_positive CHECK (kek_version IS NULL OR kek_version > 0);

-- encrypted_kek must be 48 bytes (32 KEK + 16 Poly1305 tag)
ALTER TABLE workspace_invitations
  ADD CONSTRAINT chk_encrypted_kek_length CHECK (encrypted_kek IS NULL OR length(encrypted_kek) = 48);

-- token_hash must be 43 chars (base64url of SHA-256)
ALTER TABLE workspace_invitations
  ADD CONSTRAINT chk_token_hash_length CHECK (length(token_hash) = 43);

-- token_hash must be valid base64url chars
ALTER TABLE workspace_invitations
  ADD CONSTRAINT chk_token_hash_format CHECK (token_hash ~ '^[A-Za-z0-9\-_]{43}$');

-- token_prefix must be exactly 4 chars
ALTER TABLE workspace_invitations
  ADD CONSTRAINT chk_token_prefix_length CHECK (length(token_prefix) = 4);

-- token_prefix must be valid base64url chars
ALTER TABLE workspace_invitations
  ADD CONSTRAINT chk_token_prefix_format CHECK (token_prefix ~ '^[A-Za-z0-9\-_]{4}$');

-- NOTE: max_uses range (1-1000) already enforced by chk_max_uses in 20260219000001

-- use_count must be non-negative and <= max_uses
ALTER TABLE workspace_invitations
  ADD CONSTRAINT chk_use_count_range CHECK (use_count >= 0 AND use_count <= max_uses);
