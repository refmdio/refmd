ALTER TABLE workspace_invitations DROP CONSTRAINT IF EXISTS chk_kek_nonce_length;
ALTER TABLE workspace_invitations DROP CONSTRAINT IF EXISTS chk_kek_version_positive;
ALTER TABLE workspace_invitations DROP CONSTRAINT IF EXISTS chk_encrypted_kek_length;
ALTER TABLE workspace_invitations DROP CONSTRAINT IF EXISTS chk_token_hash_length;
ALTER TABLE workspace_invitations DROP CONSTRAINT IF EXISTS chk_token_hash_format;
ALTER TABLE workspace_invitations DROP CONSTRAINT IF EXISTS chk_token_prefix_length;
ALTER TABLE workspace_invitations DROP CONSTRAINT IF EXISTS chk_token_prefix_format;
ALTER TABLE workspace_invitations DROP CONSTRAINT IF EXISTS chk_use_count_range;
