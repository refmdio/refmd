-- Make KEK encryption columns NOT NULL (defense in depth)
--
-- Legacy invitations (pre-Phase 3) were revoked in 20260222000001 migration
-- (revoked_at = NOW(), invited_email = 'revoked@legacy.local').
-- Backfill their KEK fields with sentinel values so NOT NULL can be applied.
-- These rows will never pass acceptance validation (revoked_at IS NOT NULL).

-- Backfill revoked legacy rows with sentinel values
-- kek_version = 1 satisfies existing CHECK (kek_version IS NULL OR kek_version > 0)
UPDATE workspace_invitations
SET encrypted_kek = decode(repeat('00', 48), 'hex'),
    kek_nonce = decode(repeat('00', 24), 'hex'),
    kek_version = 1
WHERE encrypted_kek IS NULL;

-- Drop the all-or-nothing CHECK (superseded by NOT NULL)
ALTER TABLE workspace_invitations DROP CONSTRAINT IF EXISTS chk_kek_fields;

-- Apply NOT NULL constraints
ALTER TABLE workspace_invitations ALTER COLUMN encrypted_kek SET NOT NULL;
ALTER TABLE workspace_invitations ALTER COLUMN kek_nonce SET NOT NULL;
ALTER TABLE workspace_invitations ALTER COLUMN kek_version SET NOT NULL;

-- Simplify CHECK constraints (now NOT NULL, remove vestigial "IS NULL OR" branches)
ALTER TABLE workspace_invitations DROP CONSTRAINT IF EXISTS chk_kek_version_positive;
ALTER TABLE workspace_invitations
  ADD CONSTRAINT chk_kek_version_positive CHECK (kek_version > 0);

ALTER TABLE workspace_invitations DROP CONSTRAINT IF EXISTS chk_kek_nonce_length;
ALTER TABLE workspace_invitations
  ADD CONSTRAINT chk_kek_nonce_length CHECK (length(kek_nonce) = 24);

ALTER TABLE workspace_invitations DROP CONSTRAINT IF EXISTS chk_encrypted_kek_length;
ALTER TABLE workspace_invitations
  ADD CONSTRAINT chk_encrypted_kek_length CHECK (length(encrypted_kek) = 48);
