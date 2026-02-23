-- Revert simplified CHECK constraints to nullable-aware versions
ALTER TABLE workspace_invitations DROP CONSTRAINT IF EXISTS chk_kek_version_positive;
ALTER TABLE workspace_invitations
  ADD CONSTRAINT chk_kek_version_positive CHECK (kek_version IS NULL OR kek_version > 0);

ALTER TABLE workspace_invitations DROP CONSTRAINT IF EXISTS chk_kek_nonce_length;
ALTER TABLE workspace_invitations
  ADD CONSTRAINT chk_kek_nonce_length CHECK (kek_nonce IS NULL OR length(kek_nonce) = 24);

ALTER TABLE workspace_invitations DROP CONSTRAINT IF EXISTS chk_encrypted_kek_length;
ALTER TABLE workspace_invitations
  ADD CONSTRAINT chk_encrypted_kek_length CHECK (encrypted_kek IS NULL OR length(encrypted_kek) = 48);

-- Revert KEK columns to nullable with all-or-nothing CHECK
ALTER TABLE workspace_invitations ALTER COLUMN encrypted_kek DROP NOT NULL;
ALTER TABLE workspace_invitations ALTER COLUMN kek_nonce DROP NOT NULL;
ALTER TABLE workspace_invitations ALTER COLUMN kek_version DROP NOT NULL;

ALTER TABLE workspace_invitations
  ADD CONSTRAINT chk_kek_fields CHECK (
    (encrypted_kek IS NULL AND kek_nonce IS NULL AND kek_version IS NULL)
    OR
    (encrypted_kek IS NOT NULL AND kek_nonce IS NOT NULL AND kek_version IS NOT NULL)
  );
