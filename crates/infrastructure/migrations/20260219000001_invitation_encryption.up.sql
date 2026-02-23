-- Add encryption columns and revocation support to workspace invitations

-- Encryption columns (KEK encrypted with token-derived key)
ALTER TABLE workspace_invitations
  ADD COLUMN encrypted_kek BYTEA,
  ADD COLUMN kek_nonce BYTEA,
  ADD COLUMN kek_version INT,
  ADD COLUMN revoked_at TIMESTAMPTZ;

-- role_id: allow NULL (set to NULL when role is deleted)
ALTER TABLE workspace_invitations DROP CONSTRAINT workspace_invitations_role_id_fkey;
ALTER TABLE workspace_invitations ALTER COLUMN role_id DROP NOT NULL;
ALTER TABLE workspace_invitations
  ADD CONSTRAINT workspace_invitations_role_fkey
  FOREIGN KEY (workspace_id, role_id)
  REFERENCES workspace_roles(workspace_id, id) ON DELETE SET NULL (role_id);

-- max_uses: ensure always in valid range
ALTER TABLE workspace_invitations
  ADD CONSTRAINT chk_max_uses CHECK (max_uses >= 1 AND max_uses <= 1000);

-- KEK fields: all-or-nothing (all present or all absent for migration compat)
ALTER TABLE workspace_invitations
  ADD CONSTRAINT chk_kek_fields CHECK (
    (encrypted_kek IS NULL AND kek_nonce IS NULL AND kek_version IS NULL)
    OR
    (encrypted_kek IS NOT NULL AND kek_nonce IS NOT NULL AND kek_version IS NOT NULL)
  );
