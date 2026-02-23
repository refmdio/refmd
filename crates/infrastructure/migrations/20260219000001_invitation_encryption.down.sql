-- Revert invitation encryption changes

ALTER TABLE workspace_invitations DROP CONSTRAINT IF EXISTS chk_kek_fields;
ALTER TABLE workspace_invitations DROP CONSTRAINT IF EXISTS chk_max_uses;

ALTER TABLE workspace_invitations DROP CONSTRAINT IF EXISTS workspace_invitations_role_fkey;
-- Clean up rows with NULL role_id (from FK SET NULL cascade) before restoring NOT NULL constraint
DELETE FROM workspace_invitations WHERE role_id IS NULL;
ALTER TABLE workspace_invitations ALTER COLUMN role_id SET NOT NULL;
ALTER TABLE workspace_invitations
  ADD CONSTRAINT workspace_invitations_role_id_fkey
  FOREIGN KEY (role_id) REFERENCES workspace_roles(id) ON DELETE CASCADE;

ALTER TABLE workspace_invitations
  DROP COLUMN IF EXISTS revoked_at,
  DROP COLUMN IF EXISTS kek_version,
  DROP COLUMN IF EXISTS kek_nonce,
  DROP COLUMN IF EXISTS encrypted_kek;
