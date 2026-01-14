-- Add E2EE KEK fields to workspace_invitations
-- These fields store the workspace KEK encrypted with a key derived from the invitation token

ALTER TABLE workspace_invitations
    ADD COLUMN IF NOT EXISTS encrypted_kek_for_invite TEXT,
    ADD COLUMN IF NOT EXISTS kek_version INT;

COMMENT ON COLUMN workspace_invitations.encrypted_kek_for_invite IS 'Workspace KEK encrypted with a key derived from the invitation token (Base64)';
COMMENT ON COLUMN workspace_invitations.kek_version IS 'Version of the KEK at the time of invitation';
