ALTER TABLE workspace_invitations ALTER COLUMN max_uses DROP NOT NULL;
ALTER TABLE workspace_invitations ALTER COLUMN expires_at DROP NOT NULL;
