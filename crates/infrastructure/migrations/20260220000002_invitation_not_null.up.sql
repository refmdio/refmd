-- Set defaults for any legacy NULL rows (shouldn't exist for Phase 3 invitations, but defensive)
UPDATE workspace_invitations SET max_uses = 50 WHERE max_uses IS NULL;
UPDATE workspace_invitations SET expires_at = created_at + INTERVAL '7 days' WHERE expires_at IS NULL;

-- Add NOT NULL constraints
ALTER TABLE workspace_invitations ALTER COLUMN max_uses SET NOT NULL;
ALTER TABLE workspace_invitations ALTER COLUMN expires_at SET NOT NULL;
