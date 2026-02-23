-- Revert email-bound model back to max_uses/use_count

-- 1. Make invited_email nullable again
ALTER TABLE workspace_invitations ALTER COLUMN invited_email DROP NOT NULL;

-- 2. Add back max_uses and use_count columns
ALTER TABLE workspace_invitations ADD COLUMN max_uses INT NOT NULL DEFAULT 50;
ALTER TABLE workspace_invitations ADD COLUMN use_count INT NOT NULL DEFAULT 0;

-- 3. Backfill use_count from is_used
UPDATE workspace_invitations SET use_count = 1 WHERE is_used = TRUE;

-- 4. Drop is_used column
ALTER TABLE workspace_invitations DROP COLUMN is_used;

-- 5. Restore constraints
ALTER TABLE workspace_invitations
  ADD CONSTRAINT chk_max_uses CHECK (max_uses >= 1 AND max_uses <= 1000);
ALTER TABLE workspace_invitations
  ADD CONSTRAINT chk_use_count_range CHECK (use_count >= 0 AND use_count <= max_uses);
