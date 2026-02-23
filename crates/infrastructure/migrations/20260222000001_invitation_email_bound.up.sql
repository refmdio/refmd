-- Convert invitation model from max_uses/use_count to email-bound (is_used boolean)
-- Design decision: invited_email is required, 1 invitation = 1 person

-- 1. Drop constraints that reference max_uses/use_count
ALTER TABLE workspace_invitations DROP CONSTRAINT IF EXISTS chk_use_count_range;
ALTER TABLE workspace_invitations DROP CONSTRAINT IF EXISTS chk_max_uses;

-- 2. Add is_used column (default FALSE for existing rows)
ALTER TABLE workspace_invitations ADD COLUMN is_used BOOLEAN NOT NULL DEFAULT FALSE;

-- 3. Backfill is_used from use_count (any invitation with use_count >= 1 is "used")
UPDATE workspace_invitations SET is_used = TRUE WHERE use_count >= 1;

-- 4. Drop max_uses and use_count columns
ALTER TABLE workspace_invitations DROP COLUMN max_uses;
ALTER TABLE workspace_invitations DROP COLUMN use_count;

-- 5. Normalize existing invited_email to lowercase (match Email::new() behavior)
UPDATE workspace_invitations SET invited_email = LOWER(TRIM(invited_email)) WHERE invited_email IS NOT NULL;

-- 6. Revoke legacy invitations with NULL invited_email (they cannot work in email-bound model)
--    and backfill with placeholder so NOT NULL constraint can be applied
UPDATE workspace_invitations
SET invited_email = 'revoked@legacy.local',
    revoked_at = COALESCE(revoked_at, NOW())
WHERE invited_email IS NULL;

-- 7. Make invited_email NOT NULL
ALTER TABLE workspace_invitations ALTER COLUMN invited_email SET NOT NULL;
