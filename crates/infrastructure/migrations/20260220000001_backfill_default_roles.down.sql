-- This migration is not reversible: removing backfilled roles would break
-- workspaces that depend on them (member assignments, invitations, default role).
-- Down migration is intentionally a no-op.
SELECT 1;
