-- Revert RBAC constraints
ALTER TABLE workspace_members DROP CONSTRAINT IF EXISTS fk_workspace_members_workspace_role;
ALTER TABLE workspace_roles DROP CONSTRAINT IF EXISTS uq_workspace_roles_workspace_id_id;
DROP INDEX IF EXISTS idx_workspace_roles_default;
