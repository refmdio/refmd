-- Drop workspace domain tables

-- Remove FK constraint from workspace_encrypted_keys
ALTER TABLE workspace_encrypted_keys
    DROP CONSTRAINT IF EXISTS fk_workspace_encrypted_keys_workspace;

DROP TABLE IF EXISTS workspace_invitations;
DROP TABLE IF EXISTS workspace_members;
DROP TABLE IF EXISTS workspace_role_permissions;
DROP TABLE IF EXISTS workspace_roles;
DROP TABLE IF EXISTS workspaces;
