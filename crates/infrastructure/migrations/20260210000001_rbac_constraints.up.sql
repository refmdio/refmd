-- RBAC constraints for workspace roles and members

-- workspace_roles: is_default partial unique index (at most one default per workspace)
CREATE UNIQUE INDEX idx_workspace_roles_default
  ON workspace_roles(workspace_id) WHERE is_default = true;

-- workspace_roles: compound unique for cross-workspace role assignment prevention
ALTER TABLE workspace_roles
  ADD CONSTRAINT uq_workspace_roles_workspace_id_id UNIQUE (workspace_id, id);

-- workspace_members: compound FK to prevent cross-workspace role assignment
ALTER TABLE workspace_members
  ADD CONSTRAINT fk_workspace_members_workspace_role
  FOREIGN KEY (workspace_id, role_id)
  REFERENCES workspace_roles(workspace_id, id);
