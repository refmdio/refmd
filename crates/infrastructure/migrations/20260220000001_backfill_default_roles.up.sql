-- Backfill Admin role for workspaces that don't have one
INSERT INTO workspace_roles (id, workspace_id, name, base_role, is_default, created_at)
SELECT gen_random_uuid(), w.id, 'Admin', 'admin', false, NOW()
FROM workspaces w
WHERE NOT EXISTS (
    SELECT 1 FROM workspace_roles r WHERE r.workspace_id = w.id AND r.base_role = 'admin'
);

-- Backfill Editor role
INSERT INTO workspace_roles (id, workspace_id, name, base_role, is_default, created_at)
SELECT gen_random_uuid(), w.id, 'Editor', 'editor', false, NOW()
FROM workspaces w
WHERE NOT EXISTS (
    SELECT 1 FROM workspace_roles r WHERE r.workspace_id = w.id AND r.base_role = 'editor'
);

-- Backfill Viewer role
INSERT INTO workspace_roles (id, workspace_id, name, base_role, is_default, created_at)
SELECT gen_random_uuid(), w.id, 'Viewer', 'viewer', false, NOW()
FROM workspaces w
WHERE NOT EXISTS (
    SELECT 1 FROM workspace_roles r WHERE r.workspace_id = w.id AND r.base_role = 'viewer'
);

-- Set editor as default for workspaces that don't have any default role
UPDATE workspace_roles
SET is_default = true
WHERE base_role = 'editor'
  AND workspace_id IN (
    SELECT w.id FROM workspaces w
    WHERE NOT EXISTS (
      SELECT 1 FROM workspace_roles r WHERE r.workspace_id = w.id AND r.is_default = true
    )
  )
  AND id = (
    SELECT r2.id FROM workspace_roles r2
    WHERE r2.workspace_id = workspace_roles.workspace_id
      AND r2.base_role = 'editor'
    LIMIT 1
  );
