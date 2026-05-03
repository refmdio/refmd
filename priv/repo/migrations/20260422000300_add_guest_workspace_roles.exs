defmodule RefMD.Repo.Migrations.AddGuestWorkspaceRoles do
  use Ecto.Migration

  def up do
    execute("""
    INSERT INTO workspace_roles (id, workspace_id, name, base_role, is_default, catalog_version, created_at)
    SELECT gen_random_uuid(), w.id, 'Guest', 'guest', false, NULL, NOW()
    FROM workspaces w
    WHERE NOT EXISTS (
      SELECT 1
      FROM workspace_roles wr
      WHERE wr.workspace_id = w.id
        AND wr.base_role = 'guest'
        AND wr.catalog_version IS NULL
    )
    """)

    execute("""
    UPDATE workspace_members wm
    SET role_id = wr.id
    FROM workspace_guest_grants g
    JOIN users u
      ON u.id = g.user_id
    JOIN workspace_roles wr
      ON wr.workspace_id = g.workspace_id
     AND wr.base_role = 'guest'
     AND wr.catalog_version IS NULL
    WHERE wm.workspace_id = g.workspace_id
      AND wm.user_id = g.user_id
      AND u.account_type = 'guest'
      AND wm.role_id <> wr.id
    """)
  end

  def down do
    :ok
  end
end
