defmodule RefMD.Workspaces.RolesTest do
  use RefMD.DataCase, async: true

  alias RefMD.Repo
  alias RefMD.Users.User
  alias RefMD.Workspaces
  alias RefMD.Workspaces.WorkspaceInvitation

  defp workspace_fixture do
    user_id = Ecto.UUID.generate()
    uniq = System.unique_integer([:positive])

    Repo.insert!(%User{
      id: user_id,
      email: "roles-#{uniq}@example.com",
      name: "roles-#{uniq}"
    })

    {:ok, workspace} = Workspaces.create_default_workspace(user_id, "Roles #{uniq}")
    workspace
  end

  describe "create_custom_role/4 permission validation" do
    test "rejects unknown permissions" do
      workspace = workspace_fixture()

      assert {:error, {:invalid_permission, "unknown:permission"}} =
               Workspaces.create_custom_role(workspace.id, "Bad", "editor", [
                 %{"permission" => "unknown:permission", "granted" => true}
               ])
    end

    test "rejects permissions above the base role ceiling" do
      workspace = workspace_fixture()

      assert {:error, {:permission_exceeds_base_role, "document:write"}} =
               Workspaces.create_custom_role(workspace.id, "Bad", "viewer", [
                 %{"permission" => "document:write", "granted" => true}
               ])
    end

    test "rejects permission dependency violations" do
      workspace = workspace_fixture()

      assert {:error, {:invalid_permission_dependency, "document:write"}} =
               Workspaces.create_custom_role(workspace.id, "Bad", "editor", [
                 %{"permission" => "document:read", "granted" => false}
               ])
    end

    test "rejects effective permissions above the actor role ceiling" do
      workspace = workspace_fixture()

      {:ok, actor_role} =
        Workspaces.create_custom_role(workspace.id, "Limited admin", "admin", [
          %{"permission" => "member:remove", "granted" => false}
        ])

      assert {:error, {:permission_exceeds_actor, "member:remove"}} =
               Workspaces.create_custom_role(workspace.id, "Escalating admin", "admin", [],
                 actor_role: actor_role
               )
    end
  end

  describe "update_role/3 permission validation" do
    test "rejects invalid permissions through the context boundary" do
      workspace = workspace_fixture()
      {:ok, role} = Workspaces.create_custom_role(workspace.id, "Custom editor", "editor", [])

      assert {:error, {:permission_exceeds_base_role, "member:invite"}} =
               Workspaces.update_role(role, %{},
                 permissions: [%{"permission" => "member:invite", "granted" => true}]
               )
    end

    test "rejects updates that would restore permissions above the actor role ceiling" do
      workspace = workspace_fixture()

      {:ok, actor_role} =
        Workspaces.create_custom_role(workspace.id, "Limited admin", "admin", [
          %{"permission" => "member:remove", "granted" => false}
        ])

      {:ok, target_role} =
        Workspaces.create_custom_role(workspace.id, "Restricted admin", "admin", [
          %{"permission" => "member:remove", "granted" => false}
        ])

      assert {:error, {:permission_exceeds_actor, "member:remove"}} =
               Workspaces.update_role(target_role, %{},
                 permissions: [],
                 actor_role: actor_role
               )
    end

    test "replaces submitted permission overrides so overrides can be cleared" do
      workspace = workspace_fixture()

      {:ok, role} =
        Workspaces.create_custom_role(workspace.id, "Clearable admin", "admin", [
          %{"permission" => "member:invite", "granted" => false},
          %{"permission" => "member:remove", "granted" => false}
        ])

      {:ok, updated} = Workspaces.update_role(role, %{}, permissions: [])

      assert updated.permissions == []
      assert Workspaces.permission_granted?(updated, "member:invite")
      assert Workspaces.permission_granted?(updated, "member:remove")
    end

    test "replaces previous overrides with the submitted override set" do
      workspace = workspace_fixture()

      {:ok, role} =
        Workspaces.create_custom_role(workspace.id, "Replaceable admin", "admin", [
          %{"permission" => "member:invite", "granted" => false},
          %{"permission" => "member:remove", "granted" => false}
        ])

      {:ok, updated} =
        Workspaces.update_role(role, %{},
          permissions: [%{"permission" => "member:invite", "granted" => false}]
        )

      assert Enum.map(updated.permissions, & &1.permission) == ["member:invite"]
      refute Workspaces.permission_granted?(updated, "member:invite")
      assert Workspaces.permission_granted?(updated, "member:remove")
    end
  end

  describe "delete_role/1" do
    test "returns the active invitation count invalidated by role deletion" do
      workspace = workspace_fixture()
      owner = Repo.get!(User, workspace.owner_id)

      {:ok, role} = Workspaces.create_custom_role(workspace.id, "Invite target", "viewer", [])

      active_invitation =
        insert_workspace_invitation!(
          workspace.id,
          owner,
          role.id,
          DateTime.add(DateTime.utc_now(), 3600, :second),
          is_used: false
        )

      insert_workspace_invitation!(
        workspace.id,
        owner,
        role.id,
        DateTime.add(DateTime.utc_now(), 3600, :second),
        is_used: true
      )

      assert {:ok, 1} = Workspaces.delete_role(role)
      assert Repo.get!(WorkspaceInvitation, active_invitation.id).role_id == nil
    end
  end

  defp insert_workspace_invitation!(workspace_id, user, role_id, expires_at, opts) do
    token_hash = hash_value()

    Repo.insert!(%WorkspaceInvitation{
      id: Ecto.UUID.generate(),
      workspace_id: workspace_id,
      token_hash: token_hash,
      token_prefix: String.slice(token_hash, 0, 4),
      role_id: role_id,
      invited_by: user.id,
      invited_email: "role-invitee-#{System.unique_integer([:positive])}@example.com",
      kek_version: 1,
      bootstrap_key_commitment: hash_value(),
      encrypted_bootstrap_package: %{"version" => 1},
      bootstrap_package_hash: hash_value(),
      bootstrap_package_key_recipient_wrap: %{"version" => 1},
      bootstrap_package_key_maintenance_wrap: %{"version" => 1},
      bootstrap_suite_id: "test-suite",
      capability_context_hash: hash_value(),
      is_used: Keyword.fetch!(opts, :is_used),
      expires_at: expires_at,
      created_at: DateTime.add(expires_at, -3600, :second)
    })
  end

  defp hash_value do
    32
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end
end
