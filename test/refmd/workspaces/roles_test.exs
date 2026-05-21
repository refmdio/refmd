defmodule RefMD.Workspaces.RolesTest do
  use RefMD.DataCase, async: true

  alias RefMD.Repo
  alias RefMD.Users.User
  alias RefMD.Workspaces

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
  end
end
