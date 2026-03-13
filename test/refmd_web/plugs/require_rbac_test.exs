defmodule RefMDWeb.Plugs.RequireRBACTest do
  use RefMD.DataCase, async: true

  import Plug.Conn
  alias RefMD.Repo
  alias RefMD.Workspaces
  alias RefMD.Workspaces.{WorkspaceRole, WorkspaceRolePermission}
  alias RefMDWeb.Plugs.RequireRBAC

  defp create_user(email) do
    id = Ecto.UUID.generate()

    Repo.insert!(%RefMD.Users.User{
      id: id,
      email: email,
      name: email
    })

    id
  end

  setup do
    user_id = create_user("test@example.com")

    {:ok, workspace} = Workspaces.create_default_workspace(user_id, "Test Workspace")
    {member, role} = Workspaces.get_member_with_role(workspace.id, user_id)

    %{
      user_id: user_id,
      workspace: workspace,
      member: member,
      role: role
    }
  end

  defp build_conn(workspace_id, user_id) do
    Plug.Test.conn("GET", "/api/workspaces/#{workspace_id}/members")
    |> Map.put(:path_params, %{"workspace_id" => workspace_id})
    |> assign(:current_user_id, user_id)
  end

  describe "init/1" do
    test "accepts valid permission with default not_member_status" do
      assert %{permission: "document:read", not_member_status: :forbidden} =
               RequireRBAC.init(permission: "document:read")
    end

    test "accepts :membership" do
      assert %{permission: :membership, not_member_status: :forbidden} =
               RequireRBAC.init(permission: :membership)
    end

    test "accepts not_member_status: :not_found" do
      assert %{permission: "member:invite", not_member_status: :not_found} =
               RequireRBAC.init(permission: "member:invite", not_member_status: :not_found)
    end

    test "raises on unknown permission" do
      assert_raise ArgumentError, ~r/Unknown permission/, fn ->
        RequireRBAC.init(permission: "invalid:perm")
      end
    end

    test "raises on invalid not_member_status" do
      assert_raise ArgumentError, ~r/not_member_status/, fn ->
        RequireRBAC.init(permission: "document:read", not_member_status: :bad)
      end
    end
  end

  describe "call/2 - membership check" do
    test "allows member", %{workspace: ws, user_id: uid} do
      conn =
        build_conn(ws.id, uid)
        |> RequireRBAC.call(%{permission: :membership, not_member_status: :forbidden})

      refute conn.halted
      assert conn.assigns[:workspace_id] == ws.id
      assert conn.assigns[:workspace_member] != nil
      assert conn.assigns[:workspace_role] != nil
    end

    test "denies non-member with 403 by default", %{workspace: ws} do
      other_user_id = create_user("other@example.com")

      conn =
        build_conn(ws.id, other_user_id)
        |> RequireRBAC.call(%{permission: :membership, not_member_status: :forbidden})

      assert conn.halted
      assert conn.status == 403
    end

    test "denies non-member with 404 when not_member_status is :not_found", %{workspace: ws} do
      other_user_id = create_user("other-404@example.com")

      conn =
        build_conn(ws.id, other_user_id)
        |> RequireRBAC.call(%{permission: :membership, not_member_status: :not_found})

      assert conn.halted
      assert conn.status == 404
    end
  end

  describe "call/2 - owner permissions" do
    test "owner has all permissions", %{workspace: ws, user_id: uid} do
      permissions = ~w(
        document:read document:write document:delete document:archive
        workspace:update workspace:admin workspace:delete
        member:list member:invite member:change_role member:remove
        role:manage
      )

      for perm <- permissions do
        conn =
          build_conn(ws.id, uid)
          |> RequireRBAC.call(%{permission: perm, not_member_status: :forbidden})

        refute conn.halted, "Owner should have #{perm}"
      end
    end
  end

  describe "call/2 - base role ceiling" do
    setup %{workspace: ws} do
      viewer_id = create_user("viewer@example.com")

      viewer_role =
        Repo.one!(
          from(r in WorkspaceRole,
            where: r.workspace_id == ^ws.id and r.base_role == "viewer"
          )
        )

      Repo.insert!(%RefMD.Workspaces.WorkspaceMember{
        workspace_id: ws.id,
        user_id: viewer_id,
        role_id: viewer_role.id,
        joined_at: DateTime.utc_now()
      })

      %{viewer_id: viewer_id}
    end

    test "viewer can read documents", %{workspace: ws, viewer_id: vid} do
      conn =
        build_conn(ws.id, vid)
        |> RequireRBAC.call(%{permission: "document:read", not_member_status: :forbidden})

      refute conn.halted
    end

    test "viewer can list members", %{workspace: ws, viewer_id: vid} do
      conn =
        build_conn(ws.id, vid)
        |> RequireRBAC.call(%{permission: "member:list", not_member_status: :forbidden})

      refute conn.halted
    end

    test "viewer cannot write documents", %{workspace: ws, viewer_id: vid} do
      conn =
        build_conn(ws.id, vid)
        |> RequireRBAC.call(%{permission: "document:write", not_member_status: :forbidden})

      assert conn.halted
      assert conn.status == 403
    end

    test "viewer cannot manage roles", %{workspace: ws, viewer_id: vid} do
      conn =
        build_conn(ws.id, vid)
        |> RequireRBAC.call(%{permission: "role:manage", not_member_status: :forbidden})

      assert conn.halted
      assert conn.status == 403
    end
  end

  describe "call/2 - editor permissions" do
    setup %{workspace: ws} do
      editor_id = create_user("editor@example.com")

      editor_role =
        Repo.one!(
          from(r in WorkspaceRole,
            where: r.workspace_id == ^ws.id and r.base_role == "editor"
          )
        )

      Repo.insert!(%RefMD.Workspaces.WorkspaceMember{
        workspace_id: ws.id,
        user_id: editor_id,
        role_id: editor_role.id,
        joined_at: DateTime.utc_now()
      })

      %{editor_id: editor_id}
    end

    test "editor can read and write documents", %{workspace: ws, editor_id: eid} do
      for perm <- ~w(document:read document:write document:archive member:list) do
        conn =
          build_conn(ws.id, eid)
          |> RequireRBAC.call(%{permission: perm, not_member_status: :forbidden})

        refute conn.halted, "Editor should have #{perm}"
      end
    end

    test "editor cannot delete documents", %{workspace: ws, editor_id: eid} do
      conn =
        build_conn(ws.id, eid)
        |> RequireRBAC.call(%{permission: "document:delete", not_member_status: :forbidden})

      assert conn.halted
    end

    test "editor cannot manage members", %{workspace: ws, editor_id: eid} do
      for perm <- ~w(member:invite member:change_role member:remove) do
        conn =
          build_conn(ws.id, eid)
          |> RequireRBAC.call(%{permission: perm, not_member_status: :forbidden})

        assert conn.halted, "Editor should not have #{perm}"
      end
    end
  end

  describe "call/2 - custom role with DB overrides" do
    setup %{workspace: ws} do
      custom_user_id = create_user("custom@example.com")

      custom_role =
        Repo.insert!(%WorkspaceRole{
          workspace_id: ws.id,
          name: "Custom Editor",
          base_role: "editor",
          is_default: false,
          catalog_version: 1,
          created_at: DateTime.utc_now()
        })

      # Override: deny document:write
      Repo.insert!(%WorkspaceRolePermission{
        role_id: custom_role.id,
        permission: "document:write",
        granted: false
      })

      Repo.insert!(%RefMD.Workspaces.WorkspaceMember{
        workspace_id: ws.id,
        user_id: custom_user_id,
        role_id: custom_role.id,
        joined_at: DateTime.utc_now()
      })

      %{custom_user_id: custom_user_id, custom_role: custom_role}
    end

    test "custom role respects override deny", %{workspace: ws, custom_user_id: cuid} do
      conn =
        build_conn(ws.id, cuid)
        |> RequireRBAC.call(%{permission: "document:write", not_member_status: :forbidden})

      assert conn.halted
      assert conn.status == 403
    end

    test "custom role inherits unoverridden permissions", %{workspace: ws, custom_user_id: cuid} do
      conn =
        build_conn(ws.id, cuid)
        |> RequireRBAC.call(%{permission: "document:read", not_member_status: :forbidden})

      refute conn.halted
    end
  end

  describe "call/2 - catalog_version new permission handling" do
    setup %{workspace: ws} do
      new_perm_user_id = create_user("newperm@example.com")

      # Custom role with catalog_version 0 (older than all current permissions at since_version 1)
      old_custom_role =
        Repo.insert!(%WorkspaceRole{
          workspace_id: ws.id,
          name: "Old Custom",
          base_role: "admin",
          is_default: false,
          catalog_version: 0,
          created_at: DateTime.utc_now()
        })

      Repo.insert!(%RefMD.Workspaces.WorkspaceMember{
        workspace_id: ws.id,
        user_id: new_perm_user_id,
        role_id: old_custom_role.id,
        joined_at: DateTime.utc_now()
      })

      %{new_perm_user_id: new_perm_user_id}
    end

    test "custom role with old catalog_version denies new permissions by default",
         %{workspace: ws, new_perm_user_id: uid} do
      # All permissions have since_version=1, catalog_version=0
      # So all permissions should be denied by default
      conn =
        build_conn(ws.id, uid)
        |> RequireRBAC.call(%{permission: "document:read", not_member_status: :forbidden})

      assert conn.halted
      assert conn.status == 403
    end
  end

  describe "effective_permissions/1" do
    test "returns all permissions for owner role" do
      role = %WorkspaceRole{base_role: "owner", permissions: []}
      perms = RequireRBAC.effective_permissions(role)

      assert MapSet.size(perms) == 12
      assert MapSet.member?(perms, "workspace:delete")
    end

    test "returns correct defaults for viewer" do
      role = %WorkspaceRole{base_role: "viewer", catalog_version: nil, permissions: []}
      perms = RequireRBAC.effective_permissions(role)

      assert perms == MapSet.new(~w(document:read member:list))
    end

    test "applies overrides for custom role" do
      role = %WorkspaceRole{
        base_role: "editor",
        catalog_version: 1,
        permissions: [
          %WorkspaceRolePermission{permission: "document:write", granted: false}
        ]
      }

      perms = RequireRBAC.effective_permissions(role)

      assert MapSet.member?(perms, "document:read")
      refute MapSet.member?(perms, "document:write")
    end
  end
end
