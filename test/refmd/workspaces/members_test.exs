defmodule RefMD.Workspaces.MembersTest do
  use RefMD.DataCase, async: true

  alias RefMD.Repo
  alias RefMD.Users.User
  alias RefMD.Workspaces
  alias RefMD.Workspaces.WorkspaceMember

  test "remove_member marks KEK rotation before returning success" do
    {workspace, owner} = workspace_fixture()
    target = user_fixture()
    editor_role = role_by_base!(workspace.id, "editor")

    insert_test_workspace_key_directory!(
      workspace.id,
      owner.id,
      role_by_base!(workspace.id, "owner").id
    )

    Repo.insert!(%WorkspaceMember{
      workspace_id: workspace.id,
      user_id: target.id,
      role_id: editor_role.id,
      joined_at: DateTime.utc_now()
    })

    signer = Process.get({:test_workspace_signer_material, workspace.id})

    append =
      workspace_member_removal_key_directory_append(
        workspace.id,
        target.id,
        owner.id,
        signer.device_id,
        signer.signing_private
      )

    key_directory = %{
      workspace_events: append["workspace_key_directory_events"],
      workspace_checkpoint: append["workspace_key_directory_checkpoint"]
    }

    assert {:ok, %WorkspaceMember{user_id: target_user_id}} =
             Workspaces.remove_member(workspace.id, target.id, owner.id, key_directory)

    assert target_user_id == target.id
    refute Repo.get_by(WorkspaceMember, workspace_id: workspace.id, user_id: target.id)

    reloaded_workspace = Workspaces.get_workspace(workspace.id)
    assert reloaded_workspace.needs_kek_rotation
    assert reloaded_workspace.kek_rotation_initiator_user_id == owner.id
  end

  defp workspace_fixture do
    owner = user_fixture()
    {:ok, workspace} = Workspaces.create_default_workspace(owner.id, "Member removal")
    {workspace, owner}
  end

  defp user_fixture do
    uniq = System.unique_integer([:positive])

    Repo.insert!(%User{
      id: Ecto.UUID.generate(),
      email: "member-removal-#{uniq}@example.com",
      name: "Member Removal #{uniq}"
    })
  end

  defp role_by_base!(workspace_id, base_role) do
    Workspaces.list_workspace_roles(workspace_id)
    |> Enum.find(&(&1.base_role == base_role))
  end
end
