defmodule RefMDWeb.Channels.DocumentAccessTest do
  use RefMDWeb.ConnCase, async: true

  alias RefMD.Documents
  alias RefMD.Repo
  alias RefMD.Users.User
  alias RefMD.Workspaces
  alias RefMD.Workspaces.WorkspaceMember
  alias RefMDWeb.Channels.Document.Access

  defp create_user(email) do
    Repo.insert!(%User{
      id: Ecto.UUID.generate(),
      email: email,
      name: email
    })
  end

  defp create_document(workspace_id, created_by) do
    {:ok, document} =
      Documents.create_document(%{
        "id" => Ecto.UUID.generate(),
        "workspace_id" => workspace_id,
        "doc_type" => "document",
        "title" => "Untitled",
        "created_by" => created_by
      })

    document
  end

  defp add_viewer_member(workspace_id, user_id) do
    viewer_role =
      workspace_id
      |> Workspaces.list_workspace_roles()
      |> Enum.find(&(&1.base_role == "viewer"))

    Repo.insert!(%WorkspaceMember{
      workspace_id: workspace_id,
      user_id: user_id,
      role_id: viewer_role.id,
      is_default: false,
      joined_at: DateTime.utc_now()
    })
  end

  test "publication sync is allowed only for workspace members with document write permission" do
    owner = create_user("publication-sync-owner@example.com")
    viewer = create_user("publication-sync-viewer@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner.id, "Publication Sync")
    document = create_document(workspace.id, owner.id)
    add_viewer_member(workspace.id, viewer.id)

    assert Access.publication_sync_allowed?(document, owner.id, nil, nil)
    refute Access.publication_sync_allowed?(document, viewer.id, nil, nil)
  end

  test "publication sync is never allowed from share contexts" do
    owner = create_user("publication-sync-share-owner@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner.id, "Publication Sync Share")
    document = create_document(workspace.id, owner.id)

    share_socket = %Phoenix.Socket{assigns: %{session_kind: :share_participant}}

    refute Access.publication_sync_allowed?(document, owner.id, share_socket, nil)
    refute Access.publication_sync_allowed?(document, owner.id, nil, Ecto.UUID.generate())
  end
end
