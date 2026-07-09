defmodule RefMD.Documents.ReorderingTest do
  use RefMD.DataCase, async: true

  alias RefMD.Documents
  alias RefMD.Repo
  alias RefMD.Users.User
  alias RefMD.Workspaces

  defp create_user(email) do
    user_id = Ecto.UUID.generate()

    Repo.insert!(%User{
      id: user_id,
      email: email,
      name: email
    })

    user_id
  end

  defp create_document(workspace_id, user_id, doc_type, parent_id \\ nil) do
    {:ok, document} =
      Documents.create_document(%{
        "id" => Ecto.UUID.generate(),
        "workspace_id" => workspace_id,
        "doc_type" => doc_type,
        "parent_id" => parent_id,
        "title" => if(doc_type == "folder", do: "Folder", else: "Document"),
        "encrypted_title" => <<1, 2, 3>>,
        "encrypted_title_nonce" => :crypto.strong_rand_bytes(24),
        "encrypted_title_key_version" => 1,
        "created_by" => user_id
      })

    document
  end

  defp setup_workspace(email) do
    user_id = create_user(email)
    {:ok, workspace} = Workspaces.create_default_workspace(user_id, "Reordering Workspace")
    %{user_id: user_id, workspace: workspace}
  end

  test "reorder persists folder-to-folder moves and sibling positions" do
    %{user_id: user_id, workspace: workspace} =
      setup_workspace("document-reorder-folder-move@example.com")

    parent = create_document(workspace.id, user_id, "folder")
    child_document = create_document(workspace.id, user_id, "document", parent.id)
    moving_folder = create_document(workspace.id, user_id, "folder")

    assert {:ok, moved_folder} =
             Documents.reorder_document(workspace.id, moving_folder.id, parent.id, 0)

    assert moved_folder.parent_id == parent.id
    assert Repo.reload!(moving_folder).position == 0
    assert Repo.reload!(child_document).position == 1

    assert {:ok, moved_document} =
             Documents.reorder_document(workspace.id, child_document.id, parent.id, 0)

    assert moved_document.parent_id == parent.id
    assert Repo.reload!(child_document).position == 0
    assert Repo.reload!(moving_folder).position == 1
  end

  test "reorder rejects circular folder moves without changing hierarchy" do
    %{user_id: user_id, workspace: workspace} =
      setup_workspace("document-reorder-circular@example.com")

    parent = create_document(workspace.id, user_id, "folder")
    child = create_document(workspace.id, user_id, "folder", parent.id)

    assert {:error, :circular_reference} =
             Documents.reorder_document(workspace.id, parent.id, child.id, 0)

    assert Repo.reload!(parent).parent_id == nil
    assert Repo.reload!(child).parent_id == parent.id
  end
end
