defmodule RefMD.SharingConcurrencyTest do
  use RefMD.DataCase, async: false

  alias RefMD.Documents
  alias RefMD.Repo
  alias RefMD.Sharing
  alias RefMD.Sharing.Share
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

  defp create_document(workspace_id, created_by, parent_id) do
    {:ok, document} =
      Documents.create_document(%{
        "id" => Ecto.UUID.generate(),
        "workspace_id" => workspace_id,
        "doc_type" => "document",
        "parent_id" => parent_id,
        "title" => "Untitled",
        "encrypted_title" => <<1, 2, 3>>,
        "encrypted_title_nonce" => :crypto.strong_rand_bytes(24),
        "encrypted_title_key_version" => 1,
        "created_by" => created_by
      })

    document
  end

  defp create_folder(workspace_id, created_by, parent_id \\ nil) do
    {:ok, folder} =
      Documents.create_document(%{
        "id" => Ecto.UUID.generate(),
        "workspace_id" => workspace_id,
        "doc_type" => "folder",
        "parent_id" => parent_id,
        "title" => "Folder",
        "created_by" => created_by
      })

    folder
  end

  defp create_folder_share_attrs do
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    %{
      "id" => Ecto.UUID.generate(),
      "scope" => "folder",
      "share_slug" => share_slug,
      "token_prefix" => String.slice(share_slug, 0, 4),
      "permission" => "view",
      "password_protected" => false,
      "encrypted_dek" => :crypto.strong_rand_bytes(32),
      "nonce" => nil,
      "share_keys" => []
    }
  end

  defp folder_share_key_attrs(document) do
    %{
      "share_id" => Ecto.UUID.generate(),
      "document_id" => document.id,
      "encrypted_dek" => :crypto.strong_rand_bytes(32),
      "nonce" => nil
    }
  end

  test "concurrent folder share key additions create only one child share" do
    owner_id = create_user("share-concurrency@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Share Concurrency")
    folder = create_folder(workspace.id, owner_id)

    assert {:ok, created} =
             Sharing.create_share(folder, owner_id, create_folder_share_attrs())

    target_document = create_document(workspace.id, owner_id, folder.id)

    tasks =
      Enum.map(1..2, fn _idx ->
        Task.async(fn ->
          Sharing.update_share_keys(
            folder.id,
            created.share.id,
            created.share_manage_token,
            %{"add_keys" => [folder_share_key_attrs(target_document)]}
          )
        end)
      end)

    results = Task.await_many(tasks)

    assert Enum.count(results, &match?({:ok, _result}, &1)) == 1
    assert Enum.count(results, &match?({:error, {:invalid_value, :add_keys}}, &1)) == 1

    child_share_count =
      from(s in Share,
        where: s.parent_share_id == ^created.share.id and s.document_id == ^target_document.id
      )
      |> Repo.aggregate(:count)

    assert child_share_count == 1
  end
end
