defmodule RefMD.Documents.TitleEncryptionTest do
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

  defp create_document(workspace_id, user_id) do
    {:ok, document} =
      Documents.create_document(%{
        "workspace_id" => workspace_id,
        "created_by" => user_id,
        "doc_type" => "document",
        "encrypted_title" => <<1, 2, 3>>,
        "encrypted_title_nonce" => :crypto.strong_rand_bytes(24),
        "encrypted_title_key_version" => 1
      })

    document
  end

  setup do
    user_id = create_user("documents-title-encryption@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(user_id, "Title Encryption")
    %{document: create_document(workspace.id, user_id), user_id: user_id, workspace: workspace}
  end

  test "rejects partial encrypted title metadata updates", %{document: document} do
    assert {:error, changeset} =
             Documents.update_document(document, %{
               "encrypted_title_nonce" => :crypto.strong_rand_bytes(24)
             })

    assert {"must be provided with encrypted title metadata updates", _} =
             changeset.errors[:encrypted_title]

    assert {"must be provided with encrypted title metadata updates", _} =
             changeset.errors[:encrypted_title_key_version]
  end

  test "accepts complete encrypted title metadata updates", %{document: document} do
    encrypted_title = <<4, 5, 6>>
    encrypted_title_nonce = :crypto.strong_rand_bytes(24)

    assert {:ok, updated} =
             Documents.update_document(document, %{
               "encrypted_title" => encrypted_title,
               "encrypted_title_nonce" => encrypted_title_nonce,
               "encrypted_title_key_version" => 1
             })

    assert updated.encrypted_title == encrypted_title
    assert updated.encrypted_title_nonce == encrypted_title_nonce
    assert updated.encrypted_title_key_version == 1
  end

  test "rejects malformed encrypted title metadata updates", %{document: document} do
    assert {:error, changeset} =
             Documents.update_document(document, %{
               "encrypted_title" => <<>>,
               "encrypted_title_nonce" => :crypto.strong_rand_bytes(24),
               "encrypted_title_key_version" => 1
             })

    assert {"can't be blank", _} = changeset.errors[:encrypted_title]

    assert {:error, changeset} =
             Documents.update_document(document, %{
               "encrypted_title" => <<4, 5, 6>>,
               "encrypted_title_nonce" => :crypto.strong_rand_bytes(12),
               "encrypted_title_key_version" => 1
             })

    assert {"must be 24 bytes", _} = changeset.errors[:encrypted_title_nonce]

    assert {:error, changeset} =
             Documents.update_document(document, %{
               "encrypted_title" => <<4, 5, 6>>,
               "encrypted_title_nonce" => :crypto.strong_rand_bytes(24),
               "encrypted_title_key_version" => 0
             })

    assert {_message, metadata} = changeset.errors[:encrypted_title_key_version]
    assert metadata[:validation] == :number
    assert metadata[:kind] == :greater_than
    assert metadata[:number] == 0
  end

  test "rejects malformed encrypted title metadata on create", %{
    user_id: user_id,
    workspace: workspace
  } do
    assert {:error, changeset} =
             Documents.create_document(%{
               "workspace_id" => workspace.id,
               "created_by" => user_id,
               "doc_type" => "document",
               "encrypted_title" => <<>>,
               "encrypted_title_nonce" => :crypto.strong_rand_bytes(12),
               "encrypted_title_key_version" => 0
             })

    assert {"can't be blank", _} = changeset.errors[:encrypted_title]

    assert {"must be 24 bytes", _} = changeset.errors[:encrypted_title_nonce]
    assert {_message, metadata} = changeset.errors[:encrypted_title_key_version]
    assert metadata[:validation] == :number
    assert metadata[:kind] == :greater_than
    assert metadata[:number] == 0
  end
end
