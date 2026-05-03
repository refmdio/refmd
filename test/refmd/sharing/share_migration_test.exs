Code.require_file(
  "../../../priv/repo/migrations/20260423000400_add_unique_child_share_per_document.exs",
  __DIR__
)

defmodule RefMD.Sharing.ShareMigrationTest do
  use RefMD.DataCase, async: false

  alias Ecto.Adapters.SQL
  alias RefMD.Documents
  alias RefMD.Repo
  alias RefMD.Repo.Migrations.AddUniqueChildSharePerDocument
  alias RefMD.Sharing
  alias RefMD.Sharing.{Share, ShareExclusion}
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

  defp create_document(workspace_id, created_by, doc_type, parent_id \\ nil) do
    attrs = %{
      "id" => Ecto.UUID.generate(),
      "workspace_id" => workspace_id,
      "doc_type" => doc_type,
      "parent_id" => parent_id,
      "title" => if(doc_type == "folder", do: "Folder", else: "Untitled"),
      "created_by" => created_by
    }

    attrs =
      if doc_type == "document" do
        Map.merge(attrs, %{
          "encrypted_title" => <<1, 2, 3>>,
          "encrypted_title_nonce" => :crypto.strong_rand_bytes(24),
          "encrypted_title_key_version" => 1
        })
      else
        attrs
      end

    {:ok, document} = Documents.create_document(attrs)
    document
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

  defp create_document_share_attrs do
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    %{
      "id" => Ecto.UUID.generate(),
      "scope" => "document",
      "share_slug" => share_slug,
      "token_prefix" => String.slice(share_slug, 0, 4),
      "permission" => "view",
      "password_protected" => false,
      "encrypted_dek" => :crypto.strong_rand_bytes(32),
      "nonce" => nil
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

  defp insert_child_share!(root_share, document, owner_id, opts \\ []) do
    token_hash = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

    Repo.insert!(
      Share.changeset(%Share{}, %{
        id: Ecto.UUID.generate(),
        document_id: document.id,
        parent_share_id: root_share.id,
        scope: Keyword.get(opts, :scope, document.doc_type),
        token_hash: token_hash,
        token_prefix: String.slice(token_hash, 0, 4),
        slug_ciphertext: :crypto.strong_rand_bytes(32),
        slug_nonce: :crypto.strong_rand_bytes(12),
        slug_key_id: "test",
        permission: "view",
        password_protected: false,
        access_count: 0,
        created_by: owner_id
      })
    )
  end

  test "migration preflight rejects child shares outside the root folder tree" do
    owner_id = create_user("share-migration@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Share Migration")
    root_folder = create_document(workspace.id, owner_id, "folder")
    outside_folder = create_document(workspace.id, owner_id, "folder")
    outside_document = create_document(workspace.id, owner_id, "document", outside_folder.id)

    assert {:ok, created} =
             Sharing.create_share(root_folder, owner_id, create_folder_share_attrs())

    insert_child_share!(created.share, outside_folder, owner_id)
    insert_child_share!(created.share, outside_document, owner_id)

    assert_raise Postgrex.Error, ~r/outside-root/, fn ->
      SQL.query!(Repo, AddUniqueChildSharePerDocument.unreachable_child_share_check_sql())
    end
  end

  test "migration preflight rejects child shares missing an ancestor child share" do
    owner_id = create_user("share-migration-missing-ancestor@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Share Migration")
    root_folder = create_document(workspace.id, owner_id, "folder")

    assert {:ok, created} =
             Sharing.create_share(root_folder, owner_id, create_folder_share_attrs())

    child_folder = create_document(workspace.id, owner_id, "folder", root_folder.id)
    nested_document = create_document(workspace.id, owner_id, "document", child_folder.id)

    insert_child_share!(created.share, nested_document, owner_id)

    assert_raise Postgrex.Error, ~r/unreachable folder share children/, fn ->
      SQL.query!(Repo, AddUniqueChildSharePerDocument.unreachable_child_share_check_sql())
    end
  end

  test "migration preflight rejects child shares under non-folder parent shares" do
    owner_id = create_user("share-migration-invalid-parent@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Share Migration")
    root_document = create_document(workspace.id, owner_id, "document")
    child_document = create_document(workspace.id, owner_id, "document")

    assert {:ok, created} =
             Sharing.create_share(root_document, owner_id, create_document_share_attrs())

    insert_child_share!(created.share, child_document, owner_id)

    assert_raise Postgrex.Error, ~r/unreachable folder share children/, fn ->
      SQL.query!(Repo, AddUniqueChildSharePerDocument.unreachable_child_share_check_sql())
    end
  end

  test "migration preflight rejects duplicate child shares" do
    owner_id = create_user("share-migration-duplicates@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Share Migration")
    root_folder = create_document(workspace.id, owner_id, "folder")

    assert {:ok, created} =
             Sharing.create_share(root_folder, owner_id, create_folder_share_attrs())

    child_document = create_document(workspace.id, owner_id, "document", root_folder.id)

    SQL.query!(Repo, "DROP INDEX IF EXISTS shares_parent_share_document_id_index")
    insert_child_share!(created.share, child_document, owner_id)
    insert_child_share!(created.share, child_document, owner_id)

    assert_raise Postgrex.Error, ~r/duplicate child shares/, fn ->
      SQL.query!(Repo, AddUniqueChildSharePerDocument.duplicate_child_share_check_sql())
    end
  end

  test "migration preflight rejects child shares with mismatched scope" do
    owner_id = create_user("share-migration-invalid-scope@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Share Migration")
    root_folder = create_document(workspace.id, owner_id, "folder")

    assert {:ok, created} =
             Sharing.create_share(root_folder, owner_id, create_folder_share_attrs())

    child_folder = create_document(workspace.id, owner_id, "folder", root_folder.id)
    insert_child_share!(created.share, child_folder, owner_id, scope: "document")

    assert_raise Postgrex.Error, ~r/unreachable folder share children/, fn ->
      SQL.query!(Repo, AddUniqueChildSharePerDocument.unreachable_child_share_check_sql())
    end
  end

  test "migration preflight rejects child shares excluded after materialization" do
    owner_id = create_user("share-migration-excluded-child@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Share Migration")
    root_folder = create_document(workspace.id, owner_id, "folder")

    assert {:ok, created} =
             Sharing.create_share(root_folder, owner_id, create_folder_share_attrs())

    child_document = create_document(workspace.id, owner_id, "document", root_folder.id)

    assert {:ok, _result} =
             Sharing.update_share_keys(
               root_folder.id,
               created.share.id,
               created.share_manage_token,
               %{"add_keys" => [folder_share_key_attrs(child_document)]}
             )

    Repo.insert!(
      ShareExclusion.changeset(%ShareExclusion{}, %{
        share_id: created.share.id,
        document_id: child_document.id
      })
    )

    assert_raise Postgrex.Error, ~r/unreachable folder share children/, fn ->
      SQL.query!(Repo, AddUniqueChildSharePerDocument.unreachable_child_share_check_sql())
    end
  end

  test "migration preflight rejects child shares missing key material" do
    owner_id = create_user("share-migration-missing-material@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Share Migration")
    root_folder = create_document(workspace.id, owner_id, "folder")

    assert {:ok, created} =
             Sharing.create_share(root_folder, owner_id, create_folder_share_attrs())

    child_document = create_document(workspace.id, owner_id, "document", root_folder.id)
    insert_child_share!(created.share, child_document, owner_id)

    assert_raise Postgrex.Error, ~r/unreachable folder share children/, fn ->
      SQL.query!(Repo, AddUniqueChildSharePerDocument.unreachable_child_share_check_sql())
    end
  end
end
