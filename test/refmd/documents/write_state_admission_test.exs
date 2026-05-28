defmodule RefMD.Documents.WriteStateAdmissionTest do
  use RefMD.DataCase, async: true

  alias RefMD.Documents
  alias RefMD.Documents.Document
  alias RefMD.Encryption.KeyDirectory.Event
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

  defp create_document(workspace_id, user_id, doc_type \\ "document", parent_id \\ nil) do
    {:ok, document} =
      Documents.create_document(%{
        "id" => Ecto.UUID.generate(),
        "workspace_id" => workspace_id,
        "doc_type" => doc_type,
        "parent_id" => parent_id,
        "title" => "Doc",
        "encrypted_title" => <<1, 2, 3>>,
        "encrypted_title_nonce" => :crypto.strong_rand_bytes(24),
        "encrypted_title_key_version" => 1,
        "created_by" => user_id
      })

    document
  end

  defp setup_workspace(email) do
    user_id = create_user(email)
    {:ok, workspace} = Workspaces.create_default_workspace(user_id, "Write State Workspace")
    {_member, role} = Workspaces.get_member_with_role(workspace.id, user_id)
    insert_test_workspace_key_directory!(workspace.id, user_id, role.id)
    signer = Process.get({:test_workspace_signer_material, workspace.id})

    %{user_id: user_id, workspace: workspace, signer: signer}
  end

  test "archive requires signed write-state events for every affected document" do
    %{user_id: user_id, workspace: workspace, signer: signer} =
      setup_workspace("write-state-archive@example.com")

    folder = create_document(workspace.id, user_id, "folder")
    child = create_document(workspace.id, user_id, "document", folder.id)

    append =
      document_write_state_key_directory_append(
        workspace.id,
        user_id,
        signer.device_id,
        signer.signing_private,
        [
          %{document_id: folder.id, previous_write_state: "writable", write_state: "archived"},
          %{document_id: child.id, previous_write_state: "writable", write_state: "archived"}
        ],
        "archive"
      )

    {:ok, admission} = Documents.WriteStateAdmission.parse_append(append)
    assert {:ok, archived} = Documents.archive_document(folder, admission)
    assert archived.archived_at
    assert Documents.get_document(child.id).archived_at

    assert 2 =
             Repo.aggregate(
               from(e in Event,
                 where:
                   e.scope_id == ^workspace.id and
                     e.event_type == "document_write_state_changed"
               ),
               :count
             )
  end

  test "archive rejects unsigned write-state changes without changing document state" do
    %{user_id: user_id, workspace: workspace} =
      setup_workspace("write-state-unsigned@example.com")

    document = create_document(workspace.id, user_id)

    assert {:error, :invalid_key_directory} =
             Documents.archive_document(document, %{events: [], checkpoint: %{}})

    refute Documents.get_document(document.id).archived_at
  end

  test "archive rejects an append that omits an affected descendant" do
    %{user_id: user_id, workspace: workspace, signer: signer} =
      setup_workspace("write-state-missing-descendant@example.com")

    folder = create_document(workspace.id, user_id, "folder")
    child = create_document(workspace.id, user_id, "document", folder.id)

    append =
      document_write_state_key_directory_append(
        workspace.id,
        user_id,
        signer.device_id,
        signer.signing_private,
        [
          %{document_id: folder.id, previous_write_state: "writable", write_state: "archived"}
        ],
        "archive"
      )

    {:ok, admission} = Documents.WriteStateAdmission.parse_append(append)

    assert {:error, :invalid_key_directory} = Documents.archive_document(folder, admission)
    refute Documents.get_document(folder.id).archived_at
    refute Documents.get_document(child.id).archived_at
  end

  test "read-only transition persists signed state and blocks document updates" do
    %{user_id: user_id, workspace: workspace, signer: signer} =
      setup_workspace("write-state-read-only@example.com")

    document = create_document(workspace.id, user_id)

    enable_append =
      document_write_state_key_directory_append(
        workspace.id,
        user_id,
        signer.device_id,
        signer.signing_private,
        [
          %{
            document_id: document.id,
            previous_write_state: "writable",
            write_state: "read_only"
          }
        ],
        "read_only_enabled"
      )

    {:ok, admission} = Documents.WriteStateAdmission.parse_append(enable_append)
    assert {:ok, read_only} = Documents.enable_document_read_only(document, admission)
    assert read_only.write_state == "read_only"
    assert Documents.get_document(document.id).write_state == "read_only"

    assert {:error, :document_read_only} =
             Documents.update_document(Documents.get_document(document.id), %{title: "Blocked"})

    disable_append =
      document_write_state_key_directory_append(
        workspace.id,
        user_id,
        signer.device_id,
        signer.signing_private,
        [
          %{
            document_id: document.id,
            previous_write_state: "read_only",
            write_state: "writable"
          }
        ],
        "read_only_disabled"
      )

    {:ok, admission} = Documents.WriteStateAdmission.parse_append(disable_append)
    assert {:ok, writable} = Documents.disable_document_read_only(read_only, admission)
    assert writable.write_state == "writable"

    assert {:ok, updated} =
             Documents.update_document(Documents.get_document(document.id), %{title: "Allowed"})

    assert updated.write_state == "writable"
  end

  test "policy write-disable persists signed state and blocks document updates" do
    %{user_id: user_id, workspace: workspace, signer: signer} =
      setup_workspace("write-state-policy-disabled@example.com")

    document = create_document(workspace.id, user_id)

    append =
      document_write_state_key_directory_append(
        workspace.id,
        user_id,
        signer.device_id,
        signer.signing_private,
        [
          %{
            document_id: document.id,
            previous_write_state: "writable",
            write_state: "write_disabled"
          }
        ],
        "policy"
      )

    {:ok, admission} = Documents.WriteStateAdmission.parse_append(append)
    assert {:ok, disabled} = Documents.disable_document_writes_by_policy(document, admission)
    assert disabled.write_state == "write_disabled"

    assert {:error, :document_write_disabled} =
             Documents.update_document(Documents.get_document(document.id), %{title: "Blocked"})

    assert {:error, :already_write_disabled} =
             Documents.disable_document_writes_by_policy(disabled, admission)
  end

  test "generic document updates cannot change write state without admission" do
    %{user_id: user_id, workspace: workspace} =
      setup_workspace("write-state-direct-update@example.com")

    document = create_document(workspace.id, user_id)

    assert {:ok, updated} = Documents.update_document(document, %{write_state: "read_only"})
    assert updated.write_state == "writable"
    assert Documents.get_document(document.id).write_state == "writable"
  end

  test "archive records read-only as the previous write state" do
    %{user_id: user_id, workspace: workspace, signer: signer} =
      setup_workspace("write-state-archive-read-only@example.com")

    document = create_document(workspace.id, user_id)

    read_only_append =
      document_write_state_key_directory_append(
        workspace.id,
        user_id,
        signer.device_id,
        signer.signing_private,
        [
          %{
            document_id: document.id,
            previous_write_state: "writable",
            write_state: "read_only"
          }
        ],
        "read_only_enabled"
      )

    {:ok, admission} = Documents.WriteStateAdmission.parse_append(read_only_append)
    assert {:ok, read_only} = Documents.enable_document_read_only(document, admission)

    archive_append =
      document_write_state_key_directory_append(
        workspace.id,
        user_id,
        signer.device_id,
        signer.signing_private,
        [
          %{
            document_id: document.id,
            previous_write_state: "read_only",
            write_state: "archived"
          }
        ],
        "archive"
      )

    {:ok, admission} = Documents.WriteStateAdmission.parse_append(archive_append)
    assert {:ok, archived} = Documents.archive_document(read_only, admission)
    assert archived.archived_at
    assert archived.write_state == "archived"
  end

  test "archive does not mutate already archived descendants omitted from append" do
    %{user_id: user_id, workspace: workspace, signer: signer} =
      setup_workspace("write-state-archive-archived-descendant@example.com")

    folder = create_document(workspace.id, user_id, "folder")
    child = create_document(workspace.id, user_id, "document", folder.id)
    archived_at = DateTime.utc_now() |> DateTime.add(-3600, :second)

    {1, nil} =
      Document
      |> where([d], d.id == ^child.id)
      |> Repo.update_all(set: [archived_at: archived_at, updated_at: archived_at])

    append =
      document_write_state_key_directory_append(
        workspace.id,
        user_id,
        signer.device_id,
        signer.signing_private,
        [
          %{document_id: folder.id, previous_write_state: "writable", write_state: "archived"}
        ],
        "archive"
      )

    {:ok, admission} = Documents.WriteStateAdmission.parse_append(append)
    assert {:ok, _archived} = Documents.archive_document(folder, admission)
    reloaded_child = Documents.get_document(child.id)
    assert reloaded_child.archived_at == archived_at
    assert reloaded_child.updated_at == archived_at
  end

  test "archive and unarchive write-state admission transactions are serializable" do
    source =
      "lib/refmd/documents/documents.ex"
      |> Path.expand(File.cwd!())
      |> File.read!()

    assert source =~ "isolation: :serializable"

    assert length(
             Regex.scan(
               ~r/Repo\.transaction\(\s*fn ->.*?end,\s*isolation: :serializable\s*\)/s,
               source
             )
           ) >= 2
  end
end
