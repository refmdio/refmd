defmodule RefMDWeb.Channels.Document.PublicStatusTest do
  use RefMDWeb.ChannelIntegrationCase, async: false

  alias RefMD.Documents
  alias RefMD.Users.User
  alias RefMD.Workspaces
  alias RefMDWeb.DocumentChannel

  defp create_user(email) do
    user_id = Ecto.UUID.generate()
    email = String.replace(email, "@", "+#{user_id}@")

    Repo.insert!(%User{
      id: user_id,
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

  defp joined_socket(assigns) do
    RefMDWeb.UserSocket
    |> socket(nil, assigns)
    |> Map.put(:topic, "document:#{assigns.document.id}")
    |> Map.put(:join_ref, "join-ref")
    |> Map.put(:joined, true)
  end

  test "public status broadcasts are pushed by the document channel" do
    owner = create_user("public-status-channel-owner@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner.id, "Public Status Channel")
    document = create_document(workspace.id, owner.id)

    socket =
      joined_socket(%{
        current_user_id: owner.id,
        document: document,
        session_kind: :user,
        silent: false
      })

    payload = %{
      is_published: true,
      updated_at: DateTime.utc_now()
    }

    assert {:noreply, ^socket} =
             DocumentChannel.handle_out("public-status-changed", payload, socket)

    assert_push "public-status-changed", ^payload
  end

  test "silent joins ignore public status broadcasts" do
    socket =
      joined_socket(%{
        document: %{id: Ecto.UUID.generate()},
        silent: true
      })

    payload = %{
      is_published: false,
      updated_at: nil
    }

    assert {:noreply, ^socket} =
             DocumentChannel.handle_out("public-status-changed", payload, socket)

    refute_push "public-status-changed", _payload
  end
end
