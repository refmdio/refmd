defmodule RefMDWeb.Channels.Document.AccessTest do
  use RefMDWeb.ConnCase, async: true

  alias RefMD.Documents
  alias RefMD.Repo
  alias RefMD.Users.User
  alias RefMD.Workspaces
  alias RefMD.Workspaces.GuestInvitation
  alias RefMD.Workspaces.WorkspaceGuestGrant
  alias RefMD.Workspaces.WorkspaceMember
  alias RefMDWeb.Channels.Document.Access
  alias RefMDWeb.Channels.Document.Bootstrap

  defp create_user(email) do
    Repo.insert!(%User{
      id: Ecto.UUID.generate(),
      email: email,
      name: email
    })
  end

  defp create_guest_user(email) do
    Repo.insert!(%User{
      id: Ecto.UUID.generate(),
      email: email,
      name: email,
      account_type: "guest"
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

  defp add_workspace_guest_grant(workspace, owner, guest) do
    token_hash = random_base64url()

    invitation =
      Repo.insert!(%GuestInvitation{
        id: Ecto.UUID.generate(),
        workspace_id: workspace.id,
        token_hash: token_hash,
        token_prefix: String.slice(token_hash, 0, 4),
        scope_kind: "workspace",
        permission: "view",
        kek_version: 1,
        bootstrap_key_commitment: random_base64url(),
        encrypted_bootstrap_package: %{"version" => 1},
        bootstrap_package_hash: random_base64url(),
        bootstrap_package_key_recipient_wrap: %{"ciphertext" => "x", "nonce" => "y"},
        bootstrap_suite_id: "refmd-v2-invitation-bootstrap-xchacha20poly1305",
        capability_context_hash: random_base64url(),
        max_redemptions: 1,
        redemption_count: 1,
        invited_by: owner.id,
        expires_at: DateTime.add(DateTime.utc_now(), 3600, :second),
        created_at: DateTime.utc_now()
      })

    Repo.insert!(%WorkspaceGuestGrant{
      id: Ecto.UUID.generate(),
      workspace_id: workspace.id,
      user_id: guest.id,
      scope_kind: "workspace",
      permission: "view",
      invite_id: invitation.id,
      created_at: DateTime.utc_now()
    })
  end

  defp random_base64url do
    32
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
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

  test "workspace channel bootstrap marks non-writers as read-only" do
    owner = create_user("bootstrap-readonly-owner@example.com")
    viewer = create_user("bootstrap-readonly-viewer@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner.id, "Bootstrap ReadOnly")
    document = create_document(workspace.id, owner.id)
    add_viewer_member(workspace.id, viewer.id)
    socket = %Phoenix.Socket{assigns: %{session_kind: :user}}

    assert {:ok, %{readOnly: false}} =
             Bootstrap.load_for_join(document, %{}, socket, nil, owner.id)

    assert {:ok, %{readOnly: true}} =
             Bootstrap.load_for_join(document, %{}, socket, nil, viewer.id)
  end

  test "workspace channel bootstrap allows active guest grants without workspace membership" do
    owner = create_user("bootstrap-guest-owner@example.com")
    guest = create_guest_user("bootstrap-guest@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner.id, "Bootstrap Guest")
    document = create_document(workspace.id, owner.id)
    add_workspace_guest_grant(workspace, owner, guest)
    socket = %Phoenix.Socket{assigns: %{session_kind: :user}}

    assert {:ok, %{readOnly: true}} =
             Bootstrap.load_for_join(document, %{}, socket, nil, guest.id)
  end

  test "publication sync is never allowed from share contexts" do
    owner = create_user("publication-sync-share-owner@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner.id, "Publication Sync Share")
    document = create_document(workspace.id, owner.id)

    share_socket = %Phoenix.Socket{assigns: %{session_kind: :share_participant}}

    refute Access.publication_sync_allowed?(document, owner.id, share_socket, nil)
    refute Access.publication_sync_allowed?(document, owner.id, nil, Ecto.UUID.generate())
  end

  test "share participant broadcast check uses joined socket state" do
    share_id = Ecto.UUID.generate()
    principal_id = Ecto.UUID.generate()
    device_id = Ecto.UUID.generate()

    socket = %Phoenix.Socket{
      assigns: %{
        session_kind: :share_participant,
        current_share_id: share_id,
        current_session: %{share_id: share_id, device_id: device_id},
        share_participant_grant: "edit",
        share_participant_principal_id: principal_id,
        device_id: device_id
      }
    }

    assert :ok = Access.check_broadcast(socket)

    stale_socket = %Phoenix.Socket{
      socket
      | assigns: %{
          socket.assigns
          | current_session: %{share_id: share_id, device_id: Ecto.UUID.generate()}
        }
    }

    assert :evict = Access.check_broadcast(stale_socket)
  end
end
