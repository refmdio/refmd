defmodule RefMDWeb.DocumentChannelGuestTest do
  use RefMDWeb.ConnCase

  import Phoenix.ChannelTest

  alias RefMD.Auth
  alias RefMD.Documents
  alias RefMD.Repo
  alias RefMD.Users.User
  alias RefMD.Workspaces

  @endpoint RefMDWeb.Endpoint

  defp create_user(email) do
    user_id = Ecto.UUID.generate()

    Repo.insert!(%User{
      id: user_id,
      email: email,
      name: email,
      account_type: "registered"
    })

    user_id
  end

  defp create_document(workspace_id, created_by) do
    {:ok, document} =
      Documents.create_document(%{
        "id" => Ecto.UUID.generate(),
        "workspace_id" => workspace_id,
        "doc_type" => "document",
        "title" => "Untitled",
        "encrypted_title" => <<1, 2, 3>>,
        "encrypted_title_nonce" => :crypto.strong_rand_bytes(24),
        "encrypted_title_key_version" => 1,
        "created_by" => created_by
      })

    document
  end

  defp invitation_attrs(workspace_id, actor_role, invited_by, document_id, token_hash) do
    %{
      workspace_id: workspace_id,
      actor_role: actor_role,
      invitation_id: Ecto.UUID.generate(),
      token_hash: token_hash,
      token_prefix: "AbCd",
      target_scope: "document",
      target_document_id: document_id,
      permission: "view",
      encrypted_kek: :crypto.strong_rand_bytes(48),
      kek_nonce: :crypto.strong_rand_bytes(24),
      kek_version: 1,
      max_redemptions: 1,
      invited_by: invited_by,
      expires_at: DateTime.add(DateTime.utc_now(), 86_400, :second)
    }
  end

  defp join_params(user_id, device_id, signing_private_key) do
    {:ok, challenge} = Auth.create_pop_challenge(user_id, device_id)

    message =
      RefMD.Crypto.build_signature_message("pop_challenge", %{
        "challenge" => Base.url_encode64(challenge, padding: false),
        "device_id" => device_id
      })

    signature = :crypto.sign(:eddsa, :none, message, [signing_private_key, :ed25519])

    %{
      "pop_challenge" => Base.url_encode64(challenge, padding: false),
      "pop_signature" => Base.url_encode64(signature, padding: false),
      "mode" => "complete"
    }
  end

  defp guest_device_attrs(signing_public_key, ecdh_public_key) do
    {identity_signing_public_key, identity_signing_private_key} =
      :crypto.generate_key(:eddsa, :ed25519)

    {identity_ecdh_public_key, identity_ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)
    client_nonce = :crypto.strong_rand_bytes(16)

    identity_signature =
      RefMD.Crypto.build_signature_message("device_registration", %{
        "client_nonce" => Base.url_encode64(client_nonce, padding: false),
        "device_ecdh_public_key" => Base.url_encode64(ecdh_public_key, padding: false),
        "device_signing_public_key" => Base.url_encode64(signing_public_key, padding: false)
      })
      |> then(&:crypto.sign(:eddsa, :none, &1, [identity_signing_private_key, :ed25519]))

    %{
      device_signing_pub_key: signing_public_key,
      device_encryption_pub_key: ecdh_public_key,
      identity_signing_pub_key: identity_signing_public_key,
      identity_encryption_pub_key: identity_ecdh_public_key,
      identity_signature: identity_signature,
      client_nonce: client_nonce,
      recovery_encrypted_umk: :crypto.strong_rand_bytes(48),
      recovery_nonce: :crypto.strong_rand_bytes(24),
      encrypted_identity_encryption_private: identity_ecdh_private_key <> <<0::128>>,
      encrypted_identity_encryption_private_nonce: :crypto.strong_rand_bytes(24),
      encrypted_identity_signing_private: identity_signing_private_key <> <<0::128>>,
      encrypted_identity_signing_private_nonce: :crypto.strong_rand_bytes(24),
      device_name: "Guest Browser",
      device_type: "browser"
    }
  end

  defp update_payload(
         document_id,
         device_id,
         signing_public_key,
         signing_private_key,
         ref_snapshot_id,
         clock \\ 0
       ) do
    ciphertext = <<9, 9, 9>>
    nonce = :crypto.strong_rand_bytes(24)
    timestamp = System.system_time(:millisecond)

    public_data = %{
      "docId" => document_id,
      "deviceId" => device_id,
      "signingPubKey" => Base.url_encode64(signing_public_key, padding: false),
      "clock" => clock,
      "keyVersion" => 1,
      "timestamp" => timestamp,
      "refSnapshotId" => ref_snapshot_id,
      "updateHash" =>
        RefMD.Crypto.compute_update_hash(%{
          "clock" => clock,
          "device_signing_pub_key" => Base.url_encode64(signing_public_key, padding: false),
          "document_id" => document_id,
          "encrypted_content" => Base.url_encode64(ciphertext, padding: false),
          "key_version" => 1,
          "nonce" => Base.url_encode64(nonce, padding: false),
          "ref_snapshot_id" => ref_snapshot_id,
          "timestamp" => timestamp
        })
    }

    ciphertext_b64 = Base.url_encode64(ciphertext, padding: false)
    nonce_b64 = Base.url_encode64(nonce, padding: false)

    signature =
      RefMD.Crypto.build_ws_signature_message(
        "refmd_update",
        ciphertext_b64,
        nonce_b64,
        public_data
      )
      |> then(&:crypto.sign(:eddsa, :none, &1, [signing_private_key, :ed25519]))

    %{
      "ciphertext" => ciphertext_b64,
      "nonce" => nonce_b64,
      "signature" => Base.url_encode64(signature, padding: false),
      "publicData" => public_data
    }
  end

  defp guest_socket(user_id, session) do
    socket(RefMDWeb.UserSocket, nil, %{
      current_user_id: user_id,
      current_session: session
    })
  end

  setup do
    owner_id = create_user("owner-channel-guest@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Channel Guest Workspace")
    Workspaces.update_current_kek_version(workspace.id, 1)
    {:ok, workspace} = Workspaces.update_workspace(workspace, %{guest_invites_enabled: true})

    invited_document = create_document(workspace.id, owner_id)
    other_document = create_document(workspace.id, owner_id)
    {_member, owner_role} = Workspaces.get_member_with_role(workspace.id, owner_id)

    token_hash =
      Base.url_encode64(:crypto.hash(:sha256, :crypto.strong_rand_bytes(32)), padding: false)

    {:ok, _invitation} =
      Workspaces.create_guest_invitation(
        invitation_attrs(workspace.id, owner_role, owner_id, invited_document.id, token_hash)
      )

    {guest_signing_public_key, guest_signing_private_key} =
      :crypto.generate_key(:eddsa, :ed25519)

    {guest_ecdh_public_key, _guest_ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)

    {:ok, redeem_result} =
      Workspaces.redeem_guest_invitation(
        token_hash,
        guest_device_attrs(guest_signing_public_key, guest_ecdh_public_key),
        %{ip_address: "127.0.0.1", user_agent: "channel-test"}
      )

    %{
      invited_document: invited_document,
      other_document: other_document,
      owner_id: owner_id,
      owner_role: owner_role,
      guest_user_id: redeem_result.guest_user_id,
      guest_device_id: redeem_result.guest_device_id,
      guest_signing_public_key: guest_signing_public_key,
      guest_signing_private_key: guest_signing_private_key,
      guest_session: redeem_result.session,
      workspace: workspace
    }
  end

  test "document-scoped guest can join only the invited document", %{
    invited_document: invited_document,
    other_document: other_document,
    guest_user_id: guest_user_id,
    guest_device_id: guest_device_id,
    guest_signing_private_key: guest_signing_private_key,
    guest_session: guest_session
  } do
    assert {:ok, %{connectionId: _connection_id}, _socket} =
             subscribe_and_join(
               guest_socket(guest_user_id, guest_session),
               RefMDWeb.DocumentChannel,
               "document:#{invited_document.id}",
               join_params(guest_user_id, guest_device_id, guest_signing_private_key)
             )

    assert {:error, %{reason: "permission_denied"}} =
             subscribe_and_join(
               guest_socket(guest_user_id, guest_session),
               RefMDWeb.DocumentChannel,
               "document:#{other_document.id}",
               join_params(guest_user_id, guest_device_id, guest_signing_private_key)
             )
  end

  test "guest loses channel access when workspace membership is missing", %{
    invited_document: invited_document,
    guest_user_id: guest_user_id,
    guest_device_id: guest_device_id,
    guest_signing_private_key: guest_signing_private_key,
    guest_session: guest_session,
    workspace: workspace
  } do
    membership = Workspaces.get_workspace_member(workspace.id, guest_user_id)
    Repo.delete!(membership)

    assert {:error, %{reason: "permission_denied"}} =
             subscribe_and_join(
               guest_socket(guest_user_id, guest_session),
               RefMDWeb.DocumentChannel,
               "document:#{invited_document.id}",
               join_params(guest_user_id, guest_device_id, guest_signing_private_key)
             )
  end

  test "guest loses channel access when the guest device is revoked", %{
    invited_document: invited_document,
    guest_user_id: guest_user_id,
    guest_device_id: guest_device_id,
    guest_signing_private_key: guest_signing_private_key,
    guest_session: guest_session
  } do
    guest_device = RefMD.Devices.get_device(guest_device_id)

    guest_device
    |> Ecto.Changeset.change(revoked_at: DateTime.utc_now())
    |> Repo.update!()

    assert {:error, %{reason: "pop_verification_failed"}} =
             subscribe_and_join(
               guest_socket(guest_user_id, guest_session),
               RefMDWeb.DocumentChannel,
               "document:#{invited_document.id}",
               join_params(guest_user_id, guest_device_id, guest_signing_private_key)
             )
  end

  test "view guest cannot push updates over the channel", %{
    invited_document: invited_document,
    guest_user_id: guest_user_id,
    guest_device_id: guest_device_id,
    guest_signing_public_key: guest_signing_public_key,
    guest_signing_private_key: guest_signing_private_key,
    guest_session: guest_session
  } do
    ref_snapshot_id = Ecto.UUID.generate()

    {:ok, _reply, socket} =
      subscribe_and_join(
        guest_socket(guest_user_id, guest_session),
        RefMDWeb.DocumentChannel,
        "document:#{invited_document.id}",
        join_params(guest_user_id, guest_device_id, guest_signing_private_key)
      )

    ref =
      Phoenix.ChannelTest.push(
        socket,
        "update",
        update_payload(
          invited_document.id,
          guest_device_id,
          guest_signing_public_key,
          guest_signing_private_key,
          ref_snapshot_id
        )
      )

    assert_reply ref, :error, %{reason: "permission_denied"}
  end

  test "workspace-scoped edit guest can join the document channel", %{
    invited_document: invited_document,
    owner_id: owner_id,
    owner_role: owner_role,
    workspace: workspace
  } do
    token_hash =
      Base.url_encode64(:crypto.hash(:sha256, :crypto.strong_rand_bytes(32)), padding: false)

    {:ok, _invitation} =
      Workspaces.create_guest_invitation(%{
        workspace_id: workspace.id,
        actor_role: owner_role,
        invitation_id: Ecto.UUID.generate(),
        token_hash: token_hash,
        token_prefix: "EfGh",
        target_scope: "workspace",
        target_document_id: nil,
        permission: "edit",
        encrypted_kek: :crypto.strong_rand_bytes(48),
        kek_nonce: :crypto.strong_rand_bytes(24),
        kek_version: 1,
        max_redemptions: 1,
        invited_by: owner_id,
        expires_at: DateTime.add(DateTime.utc_now(), 86_400, :second)
      })

    {guest_signing_public_key, guest_signing_private_key} =
      :crypto.generate_key(:eddsa, :ed25519)

    {guest_ecdh_public_key, _guest_ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)

    {:ok, redeem_result} =
      Workspaces.redeem_guest_invitation(
        token_hash,
        guest_device_attrs(guest_signing_public_key, guest_ecdh_public_key),
        %{ip_address: "127.0.0.1", user_agent: "channel-edit-test"}
      )

    {:ok, _reply, socket} =
      subscribe_and_join(
        guest_socket(redeem_result.guest_user_id, redeem_result.session),
        RefMDWeb.DocumentChannel,
        "document:#{invited_document.id}",
        join_params(
          redeem_result.guest_user_id,
          redeem_result.guest_device_id,
          guest_signing_private_key
        )
      )

    assert socket.assigns.document_id == invited_document.id
  end
end
