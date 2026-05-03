defmodule RefMDWeb.DocumentChannelShareTest do
  use RefMDWeb.ChannelIntegrationCase, async: false

  import Phoenix.ChannelTest

  alias RefMD.Crypto.Blake3
  alias RefMD.Documents
  alias RefMD.Documents.{Document, DocumentSignerKey, DocumentSnapshot}
  alias RefMD.Repo
  alias RefMD.Sharing
  alias RefMD.Users.User
  alias RefMD.Workspaces

  @endpoint RefMDWeb.Endpoint

  defp create_user(email) do
    user_id = Ecto.UUID.generate()
    unique_email = String.replace(email, "@", "+#{System.unique_integer([:positive])}@")

    Repo.insert!(%User{
      id: user_id,
      email: unique_email,
      name: unique_email
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

  defp create_folder(workspace_id, created_by) do
    {:ok, folder} =
      Documents.create_document(%{
        "id" => Ecto.UUID.generate(),
        "workspace_id" => workspace_id,
        "doc_type" => "folder",
        "title" => "Folder",
        "created_by" => created_by
      })

    folder
  end

  defp create_folder_share_attrs(nodes, opts \\ []) do
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    %{
      "id" => Ecto.UUID.generate(),
      "scope" => "folder",
      "share_slug" => share_slug,
      "token_prefix" => String.slice(share_slug, 0, 4),
      "permission" => Keyword.get(opts, :permission, "view"),
      "password_protected" => false,
      "encrypted_dek" => :crypto.strong_rand_bytes(32),
      "nonce" => nil,
      "share_keys" =>
        Enum.map(nodes, fn document ->
          %{
            "share_id" => Ecto.UUID.generate(),
            "document_id" => document.id,
            "encrypted_dek" => :crypto.strong_rand_bytes(32),
            "nonce" => nil
          }
        end)
    }
  end

  defp create_active_snapshot(document_id, device_id, signing_public_key) do
    snapshot_id = Ecto.UUID.generate()
    ciphertext = <<7, 7, 7>>

    %DocumentSnapshot{}
    |> DocumentSnapshot.changeset(%{
      id: snapshot_id,
      document_id: document_id,
      parent_snapshot_id: nil,
      device_id: device_id,
      latest_version: 0,
      data: ciphertext,
      nonce: :crypto.strong_rand_bytes(24),
      key_version: 1,
      signature: :crypto.strong_rand_bytes(64),
      ciphertext_hash: Blake3.hash_base64url(ciphertext),
      clocks: %{},
      parent_snapshot_update_clocks: %{},
      parent_snapshot_proof: "",
      created_by_device: Base.url_encode64(signing_public_key, padding: false)
    })
    |> Repo.insert!()

    Repo.get!(Document, document_id)
    |> Ecto.Changeset.change(active_snapshot_id: snapshot_id)
    |> Repo.update!()

    snapshot_id
  end

  defp join_params(share_id, device_id, signing_private_key) do
    {:ok, challenge} = Sharing.create_pop_challenge(share_id, device_id)

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

  defp signed_ephemeral_payload(document_id, device_id, signing_public_key, signing_private_key) do
    public_data = %{
      "docId" => document_id,
      "deviceId" => device_id,
      "signingPubKey" => Base.url_encode64(signing_public_key, padding: false)
    }

    ciphertext_b64 = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
    nonce_b64 = Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)

    signature =
      RefMD.Crypto.build_ws_signature_message(
        "refmd_ephemeral",
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

  defp signed_update_payload(
         document_id,
         device_id,
         signing_public_key,
         signing_private_key,
         ref_snapshot_id
       ) do
    ciphertext = <<9, 9, 9>>
    nonce = :crypto.strong_rand_bytes(24)
    timestamp = System.system_time(:millisecond)
    signing_key_b64 = Base.url_encode64(signing_public_key, padding: false)
    ciphertext_b64 = Base.url_encode64(ciphertext, padding: false)
    nonce_b64 = Base.url_encode64(nonce, padding: false)

    public_data = %{
      "docId" => document_id,
      "deviceId" => device_id,
      "signingPubKey" => signing_key_b64,
      "clock" => 0,
      "keyVersion" => 1,
      "timestamp" => timestamp,
      "refSnapshotId" => ref_snapshot_id,
      "updateHash" =>
        RefMD.Crypto.compute_update_hash(%{
          "clock" => 0,
          "device_signing_pub_key" => signing_key_b64,
          "document_id" => document_id,
          "encrypted_content" => ciphertext_b64,
          "key_version" => 1,
          "nonce" => nonce_b64,
          "ref_snapshot_id" => ref_snapshot_id,
          "timestamp" => timestamp
        })
    }

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

  defp share_socket(created, bootstrapped) do
    socket(RefMDWeb.UserSocket, nil, %{
      current_user_id: bootstrapped.participant.principal_id,
      current_session: bootstrapped.session,
      current_share_id: created.share.id,
      share_participant_grant: bootstrapped.session.grant,
      share_participant_principal_id: bootstrapped.participant.principal_id,
      session_kind: :share_participant
    })
  end

  test "excluded document revocation stops an active share participant channel" do
    owner_id = create_user("owner-channel-share@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Share Channel Workspace")
    folder = create_folder(workspace.id, owner_id)
    document = create_document(workspace.id, owner_id, folder.id)

    assert {:ok, created} =
             Sharing.create_share(folder, owner_id, create_folder_share_attrs([document]))

    {signing_public_key, signing_private_key} = :crypto.generate_key(:eddsa, :ed25519)
    {encryption_public_key, _encryption_private_key} = :crypto.generate_key(:ecdh, :x25519)

    assert {:ok, bootstrapped} =
             Sharing.bootstrap_participant(created.share_slug, %{
               "display_name" => "Guest User",
               "device_signing_pub_key" => signing_public_key,
               "device_encryption_pub_key" => encryption_public_key
             })

    assert {:ok, _reply, socket} =
             subscribe_and_join(
               share_socket(created, bootstrapped),
               RefMDWeb.DocumentChannel,
               "document:#{document.id}",
               join_params(
                 created.share.id,
                 bootstrapped.participant.device_id,
                 signing_private_key
               )
             )

    assert_push "document", _payload

    channel_pid = socket.channel_pid
    monitor_ref = Process.monitor(channel_pid)

    assert {:ok, _result} =
             Sharing.update_share_exclusions(
               folder.id,
               created.share.id,
               created.share_manage_token,
               %{"add" => [document.id]}
             )

    assert_push "unauthorized", %{}
    assert_receive {:DOWN, ^monitor_ref, :process, ^channel_pid, _reason}
  end

  test "view share participant cannot send ephemeral messages" do
    owner_id = create_user("owner-channel-share-ephemeral@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Share Channel Workspace")
    folder = create_folder(workspace.id, owner_id)
    document = create_document(workspace.id, owner_id, folder.id)

    assert {:ok, created} =
             Sharing.create_share(folder, owner_id, create_folder_share_attrs([document]))

    {signing_public_key, signing_private_key} = :crypto.generate_key(:eddsa, :ed25519)
    {encryption_public_key, _encryption_private_key} = :crypto.generate_key(:ecdh, :x25519)

    assert {:ok, bootstrapped} =
             Sharing.bootstrap_participant(created.share_slug, %{
               "display_name" => "Guest User",
               "device_signing_pub_key" => signing_public_key,
               "device_encryption_pub_key" => encryption_public_key
             })

    assert {:ok, _reply, socket} =
             subscribe_and_join(
               share_socket(created, bootstrapped),
               RefMDWeb.DocumentChannel,
               "document:#{document.id}",
               join_params(
                 created.share.id,
                 bootstrapped.participant.device_id,
                 signing_private_key
               )
             )

    assert_push "document", _payload

    ref =
      Phoenix.ChannelTest.push(
        socket,
        "ephemeral",
        signed_ephemeral_payload(
          document.id,
          bootstrapped.participant.device_id,
          signing_public_key,
          signing_private_key
        )
      )

    assert_reply ref, :error, %{reason: "permission_denied"}
  end

  test "edit share participant update records a durable signer key" do
    owner_id = create_user("owner-channel-share-update@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Share Update Workspace")
    folder = create_folder(workspace.id, owner_id)
    document = create_document(workspace.id, owner_id, folder.id)

    assert {:ok, created} =
             Sharing.create_share(
               folder,
               owner_id,
               create_folder_share_attrs([document], permission: "edit")
             )

    {signing_public_key, signing_private_key} = :crypto.generate_key(:eddsa, :ed25519)
    {encryption_public_key, _encryption_private_key} = :crypto.generate_key(:ecdh, :x25519)

    assert {:ok, bootstrapped} =
             Sharing.bootstrap_participant(created.share_slug, %{
               "display_name" => "Edit Guest",
               "device_signing_pub_key" => signing_public_key,
               "device_encryption_pub_key" => encryption_public_key
             })

    snapshot_id =
      create_active_snapshot(
        document.id,
        bootstrapped.participant.device_id,
        signing_public_key
      )

    assert {:ok, _reply, socket} =
             subscribe_and_join(
               share_socket(created, bootstrapped),
               RefMDWeb.DocumentChannel,
               "document:#{document.id}",
               join_params(
                 created.share.id,
                 bootstrapped.participant.device_id,
                 signing_private_key
               )
             )

    assert_push "document", _payload

    Phoenix.ChannelTest.push(
      socket,
      "update",
      signed_update_payload(
        document.id,
        bootstrapped.participant.device_id,
        signing_public_key,
        signing_private_key,
        snapshot_id
      )
    )

    assert_push "update-saved", %{snapshotId: ^snapshot_id, clock: 0, version: 1}

    signer =
      Repo.get_by!(DocumentSignerKey,
        document_id: document.id,
        signing_public_key: signing_public_key
      )

    assert signer.signer_kind == "share_participant"
    assert signer.share_id == created.share.id
    assert signer.principal_id == bootstrapped.participant.principal_id
    assert signer.device_id == bootstrapped.participant.device_id
  end
end
