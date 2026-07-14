defmodule RefMDWeb.DocumentChannelShareTest do
  use RefMDWeb.ChannelIntegrationCase, async: false

  import Phoenix.ChannelTest

  alias RefMD.Auth
  alias RefMD.Crypto.{Blake3, Hash, JCS, Signature, Suite}
  alias RefMD.Devices.Device
  alias RefMD.Documents
  alias RefMD.Documents.{Document, DocumentSignerKey, DocumentSnapshot, DocumentUpdate}
  alias RefMD.Documents.Snapshots.ProofChain
  alias RefMD.Encryption.DocumentEncryptedKey
  alias RefMD.Encryption.KeyDirectory
  alias RefMD.Encryption.KeyDirectory.{Checkpoint, Event}
  alias RefMD.Repo
  alias RefMD.Sharing
  alias RefMD.Sharing.{ShareKey, ShareKeyHistory}
  alias RefMD.Users.User
  alias RefMD.Workspaces
  alias RefMD.Workspaces.WorkspaceDeviceWipeRequirement
  alias RefMDWeb.Channels.Document.Access
  alias RefMDWeb.Http.RrpSessionBinding
  alias RefMDWeb.Http.RrpTranscript

  @endpoint RefMDWeb.Endpoint

  defp create_user(email) do
    user_id = Ecto.UUID.generate()
    unique_email = String.replace(email, "@", "+#{user_id}@")

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
    workspace_pin_bootstrap_hash = Process.get(:workspace_pin_bootstrap_hash)

    %{
      "id" => Ecto.UUID.generate(),
      "scope" => "folder",
      "share_slug" => share_slug,
      "token_prefix" => String.slice(share_slug, 0, 4),
      "permission" => Keyword.get(opts, :permission, "view"),
      "password_protected" => false,
      "authenticated_workspace_pin_bootstrap_hash" => workspace_pin_bootstrap_hash,
      "authorization_public_key_material" =>
        share_capability_public_key_material_for_slug(open_admission_key(), share_slug),
      "share_capability_secret_commitment" => open_share_capability_secret_commitment(),
      "key_version" => 1,
      "encrypted_dek" => :crypto.strong_rand_bytes(48),
      "nonce" => :crypto.strong_rand_bytes(24),
      "share_keys" =>
        Enum.map(nodes, fn document ->
          %{
            "share_id" => Ecto.UUID.generate(),
            "document_id" => document.id,
            "key_version" => 1,
            "encrypted_dek" => :crypto.strong_rand_bytes(48),
            "nonce" => :crypto.strong_rand_bytes(24)
          }
        end)
    }
  end

  defp create_active_snapshot(document_id, owner_id) do
    document = Repo.get!(Document, document_id)
    actor_material = Process.get({:test_workspace_signer_material, document.workspace_id})
    device_id = actor_material.device_id
    signing_public_material = actor_material.signing_public
    signing_private_material = actor_material.signing_private
    snapshot_id = Ecto.UUID.generate()
    ciphertext = <<7, 7, 7>>
    nonce = :crypto.strong_rand_bytes(24)
    ciphertext_b64 = Base.url_encode64(ciphertext, padding: false)
    nonce_b64 = Base.url_encode64(nonce, padding: false)
    signing_key_id = Signature.compute_signing_key_id!(signing_public_material)
    previous_checkpoint = KeyDirectory.current_checkpoint("workspace", document.workspace_id)

    public_data = %{
      "docId" => document_id,
      "signingKeyId" => signing_key_id,
      "snapshotId" => snapshot_id,
      "keyVersion" => 1,
      "parentSnapshotId" => "GENESIS",
      "parentProofHash" => "GENESIS",
      "parentSnapshotUpdateClocks" => %{},
      "ownerKind" => "device",
      "ownerId" => device_id,
      "authorityKind" => "workspace_device",
      "authorityId" => document.workspace_id,
      "authorityContextKey" => signing_key_id,
      "authorityScopeId" => document.workspace_id,
      "authorityPermissionVersion" => 1,
      "keyCheckpointSequence" => previous_checkpoint.sequence,
      "keyCheckpointHash" => previous_checkpoint.checkpoint_hash
    }

    signature =
      sign_document_snapshot(
        signing_private_material,
        owner_id,
        device_id,
        ciphertext_b64,
        nonce_b64,
        public_data,
        test_authority_boundary(public_data, "document_snapshot_accepted"),
        document.workspace_id
      )

    ciphertext_hash = Blake3.hash_base64url(ciphertext)
    snapshot_signature_hash = Blake3.hash_base64url(JCS.canonical_bytes!(signature))

    admission =
      document_operation_admission(%{
        workspace_id: document.workspace_id,
        document_id: document_id,
        user_id: owner_id,
        device_id: device_id,
        private_material: signing_private_material,
        event_type: "document_snapshot_accepted",
        operation_hash: ciphertext_hash,
        signature: signature,
        key_version: 1,
        min_dek_version: 1
      })

    [snapshot_event] = admission["workspaceKeyDirectoryEvents"]
    snapshot_admission_event_hash = KeyDirectory.event_hash(snapshot_event["payload"])

    KeyDirectory.append_signed_scope!(
      "workspace",
      document.workspace_id,
      admission["workspaceKeyDirectoryEvents"],
      admission["workspaceKeyDirectoryCheckpoint"],
      checkpoint_signer_kind: "device"
    )

    proof_chain_hash =
      Blake3.hash_base64url(
        JCS.canonical_bytes!(%{
          "protocol" => "refmd.snapshot-proof-link",
          "version" => 1,
          "document_id" => document_id,
          "snapshot_id" => snapshot_id,
          "parent_snapshot_id" => "GENESIS",
          "parent_proof_hash" => "GENESIS",
          "ciphertext_hash" => ciphertext_hash,
          "snapshot_signature_hash" => snapshot_signature_hash,
          "snapshot_admission_event_hash" => snapshot_admission_event_hash
        })
      )

    %DocumentSnapshot{}
    |> DocumentSnapshot.changeset(%{
      id: snapshot_id,
      document_id: document_id,
      parent_snapshot_id: nil,
      device_id: device_id,
      latest_version: 0,
      data: ciphertext,
      nonce: nonce,
      key_version: 1,
      hybrid_signature: signature,
      ciphertext_hash: ciphertext_hash,
      snapshot_signature_hash: snapshot_signature_hash,
      snapshot_admission_event_hash: snapshot_admission_event_hash,
      proof_chain_hash: proof_chain_hash,
      clocks: %{},
      parent_snapshot_update_clocks: %{},
      parent_proof_hash: "GENESIS",
      created_by_signing_key_id: signing_key_id,
      owner_kind: "device",
      owner_id: device_id,
      authority_kind: "workspace_device",
      authority_id: document.workspace_id,
      authority_context_key: signing_key_id,
      authority_scope_id: document.workspace_id,
      authority_permission_version: 1,
      key_checkpoint_sequence: previous_checkpoint.sequence,
      key_checkpoint_hash: previous_checkpoint.checkpoint_hash
    })
    |> Repo.insert!()

    Repo.get!(Document, document_id)
    |> Ecto.Changeset.change(active_snapshot_id: snapshot_id)
    |> Repo.update!()

    snapshot_id
  end

  defp join_params(
         document_id,
         share_id,
         principal_id,
         device_id,
         signing_private_material,
         session
       ) do
    {:ok, challenge} = Sharing.create_rrp_challenge(share_id, principal_id, device_id, session.id)
    challenge_b64 = Base.url_encode64(challenge, padding: false)
    device = Sharing.get_participant_device(share_id, principal_id, device_id)
    workspace_id = Sharing.share_workspace_id!(share_id)
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)

    join_payload = %{
      "mode" => "complete",
      "workspaceKeyDirectoryPinSequence" => checkpoint.sequence,
      "workspaceKeyDirectoryPinHash" => checkpoint.checkpoint_hash
    }

    strict_channel_payload(%{
      "rrp_device_id" => device_id,
      "rrp_actor_variant" => "share_participant_device",
      "rrp_challenge" => challenge_b64,
      "rrp_signature" =>
        signing_private_material
        |> signed_rrp_signature_for_actor(
          "channel_share_participant_device",
          RrpTranscript.share_participant_actor!(device, share_id, workspace_id),
          challenge_b64,
          RrpSessionBinding.for_share_session(session),
          %{
            "channel_event" => "phx_join",
            "document_id" => document_id,
            "event_name" => "phx_join",
            "join_push_kind" => "join",
            "payload_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(join_payload)),
            "scope_kind" => "share",
            "share_id" => share_id,
            "topic" => "document:#{document_id}"
          }
        ),
      "mode" => "complete",
      "workspaceKeyDirectoryPinSequence" => checkpoint.sequence,
      "workspaceKeyDirectoryPinHash" => checkpoint.checkpoint_hash
    })
  end

  defp signed_ephemeral_payload(
         document_id,
         device_id,
         signing_public_material,
         signing_private_material,
         share_id,
         principal_id,
         opts \\ []
       ) do
    workspace_id = Sharing.share_workspace_id!(share_id)
    pin = KeyDirectory.current_pin("workspace", workspace_id)
    stale_head? = Keyword.get(opts, :stale_head, false)

    public_data = %{
      "docId" => document_id,
      "signingKeyId" => Signature.compute_signing_key_id!(signing_public_material),
      "ownerKind" => "share_participant_device",
      "ownerId" => device_id,
      "authorityKind" => "share_participant_device",
      "authorityId" => share_id,
      "authorityContextKey" => "#{share_id}:#{principal_id}",
      "authorityScopeId" => share_id,
      "authorityPermissionVersion" => 1,
      "keyCheckpointSequence" => 1,
      "keyCheckpointHash" => Hash.blake3_base64url("checkpoint"),
      "keyVersion" => Keyword.get(opts, :key_version, 1),
      "workspaceEventHeadSequence" => if(stale_head?, do: 1, else: pin.event_head_sequence),
      "workspaceEventHeadHash" =>
        if(stale_head?,
          do: Hash.blake3_base64url("workspace-event-head"),
          else: pin.event_head_hash
        )
    }

    ciphertext_b64 = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
    nonce_b64 = Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)

    %{
      "ciphertext" => ciphertext_b64,
      "nonce" => nonce_b64,
      "signature" =>
        sign_editor_ephemeral(
          signing_private_material,
          principal_id,
          device_id,
          ciphertext_b64,
          nonce_b64,
          public_data,
          workspace_id
        ),
      "publicData" => public_data
    }
  end

  defp strict_channel_payload(payload) do
    payload
  end

  defp signed_update_payload(
         document_id,
         share_id,
         device_id,
         signing_public_material,
         signing_private_material,
         principal_id,
         ref_snapshot_id
       ) do
    workspace_id = Sharing.share_workspace_id!(share_id)

    ciphertext = <<9, 9, 9>>
    nonce = :crypto.strong_rand_bytes(24)
    timestamp = System.system_time(:millisecond)
    signing_key_id = Signature.compute_signing_key_id!(signing_public_material)
    ciphertext_b64 = Base.url_encode64(ciphertext, padding: false)
    nonce_b64 = Base.url_encode64(nonce, padding: false)

    public_data = %{
      "docId" => document_id,
      "signingKeyId" => signing_key_id,
      "clock" => 0,
      "keyVersion" => 1,
      "timestamp" => timestamp,
      "refSnapshotId" => ref_snapshot_id,
      "ownerKind" => "share_participant_device",
      "ownerId" => device_id,
      "authorityKind" => "share_participant_device",
      "authorityId" => share_id,
      "authorityContextKey" => "#{share_id}:#{principal_id}",
      "authorityScopeId" => share_id,
      "authorityPermissionVersion" => 1,
      "keyCheckpointSequence" => 1,
      "keyCheckpointHash" => Hash.blake3_base64url("checkpoint"),
      "minDekVersion" => 1,
      "writeSessionEventHash" => Hash.blake3_base64url("write-session"),
      "writeSessionId" => Hash.blake3_base64url("write-session-id"),
      "writeSessionCounter" => 1,
      "updateHash" =>
        RefMD.Crypto.compute_update_hash(%{
          "clock" => 0,
          "signing_key_id" => signing_key_id,
          "document_id" => document_id,
          "encrypted_content" => ciphertext_b64,
          "key_version" => 1,
          "nonce" => nonce_b64,
          "ref_snapshot_id" => ref_snapshot_id,
          "timestamp" => timestamp
        })
    }

    signature =
      sign_document_update(
        signing_private_material,
        principal_id,
        device_id,
        ciphertext_b64,
        nonce_b64,
        public_data,
        test_authority_boundary(public_data, "document_write_session_admitted"),
        workspace_id
      )

    %{
      "ciphertext" => ciphertext_b64,
      "nonce" => nonce_b64,
      "signature" => signature,
      "publicData" => public_data
    }
  end

  defp snapshot_payload_without_admission(
         document_id,
         share_id,
         device_id,
         signing_public_material,
         signing_private_material,
         principal_id
       ) do
    workspace_id = Sharing.share_workspace_id!(share_id)

    ciphertext_b64 = Base.url_encode64(<<8, 8, 8>>, padding: false)
    nonce_b64 = Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)

    public_data = %{
      "docId" => document_id,
      "signingKeyId" => Signature.compute_signing_key_id!(signing_public_material),
      "snapshotId" => Ecto.UUID.generate(),
      "keyVersion" => 1,
      "parentSnapshotId" => "GENESIS",
      "parentProofHash" => "GENESIS",
      "parentSnapshotUpdateClocks" => %{},
      "ownerKind" => "share_participant_device",
      "ownerId" => device_id,
      "authorityKind" => "share_participant_device",
      "authorityId" => share_id,
      "authorityContextKey" => "#{share_id}:#{principal_id}",
      "authorityScopeId" => share_id,
      "authorityPermissionVersion" => 1,
      "keyCheckpointSequence" => 1,
      "keyCheckpointHash" => Hash.blake3_base64url("checkpoint")
    }

    %{
      "ciphertext" => ciphertext_b64,
      "nonce" => nonce_b64,
      "signature" =>
        sign_document_snapshot(
          signing_private_material,
          principal_id,
          device_id,
          ciphertext_b64,
          nonce_b64,
          public_data,
          test_authority_boundary(public_data, "document_snapshot_accepted"),
          workspace_id
        ),
      "publicData" => public_data
    }
  end

  defp test_authority_boundary(public_data, event_type) do
    if event_type == "document_write_session_admitted" do
      %{
        "write_session_event_hash" => public_data["writeSessionEventHash"],
        "write_session_id" => public_data["writeSessionId"],
        "write_session_counter" => public_data["writeSessionCounter"],
        "min_dek_version" => public_data["minDekVersion"],
        "document_permission_proof_hash" => public_data["keyCheckpointHash"]
      }
    else
      %{
        "previous_workspace_event_sequence" => public_data["keyCheckpointSequence"],
        "previous_workspace_event_hash" => public_data["keyCheckpointHash"],
        "admission_event_type" => event_type,
        "admission_nonce" => public_data["keyCheckpointHash"],
        "min_dek_version" => public_data["keyVersion"],
        "document_permission_proof_hash" => public_data["keyCheckpointHash"]
      }
    end
  end

  defp share_participant_material do
    device_id = Ecto.UUID.generate()
    private = hybrid_signing_private_key_material("share_participant_device", device_id)
    public = hybrid_signing_public_key_material(private)

    %{
      device_id: device_id,
      private: private,
      public: public
    }
  end

  defp share_participant_bootstrap_attrs(display_name, material, encryption_public_key) do
    encryption =
      hybrid_encryption_public_key_material(
        "share_participant_device",
        material.device_id,
        encryption_public_key
      )

    %{
      "display_name" => display_name,
      "share_participant_principal_id" => Ecto.UUID.generate(),
      "share_participant_device_id" => material.device_id,
      "hybrid_signing_public_key_material" => material.public,
      "hybrid_encryption_public_key_material" => encryption.public,
      "__share_participant_private_material" => material.private
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

  defp user_socket(user_id, session) do
    socket(RefMDWeb.UserSocket, nil, %{
      current_user_id: user_id,
      current_session: session
    })
  end

  test "workspace wipe-required user device is rejected by the document admission gate" do
    owner_id = create_user("owner-wipe-required-admission@example.com")

    {:ok, workspace} =
      Workspaces.create_default_workspace(owner_id, "Wipe Required Admission Workspace")

    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)
    document = create_document(workspace.id, owner_id, nil)
    signer = Process.get({:test_workspace_signer_material, workspace.id})
    ensure_workspace_signer_device!(workspace.id, owner_id, signer)
    device = ensure_test_user_rrp_key_directory!(owner_id, Repo.get!(Device, signer.device_id))

    %WorkspaceDeviceWipeRequirement{}
    |> WorkspaceDeviceWipeRequirement.changeset(%{
      workspace_id: workspace.id,
      device_id: device.id,
      required_kek_version: 2,
      reason: "kek_rotation_deletion_proof_missing",
      required_at: DateTime.utc_now()
    })
    |> Repo.insert!()

    socket =
      socket(RefMDWeb.UserSocket, nil, %{
        current_user_id: owner_id,
        device_id: device.id,
        document: document
      })

    assert {:error, "device_wipe_required"} = Access.validate_device_active(socket)
  end

  defp user_join_params(
         document_id,
         user_id,
         device,
         signing_private_material,
         session,
         opts \\ []
       ) do
    {:ok, challenge} = Auth.create_rrp_challenge(user_id, device.id, session.id)
    challenge_b64 = Base.url_encode64(challenge, padding: false)
    document = Repo.get!(Document, document_id)

    checkpoint =
      Keyword.get_lazy(opts, :workspace_pin_checkpoint, fn ->
        KeyDirectory.current_checkpoint("workspace", document.workspace_id)
      end)

    join_payload =
      %{
        "mode" => "complete",
        "workspaceKeyDirectoryPinSequence" => checkpoint.sequence,
        "workspaceKeyDirectoryPinHash" => checkpoint.checkpoint_hash
      }

    strict_channel_payload(%{
      "rrp_device_id" => device.id,
      "rrp_actor_variant" => "user_device",
      "rrp_challenge" => challenge_b64,
      "rrp_signature" =>
        signing_private_material
        |> signed_rrp_signature_for_actor(
          "channel_user_device",
          RrpTranscript.user_actor!(device, user_id),
          challenge_b64,
          RrpSessionBinding.for_user_session(session),
          %{
            "channel_event" => "phx_join",
            "document_id" => document_id,
            "event_name" => "phx_join",
            "join_push_kind" => "join",
            "payload_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(join_payload)),
            "scope_kind" => "user",
            "share_id" => "none",
            "topic" => "document:#{document_id}"
          }
        ),
      "mode" => "complete",
      "workspaceKeyDirectoryPinSequence" => checkpoint.sequence,
      "workspaceKeyDirectoryPinHash" => checkpoint.checkpoint_hash
    })
  end

  defp authorize_bootstrapped_participant!(_created, bootstrapped) do
    session_token_base64 = Base.url_encode64(bootstrapped.session_token, padding: false)
    pin_hash = Process.get(:workspace_pin_bootstrap_hash)

    case bootstrapped.root do
      %{document_token: document_token} ->
        assert {:ok, _canonical} =
                 Sharing.get_document_bootstrap(
                   document_token,
                   session_token_base64,
                   pin_hash
                 )

      %{folder_token: folder_token} ->
        assert {:ok, _canonical} =
                 Sharing.get_folder_bootstrap(
                   folder_token,
                   session_token_base64,
                   pin_hash
                 )
    end

    bootstrapped
  end

  test "excluded document revocation stops an active share participant channel" do
    owner_id = create_user("owner-channel-share@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Share Channel Workspace")
    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)
    Process.put(:workspace_pin_bootstrap_hash, test_workspace_pin_bootstrap_hash!(workspace.id))
    folder = create_folder(workspace.id, owner_id)
    document = create_document(workspace.id, owner_id, folder.id)

    assert {:ok, created} =
             Sharing.create_share(
               folder,
               owner_id,
               with_test_share_security_artifacts(
                 folder,
                 owner_id,
                 create_folder_share_attrs([document])
               )
             )

    participant_material = share_participant_material()
    {encryption_public_key, _encryption_private_key} = :crypto.generate_key(:ecdh, :x25519)

    assert {:ok, bootstrapped} =
             bootstrap_share_participant(
               created,
               share_participant_bootstrap_attrs(
                 "Guest User",
                 participant_material,
                 encryption_public_key
               )
             )

    bootstrapped = authorize_bootstrapped_participant!(created, bootstrapped)

    assert {:ok, _reply, socket} =
             subscribe_and_join(
               share_socket(created, bootstrapped),
               RefMDWeb.DocumentChannel,
               "document:#{document.id}",
               join_params(
                 document.id,
                 created.share.id,
                 bootstrapped.participant.principal_id,
                 bootstrapped.participant.device_id,
                 participant_material.private,
                 bootstrapped.session
               )
             )

    assert_push "document", _payload

    channel_pid = socket.channel_pid
    monitor_ref = Process.monitor(channel_pid)

    assert {:ok, _result} =
             Sharing.update_share_exclusions(
               folder.id,
               created.share.id,
               with_test_share_management_append(
                 created.share,
                 "share_exclusion_changed",
                 %{"add" => [document.id]}
               )
             )

    assert_push "unauthorized", %{}
    assert_receive {:DOWN, ^monitor_ref, :process, ^channel_pid, _reason}
  end

  test "view share participant cannot send ephemeral messages" do
    owner_id = create_user("owner-channel-share-ephemeral@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Share Channel Workspace")
    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)
    Process.put(:workspace_pin_bootstrap_hash, test_workspace_pin_bootstrap_hash!(workspace.id))
    folder = create_folder(workspace.id, owner_id)
    document = create_document(workspace.id, owner_id, folder.id)

    assert {:ok, created} =
             Sharing.create_share(
               folder,
               owner_id,
               with_test_share_security_artifacts(
                 folder,
                 owner_id,
                 create_folder_share_attrs([document])
               )
             )

    participant_material = share_participant_material()
    {encryption_public_key, _encryption_private_key} = :crypto.generate_key(:ecdh, :x25519)

    assert {:ok, bootstrapped} =
             bootstrap_share_participant(
               created,
               share_participant_bootstrap_attrs(
                 "Guest User",
                 participant_material,
                 encryption_public_key
               )
             )

    bootstrapped = authorize_bootstrapped_participant!(created, bootstrapped)

    assert {:ok, _reply, socket} =
             subscribe_and_join(
               share_socket(created, bootstrapped),
               RefMDWeb.DocumentChannel,
               "document:#{document.id}",
               join_params(
                 document.id,
                 created.share.id,
                 bootstrapped.participant.principal_id,
                 bootstrapped.participant.device_id,
                 participant_material.private,
                 bootstrapped.session
               )
             )

    assert_push "document", _payload

    ref =
      Phoenix.ChannelTest.push(
        socket,
        "ephemeral",
        strict_channel_payload(
          signed_ephemeral_payload(
            document.id,
            bootstrapped.participant.device_id,
            participant_material.public,
            participant_material.private,
            created.share.id,
            bootstrapped.participant.principal_id
          )
        )
      )

    assert_reply ref, :error, %{reason: "permission_denied"}
  end

  test "edit share participant ephemeral messages reject stale authority and overdue DEKs" do
    owner_id = create_user("owner-channel-share-stale-ephemeral@example.com")

    {:ok, workspace} =
      Workspaces.create_default_workspace(owner_id, "Share Stale Ephemeral Workspace")

    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)
    Process.put(:workspace_pin_bootstrap_hash, test_workspace_pin_bootstrap_hash!(workspace.id))
    folder = create_folder(workspace.id, owner_id)
    document = create_document(workspace.id, owner_id, folder.id)

    assert {:ok, created} =
             Sharing.create_share(
               folder,
               owner_id,
               with_test_share_security_artifacts(
                 folder,
                 owner_id,
                 create_folder_share_attrs([document], permission: "edit")
               )
             )

    participant_material = share_participant_material()
    {encryption_public_key, _encryption_private_key} = :crypto.generate_key(:ecdh, :x25519)

    assert {:ok, bootstrapped} =
             bootstrap_share_participant(
               created,
               share_participant_bootstrap_attrs(
                 "Edit Guest",
                 participant_material,
                 encryption_public_key
               )
             )

    bootstrapped = authorize_bootstrapped_participant!(created, bootstrapped)

    assert {:ok, _reply, socket} =
             subscribe_and_join(
               share_socket(created, bootstrapped),
               RefMDWeb.DocumentChannel,
               "document:#{document.id}",
               join_params(
                 document.id,
                 created.share.id,
                 bootstrapped.participant.principal_id,
                 bootstrapped.participant.device_id,
                 participant_material.private,
                 bootstrapped.session
               )
             )

    assert_push "document", _payload

    ref =
      Phoenix.ChannelTest.push(
        socket,
        "ephemeral",
        strict_channel_payload(
          signed_ephemeral_payload(
            document.id,
            bootstrapped.participant.device_id,
            participant_material.public,
            participant_material.private,
            created.share.id,
            bootstrapped.participant.principal_id,
            stale_head: true
          )
        )
      )

    assert_reply ref, :error, %{reason: "ephemeral_workspace_head_mismatch"}

    document
    |> Ecto.Changeset.change(dek_rotation_due_at: DateTime.add(DateTime.utc_now(), -1, :second))
    |> Repo.update!()

    overdue_ref =
      Phoenix.ChannelTest.push(
        socket,
        "ephemeral",
        strict_channel_payload(
          signed_ephemeral_payload(
            document.id,
            bootstrapped.participant.device_id,
            participant_material.public,
            participant_material.private,
            created.share.id,
            bootstrapped.participant.principal_id
          )
        )
      )

    assert_reply overdue_ref, :error, %{reason: "key_rotation_required"}
  end

  test "edit share participant durable update fails closed without workspace admission" do
    owner_id = create_user("owner-channel-share-update@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Share Update Workspace")
    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)
    Process.put(:workspace_pin_bootstrap_hash, test_workspace_pin_bootstrap_hash!(workspace.id))
    folder = create_folder(workspace.id, owner_id)
    document = create_document(workspace.id, owner_id, folder.id)

    assert {:ok, created} =
             Sharing.create_share(
               folder,
               owner_id,
               with_test_share_security_artifacts(
                 folder,
                 owner_id,
                 create_folder_share_attrs([document], permission: "edit")
               )
             )

    participant_material = share_participant_material()
    {encryption_public_key, _encryption_private_key} = :crypto.generate_key(:ecdh, :x25519)

    assert {:ok, bootstrapped} =
             bootstrap_share_participant(
               created,
               share_participant_bootstrap_attrs(
                 "Edit Guest",
                 participant_material,
                 encryption_public_key
               )
             )

    bootstrapped = authorize_bootstrapped_participant!(created, bootstrapped)

    snapshot_id =
      create_active_snapshot(document.id, owner_id)

    assert {:ok, _reply, socket} =
             subscribe_and_join(
               share_socket(created, bootstrapped),
               RefMDWeb.DocumentChannel,
               "document:#{document.id}",
               join_params(
                 document.id,
                 created.share.id,
                 bootstrapped.participant.principal_id,
                 bootstrapped.participant.device_id,
                 participant_material.private,
                 bootstrapped.session
               )
             )

    assert_push "document", _payload

    ref =
      Phoenix.ChannelTest.push(
        socket,
        "update",
        strict_channel_payload(
          signed_update_payload(
            document.id,
            created.share.id,
            bootstrapped.participant.device_id,
            participant_material.public,
            participant_material.private,
            bootstrapped.participant.principal_id,
            snapshot_id
          )
        )
      )

    assert_reply ref, :error, %{reason: "missing_admission"}

    assert Repo.aggregate(
             from(u in DocumentUpdate, where: u.document_id == ^document.id),
             :count
           ) == 0

    refute Repo.get_by(DocumentSignerKey,
             document_id: document.id,
             signing_key_id: Signature.compute_signing_key_id!(participant_material.public)
           )
  end

  test "edit share participant oversized update marker fails closed without serializer crash" do
    owner_id = create_user("owner-channel-share-oversized-update@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Share Oversized Update")
    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)
    Process.put(:workspace_pin_bootstrap_hash, test_workspace_pin_bootstrap_hash!(workspace.id))
    folder = create_folder(workspace.id, owner_id)
    document = create_document(workspace.id, owner_id, folder.id)

    assert {:ok, created} =
             Sharing.create_share(
               folder,
               owner_id,
               with_test_share_security_artifacts(
                 folder,
                 owner_id,
                 create_folder_share_attrs([document], permission: "edit")
               )
             )

    participant_material = share_participant_material()
    {encryption_public_key, _encryption_private_key} = :crypto.generate_key(:ecdh, :x25519)

    assert {:ok, bootstrapped} =
             bootstrap_share_participant(
               created,
               share_participant_bootstrap_attrs(
                 "Edit Oversized Guest",
                 participant_material,
                 encryption_public_key
               )
             )

    bootstrapped = authorize_bootstrapped_participant!(created, bootstrapped)

    assert {:ok, _reply, socket} =
             subscribe_and_join(
               share_socket(created, bootstrapped),
               RefMDWeb.DocumentChannel,
               "document:#{document.id}",
               join_params(
                 document.id,
                 created.share.id,
                 bootstrapped.participant.principal_id,
                 bootstrapped.participant.device_id,
                 participant_material.private,
                 bootstrapped.session
               )
             )

    assert_push "document", _payload

    Phoenix.ChannelTest.push(socket, "update", %{
      "_refmd_strict_json_error" => "document_update_payload_too_large"
    })

    assert_push "update-save-failed", %{
      reason: "document_update_payload_too_large",
      requiresNewSnapshot: false
    }

    refute_receive %Phoenix.Socket.Broadcast{
                     event: "phx_error",
                     topic: "document:" <> _
                   },
                   100

    assert Repo.aggregate(
             from(u in DocumentUpdate, where: u.document_id == ^document.id),
             :count
           ) == 0
  end

  test "edit share participant durable snapshot fails closed without workspace admission" do
    owner_id = create_user("owner-channel-share-snapshot@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Share Snapshot Workspace")
    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)
    Process.put(:workspace_pin_bootstrap_hash, test_workspace_pin_bootstrap_hash!(workspace.id))
    folder = create_folder(workspace.id, owner_id)
    document = create_document(workspace.id, owner_id, folder.id)

    assert {:ok, created} =
             Sharing.create_share(
               folder,
               owner_id,
               with_test_share_security_artifacts(
                 folder,
                 owner_id,
                 create_folder_share_attrs([document], permission: "edit")
               )
             )

    participant_material = share_participant_material()
    {encryption_public_key, _encryption_private_key} = :crypto.generate_key(:ecdh, :x25519)

    assert {:ok, bootstrapped} =
             bootstrap_share_participant(
               created,
               share_participant_bootstrap_attrs(
                 "Edit Snapshot Guest",
                 participant_material,
                 encryption_public_key
               )
             )

    bootstrapped = authorize_bootstrapped_participant!(created, bootstrapped)

    assert {:ok, _reply, socket} =
             subscribe_and_join(
               share_socket(created, bootstrapped),
               RefMDWeb.DocumentChannel,
               "document:#{document.id}",
               join_params(
                 document.id,
                 created.share.id,
                 bootstrapped.participant.principal_id,
                 bootstrapped.participant.device_id,
                 participant_material.private,
                 bootstrapped.session
               )
             )

    assert_push "document", _payload

    ref =
      Phoenix.ChannelTest.push(
        socket,
        "snapshot",
        strict_channel_payload(
          snapshot_payload_without_admission(
            document.id,
            created.share.id,
            bootstrapped.participant.device_id,
            participant_material.public,
            participant_material.private,
            bootstrapped.participant.principal_id
          )
        )
      )

    assert_reply ref, :error, %{reason: "missing_admission"}

    assert Repo.aggregate(
             from(s in DocumentSnapshot,
               where:
                 s.document_id == ^document.id and
                   s.owner_id == ^bootstrapped.participant.device_id
             ),
             :count
           ) == 0
  end

  test "document update persistence preserves semantic verifier failures" do
    owner_id = create_user("owner-update-semantic@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Update Semantic Workspace")
    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)
    document = create_document(workspace.id, owner_id, nil)
    snapshot_id = create_active_snapshot(document.id, owner_id)
    signer = Process.get({:test_workspace_signer_material, workspace.id})
    ensure_workspace_signer_device!(workspace.id, owner_id, signer)

    attrs =
      workspace_update_attrs(
        document,
        owner_id,
        signer,
        snapshot_id,
        Ecto.UUID.generate()
      )

    assert {:error, :document_admission_workspace_mismatch} =
             Documents.save_update(document.id, owner_id, attrs)
  end

  test "document update persistence rejects write session counter replay" do
    owner_id = create_user("owner-update-counter-replay@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Update Counter Workspace")
    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)
    document = create_document(workspace.id, owner_id, nil)
    snapshot_id = create_active_snapshot(document.id, owner_id)
    signer = Process.get({:test_workspace_signer_material, workspace.id})
    ensure_workspace_signer_device!(workspace.id, owner_id, signer)

    first =
      workspace_write_session_update_attrs(document, owner_id, signer, snapshot_id, workspace.id,
        clock: 0,
        write_session_counter: 1
      )

    assert {:ok, %{clock: 0}} = Documents.save_update(document.id, owner_id, first)

    replay =
      workspace_write_session_update_attrs(document, owner_id, signer, snapshot_id, workspace.id,
        admission: first.admission,
        clock: 1,
        write_session_counter: 1
      )

    assert {:error, :write_session_invalid} = Documents.save_update(document.id, owner_id, replay)

    next =
      workspace_write_session_update_attrs(document, owner_id, signer, snapshot_id, workspace.id,
        admission: first.admission,
        clock: 1,
        write_session_counter: 2
      )

    assert {:ok, %{clock: 1}} = Documents.save_update(document.id, owner_id, next)
  end

  test "document update persistence accepts write session after unrelated workspace head movement" do
    owner_id = create_user("owner-update-unrelated-head@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Unrelated Head Workspace")
    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)
    document = create_document(workspace.id, owner_id, nil)
    snapshot_id = create_active_snapshot(document.id, owner_id)
    signer = Process.get({:test_workspace_signer_material, workspace.id})
    ensure_workspace_signer_device!(workspace.id, owner_id, signer)

    first =
      workspace_write_session_update_attrs(document, owner_id, signer, snapshot_id, workspace.id,
        clock: 0,
        write_session_counter: 1
      )

    assert {:ok, %{clock: 0}} = Documents.save_update(document.id, owner_id, first)

    append_workspace_key_directory_event!(
      workspace.id,
      "suite_policy_changed",
      suite_policy_changed_body()
    )

    next =
      workspace_write_session_update_attrs(document, owner_id, signer, snapshot_id, workspace.id,
        admission: first.admission,
        clock: 1,
        write_session_counter: 2
      )

    assert {:ok, %{clock: 1}} = Documents.save_update(document.id, owner_id, next)
  end

  test "document update persistence rejects write session invalidated after session head" do
    owner_id = create_user("owner-update-session-invalidated@example.com")

    {:ok, workspace} =
      Workspaces.create_default_workspace(owner_id, "Invalidated Session Workspace")

    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)
    document = create_document(workspace.id, owner_id, nil)
    snapshot_id = create_active_snapshot(document.id, owner_id)
    signer = Process.get({:test_workspace_signer_material, workspace.id})
    ensure_workspace_signer_device!(workspace.id, owner_id, signer)

    first =
      workspace_write_session_update_attrs(document, owner_id, signer, snapshot_id, workspace.id,
        clock: 0,
        write_session_counter: 1
      )

    assert {:ok, %{clock: 0}} = Documents.save_update(document.id, owner_id, first)

    append_workspace_key_directory_event!(
      workspace.id,
      "signing_key_revoked",
      fn sequence ->
        %{
          "key_id" => first.signing_key_id,
          "reason" => "test",
          "revoked_at_event_sequence" => sequence
        }
      end
    )

    invalidated =
      workspace_write_session_update_attrs(document, owner_id, signer, snapshot_id, workspace.id,
        admission: first.admission,
        clock: 1,
        write_session_counter: 2
      )

    assert {:error, :write_session_invalid} =
             Documents.save_update(document.id, owner_id, invalidated)
  end

  test "document update persistence rejects write session invalidated by document write state" do
    owner_id = create_user("owner-update-document-state-invalidated@example.com")

    {:ok, workspace} =
      Workspaces.create_default_workspace(owner_id, "Document State Invalidated Workspace")

    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)
    document = create_document(workspace.id, owner_id, nil)
    snapshot_id = create_active_snapshot(document.id, owner_id)
    signer = Process.get({:test_workspace_signer_material, workspace.id})
    ensure_workspace_signer_device!(workspace.id, owner_id, signer)

    first =
      workspace_write_session_update_attrs(document, owner_id, signer, snapshot_id, workspace.id,
        clock: 0,
        write_session_counter: 1
      )

    assert {:ok, %{clock: 0}} = Documents.save_update(document.id, owner_id, first)

    append_workspace_key_directory_event!(
      workspace.id,
      "document_write_state_changed",
      fn sequence, previous_hash ->
        %{
          "document_id" => document.id,
          "event_type" => "document_write_state_changed",
          "issued_at_ms" => System.system_time(:millisecond),
          "previous_workspace_event_hash" => previous_hash,
          "previous_workspace_event_sequence" => sequence - 1,
          "previous_write_state" => "writable",
          "reason" => "archive",
          "workspace_id" => workspace.id,
          "write_state" => "archived"
        }
      end
    )

    invalidated =
      workspace_write_session_update_attrs(document, owner_id, signer, snapshot_id, workspace.id,
        admission: first.admission,
        clock: 1,
        write_session_counter: 2
      )

    assert {:error, :write_session_invalid} =
             Documents.save_update(document.id, owner_id, invalidated)
  end

  test "document update persistence rejects future-issued write sessions" do
    owner_id = create_user("owner-update-future-session@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Future Session Workspace")
    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)
    document = create_document(workspace.id, owner_id, nil)
    snapshot_id = create_active_snapshot(document.id, owner_id)
    signer = Process.get({:test_workspace_signer_material, workspace.id})
    ensure_workspace_signer_device!(workspace.id, owner_id, signer)

    attrs =
      workspace_write_session_update_attrs(document, owner_id, signer, snapshot_id, workspace.id,
        clock: 0,
        issued_at_ms: System.system_time(:millisecond) + 86_400_000,
        write_session_counter: 1
      )

    assert {:error, :write_session_invalid} = Documents.save_update(document.id, owner_id, attrs)
  end

  test "document update persistence rejects expired write sessions with typed reason" do
    owner_id = create_user("owner-update-expired-session@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Expired Session Workspace")
    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)
    document = create_document(workspace.id, owner_id, nil)
    snapshot_id = create_active_snapshot(document.id, owner_id)
    signer = Process.get({:test_workspace_signer_material, workspace.id})
    ensure_workspace_signer_device!(workspace.id, owner_id, signer)
    issued_at_ms = System.system_time(:millisecond) - 60_000

    attrs =
      workspace_write_session_update_attrs(document, owner_id, signer, snapshot_id, workspace.id,
        clock: 0,
        expires_at_ms: issued_at_ms + 30_000,
        issued_at_ms: issued_at_ms,
        write_session_counter: 1
      )

    assert {:error, :write_session_expired} = Documents.save_update(document.id, owner_id, attrs)
  end

  test "document update persistence rejects malformed write session body" do
    owner_id = create_user("owner-update-malformed-session@example.com")

    {:ok, workspace} =
      Workspaces.create_default_workspace(owner_id, "Malformed Session Workspace")

    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)
    document = create_document(workspace.id, owner_id, nil)
    snapshot_id = create_active_snapshot(document.id, owner_id)
    signer = Process.get({:test_workspace_signer_material, workspace.id})
    ensure_workspace_signer_device!(workspace.id, owner_id, signer)

    attrs =
      workspace_write_session_update_attrs(document, owner_id, signer, snapshot_id, workspace.id,
        clock: 0,
        write_session_counter: 1
      )
      |> update_write_session_body(&Map.delete(&1, "session_nonce"))

    assert {:error, :admission_invalid} = Documents.save_update(document.id, owner_id, attrs)
  end

  test "document update persistence rejects write session authority mismatches" do
    owner_id = create_user("owner-update-authority-session@example.com")

    {:ok, workspace} =
      Workspaces.create_default_workspace(owner_id, "Authority Session Workspace")

    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)
    document = create_document(workspace.id, owner_id, nil)
    snapshot_id = create_active_snapshot(document.id, owner_id)
    signer = Process.get({:test_workspace_signer_material, workspace.id})
    ensure_workspace_signer_device!(workspace.id, owner_id, signer)

    attrs =
      workspace_write_session_update_attrs(document, owner_id, signer, snapshot_id, workspace.id,
        clock: 0,
        write_session_counter: 1
      )
      |> update_write_session_body(fn body ->
        %{body | "authority_scope_id" => Ecto.UUID.generate()}
      end)

    assert {:error, :write_session_invalid} = Documents.save_update(document.id, owner_id, attrs)
  end

  test "document write session admission rejects overlong lifetimes" do
    owner_id = create_user("owner-update-overlong-session@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Overlong Session Workspace")
    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)
    document = create_document(workspace.id, owner_id, nil)
    snapshot_id = create_active_snapshot(document.id, owner_id)
    signer = Process.get({:test_workspace_signer_material, workspace.id})
    ensure_workspace_signer_device!(workspace.id, owner_id, signer)
    issued_at_ms = System.system_time(:millisecond) - 1_000

    assert_raise ArgumentError, "expires_at_ms_invalid", fn ->
      workspace_write_session_update_attrs(document, owner_id, signer, snapshot_id, workspace.id,
        clock: 0,
        expires_at_ms: issued_at_ms + 60_001,
        issued_at_ms: issued_at_ms,
        write_session_counter: 1
      )
    end
  end

  test "write session broadcast and cache use server-normalized admission" do
    owner_id = create_user("owner-write-session-normalized@example.com")

    {:ok, workspace} =
      Workspaces.create_default_workspace(owner_id, "Write Session Normalized Workspace")

    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)
    document = create_document(workspace.id, owner_id, nil)
    snapshot_id = create_active_snapshot(document.id, owner_id)
    signer = Process.get({:test_workspace_signer_material, workspace.id})
    ensure_workspace_signer_device!(workspace.id, owner_id, signer)
    device = ensure_test_user_rrp_key_directory!(owner_id, Repo.get!(Device, signer.device_id))

    {:ok, session, _token} = Auth.create_session(owner_id, %{device_id: device.id})

    assert {:ok, _reply, socket_a} =
             subscribe_and_join(
               user_socket(owner_id, session),
               RefMDWeb.DocumentChannel,
               "document:#{document.id}",
               user_join_params(document.id, owner_id, device, signer.signing_private, session)
             )

    assert_push "document", _payload

    assert {:ok, _reply, _socket_b} =
             subscribe_and_join(
               user_socket(owner_id, session),
               RefMDWeb.DocumentChannel,
               "document:#{document.id}",
               user_join_params(document.id, owner_id, device, signer.signing_private, session)
             )

    assert_push "document", _payload

    append_workspace_key_directory_event!(
      workspace.id,
      "suite_policy_changed",
      suite_policy_changed_body()
    )

    append_workspace_key_directory_event!(
      workspace.id,
      "suite_policy_changed",
      suite_policy_changed_body()
    )

    attrs =
      workspace_write_session_update_attrs(
        document,
        owner_id,
        signer,
        snapshot_id,
        workspace.id,
        clock: 0,
        write_session_counter: 1
      )

    previous_checkpoint = KeyDirectory.current_checkpoint("workspace", workspace.id)

    client_admission =
      attrs.admission
      |> Map.put("workspaceKeyDirectoryCheckpointAncestry", [
        %{
          "payload" => previous_checkpoint.payload,
          "signatures" => previous_checkpoint.signatures,
          "clientSentinel" => true
        }
      ])
      |> Map.put(
        "workspaceKeyDirectoryEventAncestry",
        attrs.admission["workspaceKeyDirectoryEvents"]
      )

    ref =
      Phoenix.ChannelTest.push(
        socket_a,
        "write-session",
        strict_channel_payload(%{
          "admission" => client_admission,
          "publicData" => write_session_public_data(attrs.public_data)
        })
      )

    assert_reply ref, :ok, %{writeSessionEventHash: write_session_event_hash}, 1_000

    assert_push "write-session", pushed
    refute admission_has_client_sentinel?(payload_admission(pushed))

    assert [
             %{
               admission: cached_admission,
               publicData: %{"writeSessionEventHash" => ^write_session_event_hash}
             }
           ] = Documents.active_write_sessions(document.id)

    refute admission_has_client_sentinel?(cached_admission)

    append_workspace_key_directory_event!(
      workspace.id,
      "suite_policy_changed",
      suite_policy_changed_body()
    )

    append_workspace_key_directory_event!(
      workspace.id,
      "suite_policy_changed",
      suite_policy_changed_body()
    )

    latest_after_session = KeyDirectory.current_checkpoint("workspace", workspace.id)

    assert {:ok, _reply, _socket_c} =
             subscribe_and_join(
               user_socket(owner_id, session),
               RefMDWeb.DocumentChannel,
               "document:#{document.id}",
               user_join_params(document.id, owner_id, device, signer.signing_private, session,
                 workspace_pin_checkpoint: latest_after_session
               )
             )

    assert_push "document", _payload
    assert_push "write-session", active_pushed
    active_admission = payload_admission(active_pushed)
    refute admission_has_client_sentinel?(active_admission)

    active_checkpoint_sequence =
      get_in(active_admission, ["workspaceKeyDirectoryCheckpoint", "payload", "sequence"])

    active_event_head_sequence =
      get_in(active_admission, [
        "workspaceKeyDirectoryCheckpoint",
        "payload",
        "covered_event_head",
        "head_sequence"
      ])

    checkpoint_ancestry_sequences = checkpoint_ancestry_sequences(active_admission)
    event_ancestry_sequences = event_ancestry_sequences(active_admission)

    assert latest_after_session.sequence > active_checkpoint_sequence
    assert checkpoint_ancestry_sequences == [active_checkpoint_sequence - 1]
    refute latest_after_session.sequence in checkpoint_ancestry_sequences
    assert event_ancestry_sequences == [active_event_head_sequence]
    refute latest_after_session.covered_event_head_sequence in event_ancestry_sequences
  end

  test "initial bootstrap snapshot admission uses supplied workspace pin anchor" do
    owner_id = create_user("owner-bootstrap-bounded-admission@example.com")

    {:ok, workspace} =
      Workspaces.create_default_workspace(owner_id, "Bootstrap Bounded Admission Workspace")

    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)

    append_workspace_key_directory_event!(
      workspace.id,
      "suite_policy_changed",
      suite_policy_changed_body()
    )

    stale_checkpoint = KeyDirectory.current_checkpoint("workspace", workspace.id)

    append_workspace_key_directory_event!(
      workspace.id,
      "suite_policy_changed",
      suite_policy_changed_body()
    )

    document = create_document(workspace.id, owner_id, nil)
    create_active_snapshot(document.id, owner_id)

    append_workspace_key_directory_event!(
      workspace.id,
      "suite_policy_changed",
      suite_policy_changed_body()
    )

    signer = Process.get({:test_workspace_signer_material, workspace.id})
    ensure_workspace_signer_device!(workspace.id, owner_id, signer)
    device = ensure_test_user_rrp_key_directory!(owner_id, Repo.get!(Device, signer.device_id))
    {:ok, session, _token} = Auth.create_session(owner_id, %{device_id: device.id})

    assert {:ok, _reply, _socket} =
             subscribe_and_join(
               user_socket(owner_id, session),
               RefMDWeb.DocumentChannel,
               "document:#{document.id}",
               user_join_params(document.id, owner_id, device, signer.signing_private, session,
                 workspace_pin_checkpoint: stale_checkpoint
               )
             )

    assert_push "document", pushed
    snapshot = Map.fetch!(pushed, :snapshot)
    admission = Map.fetch!(snapshot, :admission)

    candidate_sequence =
      get_in(admission, ["workspaceKeyDirectoryCheckpoint", "payload", "sequence"])

    assert checkpoint_ancestry_sequences(admission) ==
             Enum.to_list(stale_checkpoint.sequence..(candidate_sequence - 1))

    assert first_checkpoint_ancestry_sequence(admission) == stale_checkpoint.sequence
  end

  test "document snapshot persistence preserves semantic verifier failures" do
    owner_id = create_user("owner-snapshot-semantic@example.com")

    {:ok, workspace} =
      Workspaces.create_default_workspace(owner_id, "Snapshot Semantic Workspace")

    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)
    document = create_document(workspace.id, owner_id, nil)
    signer = Process.get({:test_workspace_signer_material, workspace.id})
    ensure_workspace_signer_device!(workspace.id, owner_id, signer)

    attrs =
      workspace_snapshot_attrs(
        document,
        owner_id,
        signer,
        Ecto.UUID.generate()
      )

    assert {:error, :document_admission_workspace_mismatch, nil} =
             Documents.save_snapshot(document.id, owner_id, attrs)
  end

  test "successful rotation snapshot retains obsolete secrets until deletion proof" do
    %{
      document: document,
      owner_id: owner_id,
      signer: signer,
      old_update: old_update,
      expired_share_key: expired_share_key
    } =
      setup_rotation_snapshot_gc("rotation-snapshot-gc-success@example.com")

    attrs = rotation_snapshot_attrs(document, owner_id, signer)

    assert {:ok, %{snapshot_id: snapshot_id}} =
             Documents.save_snapshot(document.id, owner_id, attrs)

    assert Repo.get!(DocumentUpdate, old_update.id)
    assert Repo.get_by(DocumentEncryptedKey, document_id: document.id, key_version: 1)
    assert Repo.get_by(DocumentEncryptedKey, document_id: document.id, key_version: 2)
    assert Repo.get_by(ShareKeyHistory, document_id: document.id, key_version: 1)
    assert Repo.get!(ShareKey, expired_share_key.share_id)

    rotated = Repo.get!(Document, document.id)
    assert rotated.active_snapshot_id == snapshot_id
    assert rotated.needs_rotation_snapshot
  end

  test "failed rotation snapshot preserves obsolete updates and DEKs" do
    %{
      document: document,
      owner_id: owner_id,
      signer: signer,
      old_update: old_update,
      expired_share_key: expired_share_key
    } =
      setup_rotation_snapshot_gc("rotation-snapshot-gc-failure@example.com")

    attrs = rotation_snapshot_attrs(document, owner_id, signer)
    invalid_attrs = %{attrs | parent_proof_hash: Hash.blake3_base64url("invalid-parent")}

    assert {:error, :parent_mismatch, _recovery} =
             Documents.save_snapshot(document.id, owner_id, invalid_attrs)

    assert Repo.get!(DocumentUpdate, old_update.id)
    assert Repo.get_by(DocumentEncryptedKey, document_id: document.id, key_version: 1)
    assert Repo.get_by(DocumentEncryptedKey, document_id: document.id, key_version: 2)
    assert Repo.get_by(ShareKeyHistory, document_id: document.id, key_version: 1)
    assert Repo.get!(ShareKey, expired_share_key.share_id)
    assert Repo.get!(Document, document.id).needs_rotation_snapshot
  end

  test "document update and snapshot reject future DEK versions" do
    owner_id = create_user("future-document-dek-version@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Future DEK Version")
    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)
    document = create_document(workspace.id, owner_id, nil)
    signer = Process.get({:test_workspace_signer_material, workspace.id})
    ensure_workspace_signer_device!(workspace.id, owner_id, signer)

    snapshot_id = create_active_snapshot(document.id, owner_id)

    update_attrs =
      document
      |> workspace_update_attrs(owner_id, signer, snapshot_id, workspace.id)
      |> Map.put(:key_version, 2)
      |> Map.put(:signature_verified, true)

    assert {:error, :key_version_too_old} =
             Documents.save_update(document.id, owner_id, update_attrs)

    snapshot_attrs =
      document
      |> Repo.reload!()
      |> rotation_snapshot_attrs(owner_id, signer)
      |> Map.put(:key_version, 3)

    assert {:error, :key_version_too_old, _recovery} =
             Documents.save_snapshot(document.id, owner_id, snapshot_attrs)
  end

  defp workspace_update_attrs(document, actor_user_id, signer, ref_snapshot_id, workspace_id) do
    ciphertext = <<13, 13, 13>>
    nonce = :crypto.strong_rand_bytes(24)
    ciphertext_b64 = Base.url_encode64(ciphertext, padding: false)
    nonce_b64 = Base.url_encode64(nonce, padding: false)
    timestamp = System.system_time(:millisecond)
    signing_key_id = Signature.compute_signing_key_id!(signer.signing_public)
    key_checkpoint_hash = Hash.blake3_base64url("checkpoint")

    public_data = %{
      "docId" => document.id,
      "signingKeyId" => signing_key_id,
      "clock" => 0,
      "keyVersion" => 1,
      "timestamp" => timestamp,
      "refSnapshotId" => ref_snapshot_id,
      "ownerKind" => "device",
      "ownerId" => signer.device_id,
      "authorityKind" => "workspace_device",
      "authorityId" => workspace_id,
      "authorityContextKey" => signing_key_id,
      "authorityScopeId" => workspace_id,
      "authorityPermissionVersion" => 1,
      "keyCheckpointSequence" => 1,
      "keyCheckpointHash" => key_checkpoint_hash,
      "minDekVersion" => 1,
      "writeSessionEventHash" => Hash.blake3_base64url("write-session"),
      "writeSessionId" => Hash.blake3_base64url("write-session-id"),
      "writeSessionCounter" => 1,
      "updateHash" =>
        RefMD.Crypto.compute_update_hash(%{
          "clock" => 0,
          "signing_key_id" => signing_key_id,
          "document_id" => document.id,
          "encrypted_content" => ciphertext_b64,
          "key_version" => 1,
          "nonce" => nonce_b64,
          "ref_snapshot_id" => ref_snapshot_id,
          "timestamp" => timestamp
        })
    }

    boundary = test_authority_boundary(public_data, "document_write_session_admitted")

    %{
      ref_snapshot_id: ref_snapshot_id,
      workspace_id: workspace_id,
      clock: 0,
      signing_key_id: signing_key_id,
      update_data: ciphertext,
      nonce: nonce,
      key_version: 1,
      update_hash: public_data["updateHash"],
      hybrid_signature:
        sign_document_update(
          signer.signing_private,
          actor_user_id,
          signer.device_id,
          ciphertext_b64,
          nonce_b64,
          public_data,
          boundary,
          workspace_id
        ),
      public_data: public_data,
      owner_kind: "device",
      owner_id: signer.device_id,
      authority_kind: "workspace_device",
      authority_id: workspace_id,
      authority_context_key: signing_key_id,
      authority_scope_id: workspace_id,
      authority_permission_version: 1,
      key_checkpoint_sequence: 1,
      key_checkpoint_hash: key_checkpoint_hash,
      write_session_counter: 1,
      timestamp: timestamp,
      admission: minimal_document_operation_admission("document_write_session_admitted", boundary)
    }
  end

  defp workspace_write_session_update_attrs(
         document,
         actor_user_id,
         signer,
         ref_snapshot_id,
         workspace_id,
         opts
       ) do
    ciphertext = Keyword.get(opts, :ciphertext, <<13, 13, 13>>)
    nonce = Keyword.get(opts, :nonce, :crypto.strong_rand_bytes(24))
    clock = Keyword.fetch!(opts, :clock)
    write_session_counter = Keyword.fetch!(opts, :write_session_counter)
    ciphertext_b64 = Base.url_encode64(ciphertext, padding: false)
    nonce_b64 = Base.url_encode64(nonce, padding: false)
    timestamp = Keyword.get(opts, :timestamp, System.system_time(:millisecond))
    signing_key_id = Signature.compute_signing_key_id!(signer.signing_public)
    issued_at_ms = Keyword.get(opts, :issued_at_ms, timestamp - 1_000)
    expires_at_ms = Keyword.get(opts, :expires_at_ms, issued_at_ms + 60_000)
    session_id = Keyword.get(opts, :write_session_id, Hash.blake3_base64url("write-session-id"))

    admission =
      Keyword.get_lazy(opts, :admission, fn ->
        document_operation_admission(%{
          workspace_id: workspace_id,
          document_id: document.id,
          user_id: actor_user_id,
          device_id: signer.device_id,
          private_material: signer.signing_private,
          event_type: "document_write_session_admitted",
          key_version: 1,
          min_dek_version: 1,
          session_id: session_id,
          issued_at_ms: issued_at_ms,
          expires_at_ms: expires_at_ms,
          max_update_count: 8,
          max_ciphertext_bytes: 1024
        })
      end)

    [admission_event] = admission["workspaceKeyDirectoryEvents"]
    admission_payload = admission_event["payload"]
    admission_body = admission_payload["body"]
    write_session_event_hash = KeyDirectory.event_hash(admission_payload)

    public_data = %{
      "docId" => document.id,
      "signingKeyId" => signing_key_id,
      "clock" => clock,
      "keyVersion" => 1,
      "timestamp" => timestamp,
      "refSnapshotId" => ref_snapshot_id,
      "ownerKind" => "device",
      "ownerId" => signer.device_id,
      "authorityKind" => "workspace_device",
      "authorityId" => workspace_id,
      "authorityContextKey" => signing_key_id,
      "authorityScopeId" => workspace_id,
      "authorityPermissionVersion" => 1,
      "keyCheckpointSequence" => admission_payload["actor"]["key_checkpoint_sequence"],
      "keyCheckpointHash" => admission_payload["actor"]["key_checkpoint_hash"],
      "minDekVersion" => 1,
      "writeSessionEventHash" => write_session_event_hash,
      "writeSessionId" => admission_body["session_id"],
      "writeSessionCounter" => write_session_counter,
      "updateHash" =>
        RefMD.Crypto.compute_update_hash(%{
          "clock" => clock,
          "signing_key_id" => signing_key_id,
          "document_id" => document.id,
          "encrypted_content" => ciphertext_b64,
          "key_version" => 1,
          "nonce" => nonce_b64,
          "ref_snapshot_id" => ref_snapshot_id,
          "timestamp" => timestamp
        })
    }

    boundary = %{
      "document_permission_proof_hash" => admission_body["document_permission_proof_hash"],
      "min_dek_version" => admission_body["min_dek_version"],
      "write_session_counter" => write_session_counter,
      "write_session_event_hash" => write_session_event_hash,
      "write_session_id" => admission_body["session_id"]
    }

    %{
      ref_snapshot_id: ref_snapshot_id,
      workspace_id: workspace_id,
      clock: clock,
      signing_key_id: signing_key_id,
      update_data: ciphertext,
      nonce: nonce,
      key_version: 1,
      update_hash: public_data["updateHash"],
      hybrid_signature:
        sign_document_update(
          signer.signing_private,
          actor_user_id,
          signer.device_id,
          ciphertext_b64,
          nonce_b64,
          public_data,
          boundary,
          workspace_id
        ),
      public_data: public_data,
      owner_kind: "device",
      owner_id: signer.device_id,
      authority_kind: "workspace_device",
      authority_id: workspace_id,
      authority_context_key: signing_key_id,
      authority_scope_id: workspace_id,
      authority_permission_version: 1,
      key_checkpoint_sequence: admission_payload["actor"]["key_checkpoint_sequence"],
      key_checkpoint_hash: admission_payload["actor"]["key_checkpoint_hash"],
      write_session_counter: write_session_counter,
      timestamp: timestamp,
      admission: admission,
      admission_actor: admission_payload["actor"]
    }
  end

  defp update_write_session_body(attrs, fun) do
    admission = Map.fetch!(attrs, :admission)
    [event] = Map.fetch!(admission, "workspaceKeyDirectoryEvents")
    body = get_in(event, ["payload", "body"])
    event = put_in(event, ["payload", "body"], fun.(body))

    Map.put(attrs, :admission, %{admission | "workspaceKeyDirectoryEvents" => [event]})
  end

  defp admission_has_client_sentinel?(admission) do
    admission
    |> Map.get("workspaceKeyDirectoryCheckpointAncestry", [])
    |> Enum.any?(&Map.has_key?(&1, "clientSentinel"))
  end

  defp payload_admission(payload) do
    Map.get(payload, :admission) || Map.get(payload, "admission")
  end

  defp first_checkpoint_ancestry_sequence(admission) do
    admission
    |> Map.fetch!("workspaceKeyDirectoryCheckpointAncestry")
    |> List.first()
    |> get_in(["payload", "sequence"])
  end

  defp checkpoint_ancestry_sequences(admission) do
    admission
    |> Map.fetch!("workspaceKeyDirectoryCheckpointAncestry")
    |> Enum.map(&get_in(&1, ["payload", "sequence"]))
  end

  defp event_ancestry_sequences(admission) do
    admission
    |> Map.fetch!("workspaceKeyDirectoryEventAncestry")
    |> Enum.map(&get_in(&1, ["payload", "sequence"]))
  end

  defp write_session_public_data(public_data) do
    Map.take(public_data, [
      "docId",
      "signingKeyId",
      "keyVersion",
      "minDekVersion",
      "writeSessionEventHash",
      "writeSessionId",
      "writeSessionCounter",
      "ownerKind",
      "ownerId",
      "authorityKind",
      "authorityId",
      "authorityContextKey",
      "authorityScopeId",
      "authorityPermissionVersion",
      "keyCheckpointSequence",
      "keyCheckpointHash"
    ])
  end

  defp append_workspace_key_directory_event!(workspace_id, event_type, body_or_fun) do
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)
    next_sequence = checkpoint.covered_event_head_sequence + 1

    body =
      cond do
        is_function(body_or_fun, 2) ->
          body_or_fun.(next_sequence, checkpoint.covered_event_head_hash)

        is_function(body_or_fun, 1) ->
          body_or_fun.(next_sequence)

        true ->
          body_or_fun
      end

    event_payload =
      KeyDirectory.build_event_payload!(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => next_sequence,
        "event_type" => event_type,
        "actor" => %{"signer_kind" => "device"},
        "previous_event_hash" => checkpoint.covered_event_head_hash,
        "body" => body
      })

    Repo.insert!(
      Event.changeset(%Event{}, %{
        scope_kind: "workspace",
        scope_id: workspace_id,
        sequence: event_payload["sequence"],
        event_type: event_payload["event_type"],
        event_hash: KeyDirectory.event_hash(event_payload),
        event_body_hash: KeyDirectory.event_body_hash(event_payload["body"]),
        previous_event_hash: event_payload["previous_event_hash"],
        payload: event_payload,
        signatures: [%{"test" => "post-session-head"}]
      })
    )

    checkpoint_payload =
      checkpoint.payload
      |> Map.put("sequence", checkpoint.sequence + 1)
      |> Map.put(
        "issued_at",
        DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601()
      )
      |> Map.put("previous_checkpoint_hash", checkpoint.checkpoint_hash)
      |> Map.put("covered_event_head", %{
        "head_sequence" => event_payload["sequence"],
        "head_hash" => KeyDirectory.event_hash(event_payload)
      })
      |> KeyDirectory.build_checkpoint_payload!()

    Repo.insert!(
      Checkpoint.changeset(%Checkpoint{}, %{
        scope_kind: "workspace",
        scope_id: workspace_id,
        sequence: checkpoint_payload["sequence"],
        checkpoint_hash: KeyDirectory.checkpoint_hash(checkpoint_payload),
        previous_checkpoint_hash: Map.get(checkpoint_payload, "previous_checkpoint_hash"),
        covered_event_head_sequence: checkpoint_payload["covered_event_head"]["head_sequence"],
        covered_event_head_hash: checkpoint_payload["covered_event_head"]["head_hash"],
        suite_policy_version: checkpoint_payload["suite_policy_version"],
        min_suite_rank: checkpoint_payload["min_suite_rank"],
        allowed_suite_ids_hash: Suite.canonical_allowed_suite_ids_hash(checkpoint_payload),
        payload: checkpoint_payload,
        signatures: [%{"test" => "post-session-head"}]
      })
    )
  end

  defp suite_policy_changed_body do
    policy = Suite.current_suite_policy()

    %{
      "suite_policy_version" => policy["suite_policy_version"],
      "min_suite_rank" => policy["min_suite_rank"],
      "allowed_suite_ids" => policy["allowed_suite_ids"]
    }
  end

  defp ensure_workspace_signer_device!(workspace_id, user_id, signer) do
    if is_nil(Repo.get(Device, signer.device_id)) do
      signing_key_id = Signature.compute_signing_key_id!(signer.signing_public)
      checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)
      now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

      Repo.insert!(%Device{
        id: signer.device_id,
        user_id: user_id,
        name: "Workspace signer",
        device_type: "browser",
        hybrid_encryption_public_key_material: signer.encryption_public,
        encryption_key_id: signer.encryption_key_id,
        hybrid_signing_public_key_material: signer.signing_public,
        signing_key_id: signing_key_id,
        approval_signature: %{},
        approval_signature_surface: "genesis_device_bootstrap",
        approval_proof: %{},
        key_checkpoint_sequence: checkpoint.sequence,
        key_checkpoint_hash: checkpoint.checkpoint_hash,
        client_nonce: <<0::128>>,
        last_seen_at: now,
        created_at: now
      })
    end
  end

  defp workspace_snapshot_attrs(document, actor_user_id, signer, workspace_id) do
    ciphertext = <<14, 14, 14>>
    nonce = :crypto.strong_rand_bytes(24)
    ciphertext_b64 = Base.url_encode64(ciphertext, padding: false)
    nonce_b64 = Base.url_encode64(nonce, padding: false)
    signing_key_id = Signature.compute_signing_key_id!(signer.signing_public)
    key_checkpoint_hash = Hash.blake3_base64url("checkpoint")

    public_data = %{
      "docId" => document.id,
      "signingKeyId" => signing_key_id,
      "snapshotId" => Ecto.UUID.generate(),
      "keyVersion" => 1,
      "parentSnapshotId" => "GENESIS",
      "parentProofHash" => "GENESIS",
      "parentSnapshotUpdateClocks" => %{},
      "ownerKind" => "device",
      "ownerId" => signer.device_id,
      "authorityKind" => "workspace_device",
      "authorityId" => workspace_id,
      "authorityContextKey" => signing_key_id,
      "authorityScopeId" => workspace_id,
      "authorityPermissionVersion" => 1,
      "keyCheckpointSequence" => 1,
      "keyCheckpointHash" => key_checkpoint_hash
    }

    boundary = test_authority_boundary(public_data, "document_snapshot_accepted")

    %{
      snapshot_id: public_data["snapshotId"],
      parent_snapshot_id: nil,
      workspace_id: workspace_id,
      data: ciphertext,
      nonce: nonce,
      key_version: 1,
      hybrid_signature:
        sign_document_snapshot(
          signer.signing_private,
          actor_user_id,
          signer.device_id,
          ciphertext_b64,
          nonce_b64,
          public_data,
          boundary,
          workspace_id
        ),
      public_data: public_data,
      parent_proof_hash: "GENESIS",
      parent_snapshot_update_clocks: %{},
      created_by_signing_key_id: signing_key_id,
      owner_kind: "device",
      owner_id: signer.device_id,
      authority_kind: "workspace_device",
      authority_id: workspace_id,
      authority_context_key: signing_key_id,
      authority_scope_id: workspace_id,
      authority_permission_version: 1,
      key_checkpoint_sequence: 1,
      key_checkpoint_hash: key_checkpoint_hash,
      admission: minimal_document_operation_admission("document_snapshot_accepted", boundary)
    }
  end

  defp setup_rotation_snapshot_gc(email) do
    owner_id = create_user(email)
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Rotation Snapshot GC")
    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)
    document = create_document(workspace.id, owner_id, nil)
    signer = Process.get({:test_workspace_signer_material, workspace.id})
    ensure_workspace_signer_device!(workspace.id, owner_id, signer)

    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    share_attrs = %{
      "id" => Ecto.UUID.generate(),
      "scope" => "document",
      "share_slug" => share_slug,
      "token_prefix" => String.slice(share_slug, 0, 4),
      "permission" => "edit",
      "password_protected" => false,
      "authorization_public_key_material" =>
        share_capability_public_key_material_for_slug(open_admission_key(), share_slug),
      "share_capability_secret_commitment" => open_share_capability_secret_commitment(),
      "authenticated_workspace_pin_bootstrap_hash" =>
        test_workspace_pin_bootstrap_hash!(workspace.id),
      "key_version" => 1,
      "encrypted_dek" => :crypto.strong_rand_bytes(48),
      "nonce" => :crypto.strong_rand_bytes(24),
      "max_views" => 9_007_199_254_740_991,
      "expires_event_sequence" => 9_007_199_254_740_991
    }

    assert {:ok, created_share} =
             Sharing.create_share(
               document,
               owner_id,
               with_test_share_security_artifacts(document, owner_id, share_attrs)
             )

    expired_share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    expired_share_attrs =
      Map.merge(share_attrs, %{
        "id" => Ecto.UUID.generate(),
        "share_slug" => expired_share_slug,
        "token_prefix" => String.slice(expired_share_slug, 0, 4),
        "authorization_public_key_material" =>
          share_capability_public_key_material_for_slug(
            open_admission_key(),
            expired_share_slug
          )
      })

    assert {:ok, expired_share} =
             Sharing.create_share(
               document,
               owner_id,
               with_test_share_security_artifacts(document, owner_id, expired_share_attrs)
             )

    expired_share.share
    |> Ecto.Changeset.change(expires_event_sequence: 1)
    |> Repo.update!()

    expired_share_key = Repo.get!(ShareKey, expired_share.share.id)

    snapshot_id = create_active_snapshot(document.id, owner_id)
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    document =
      document
      |> Ecto.Changeset.change(
        min_dek_version: 2,
        needs_rotation_snapshot: true,
        dek_rotation_due_at: DateTime.add(now, 3600, :second)
      )
      |> Repo.update!()
      |> Repo.reload!()

    for {version, active?} <- [{1, false}, {2, true}] do
      Repo.insert!(%DocumentEncryptedKey{
        document_id: document.id,
        key_version: version,
        kek_version: 1,
        encrypted_dek: :crypto.strong_rand_bytes(48),
        nonce: :crypto.strong_rand_bytes(24),
        is_active: active?,
        created_at: now
      })
    end

    share_key = Repo.get!(ShareKey, created_share.share.id)

    Repo.insert!(%ShareKeyHistory{
      share_id: share_key.share_id,
      document_id: share_key.document_id,
      key_version: share_key.key_version,
      encrypted_dek: share_key.encrypted_dek,
      nonce: share_key.nonce,
      created_at: now
    })

    share_key
    |> ShareKey.changeset(%{
      key_version: 2,
      encrypted_dek: :crypto.strong_rand_bytes(48),
      nonce: :crypto.strong_rand_bytes(24)
    })
    |> Repo.update!()

    signing_key_id = Signature.compute_signing_key_id!(signer.signing_public)

    old_update =
      Repo.insert!(%DocumentUpdate{
        document_id: document.id,
        snapshot_id: snapshot_id,
        clock: 0,
        version: 1,
        signing_key_id: signing_key_id,
        update_data: <<1, 2, 3>>,
        nonce: :crypto.strong_rand_bytes(24),
        key_version: 1,
        update_hash: Hash.blake3_base64url("old-update-#{document.id}"),
        hybrid_signature: %{},
        owner_kind: "device",
        owner_id: signer.device_id,
        authority_kind: "workspace_device",
        authority_id: workspace.id,
        authority_context_key: signing_key_id,
        authority_scope_id: workspace.id,
        authority_permission_version: 1,
        key_checkpoint_sequence: 1,
        key_checkpoint_hash: Hash.blake3_base64url("checkpoint"),
        admission_event_hash: Hash.blake3_base64url("admission-#{document.id}"),
        write_session_counter: 1,
        timestamp: System.system_time(:millisecond),
        created_at: now
      })

    %{
      document: document,
      owner_id: owner_id,
      signer: signer,
      old_update: old_update,
      expired_share_key: expired_share_key
    }
  end

  defp rotation_snapshot_attrs(document, actor_user_id, signer) do
    parent = Repo.get!(DocumentSnapshot, document.active_snapshot_id)
    ciphertext = <<14, 14, 14>>
    nonce = :crypto.strong_rand_bytes(24)
    ciphertext_b64 = Base.url_encode64(ciphertext, padding: false)
    nonce_b64 = Base.url_encode64(nonce, padding: false)
    signing_key_id = Signature.compute_signing_key_id!(signer.signing_public)
    checkpoint = KeyDirectory.current_checkpoint("workspace", document.workspace_id)

    parent_proof_hash = ProofChain.compute_snapshot_proof_link_hash(parent)

    public_data = %{
      "docId" => document.id,
      "signingKeyId" => signing_key_id,
      "snapshotId" => Ecto.UUID.generate(),
      "keyVersion" => 2,
      "parentSnapshotId" => parent.id,
      "parentProofHash" => parent_proof_hash,
      "parentSnapshotUpdateClocks" => parent.clocks,
      "ownerKind" => "device",
      "ownerId" => signer.device_id,
      "authorityKind" => "workspace_device",
      "authorityId" => document.workspace_id,
      "authorityContextKey" => signing_key_id,
      "authorityScopeId" => document.workspace_id,
      "authorityPermissionVersion" => 1,
      "keyCheckpointSequence" => checkpoint.sequence,
      "keyCheckpointHash" => checkpoint.checkpoint_hash
    }

    boundary = test_authority_boundary(public_data, "document_snapshot_accepted")

    signature =
      sign_document_snapshot(
        signer.signing_private,
        actor_user_id,
        signer.device_id,
        ciphertext_b64,
        nonce_b64,
        public_data,
        boundary,
        document.workspace_id
      )

    admission =
      document_operation_admission(%{
        workspace_id: document.workspace_id,
        document_id: document.id,
        user_id: actor_user_id,
        device_id: signer.device_id,
        private_material: signer.signing_private,
        event_type: "document_snapshot_accepted",
        operation_hash: Blake3.hash_base64url(ciphertext),
        signature: signature,
        key_version: 2,
        min_dek_version: 2
      })

    [admission_event] = admission["workspaceKeyDirectoryEvents"]
    admission_actor = admission_event["payload"]["actor"]

    %{
      snapshot_id: public_data["snapshotId"],
      parent_snapshot_id: parent.id,
      workspace_id: document.workspace_id,
      data: ciphertext,
      nonce: nonce,
      key_version: 2,
      hybrid_signature: signature,
      signature_verified: true,
      public_data: public_data,
      parent_proof_hash: parent_proof_hash,
      parent_snapshot_update_clocks: parent.clocks,
      created_by_signing_key_id: signing_key_id,
      owner_kind: "device",
      owner_id: signer.device_id,
      authority_kind: "workspace_device",
      authority_id: document.workspace_id,
      authority_context_key: signing_key_id,
      authority_scope_id: document.workspace_id,
      authority_permission_version: 1,
      key_checkpoint_sequence: checkpoint.sequence,
      key_checkpoint_hash: checkpoint.checkpoint_hash,
      admission_actor: admission_actor,
      admission: admission
    }
  end

  defp minimal_document_operation_admission(event_type, boundary) do
    %{
      "workspaceKeyDirectoryEvents" => [
        %{
          "payload" => %{
            "event_type" => event_type,
            "body" => boundary
          }
        }
      ]
    }
  end
end
