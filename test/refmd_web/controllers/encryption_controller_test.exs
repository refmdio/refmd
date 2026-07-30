defmodule RefMDWeb.EncryptionControllerTest do
  use RefMDWeb.ConnCase, async: true

  import Ecto.Query, only: [where: 3]

  alias RefMD.Auth
  alias RefMD.Encryption.KeyDirectory
  alias RefMD.Encryption.WorkspaceEncryptedKey
  alias RefMD.Repo
  alias RefMD.Users.User
  alias RefMD.Workspaces
  alias RefMD.Workspaces.{WorkspaceDeviceWipeRequirement, WorkspaceMember}

  defp create_user(email, opts \\ []) do
    user_id = Ecto.UUID.generate()

    Repo.insert!(%User{
      id: user_id,
      email: email,
      name: email,
      account_type: Keyword.get(opts, :account_type, "registered")
    })

    user_id
  end

  defp create_device(user_id) do
    device_id = Ecto.UUID.generate()
    keys = hybrid_device_material(device_id)
    {ecdh_public_key, _ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)
    encryption = hybrid_encryption_public_key_material("device", device_id, ecdh_public_key)
    client_nonce = :crypto.strong_rand_bytes(16)

    {:ok, device} =
      RefMD.Devices.create_device(%{
        id: device_id,
        user_id: user_id,
        name: "Browser",
        device_type: "browser",
        hybrid_encryption_public_key_material: encryption.public,
        encryption_key_id: encryption.encryption_key_id,
        hybrid_signing_public_key_material: keys.public,
        signing_key_id: keys.signing_key_id,
        approval_signature:
          genesis_device_bootstrap_signature(
            user_id,
            device_id,
            keys.public,
            ecdh_public_key,
            encryption.public,
            client_nonce
          ),
        approval_signature_surface: "genesis_device_bootstrap",
        approval_proof:
          genesis_device_approval_proof(
            user_id,
            device_id,
            keys.public,
            ecdh_public_key,
            encryption.public,
            client_nonce
          ),
        client_nonce: client_nonce
      })

    %{device: device, signing_private_key: keys.private}
  end

  defp authed_conn(conn, user_id, device) do
    {:ok, session, token} = Auth.create_session(user_id, %{device_id: device.id})

    conn
    |> put_req_header(
      "cookie",
      "__Host-refmd-session=#{Base.url_encode64(token, padding: false)}"
    )
    |> put_private(:test_session, session)
  end

  defp with_rrp_headers(conn, user_id, device, signing_private_key, method, path, body) do
    put_test_rrp_headers(conn, user_id, device, signing_private_key, method, path, body)
  end

  defp add_member(workspace_id, user_id, base_role) do
    role =
      workspace_id
      |> Workspaces.list_workspace_roles()
      |> Enum.find(&(&1.base_role == base_role))

    Repo.insert!(%WorkspaceMember{
      workspace_id: workspace_id,
      user_id: user_id,
      role_id: role.id,
      is_default: false,
      joined_at: DateTime.utc_now()
    })
  end

  defp owner_role_id(workspace_id) do
    workspace_id
    |> Workspaces.list_workspace_roles()
    |> Enum.find(&(&1.base_role == "owner"))
    |> Map.fetch!(:id)
  end

  defp require_workspace_wipe!(workspace_id, device_id, required_kek_version) do
    %WorkspaceDeviceWipeRequirement{}
    |> WorkspaceDeviceWipeRequirement.changeset(%{
      workspace_id: workspace_id,
      device_id: device_id,
      required_kek_version: required_kek_version,
      reason: "kek_rotation_deletion_proof_missing",
      required_at: DateTime.utc_now()
    })
    |> Repo.insert!()
  end

  defp insert_initial_workspace_key_directory!(workspace, owner_id, device, device_private) do
    identity_private = hybrid_signing_private_key_material("identity", owner_id)
    {identity_ecdh_public_key, _identity_ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)

    identity_encryption =
      hybrid_encryption_public_key_material("identity", owner_id, identity_ecdh_public_key)

    bootstrap =
      initial_key_directory_bootstrap(
        owner_id,
        workspace.id,
        owner_role_id(workspace.id),
        identity_private,
        identity_encryption.public,
        device_private,
        device.hybrid_encryption_public_key_material
      )

    Process.put(
      {:test_workspace_signer_material, workspace.id},
      %{
        user_id: owner_id,
        device_id: device.id,
        signing_private: device_private,
        signing_public: device.hybrid_signing_public_key_material
      }
    )

    KeyDirectory.insert_signed_initial_scope!(
      "workspace",
      workspace.id,
      bootstrap.workspace_events,
      bootstrap.workspace_checkpoint,
      checkpoint_signer_kind: "device"
    )
  end

  setup do
    owner_id = create_user("owner-encryption-controller@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Encryption Controller")
    %{workspace: workspace, owner_id: owner_id}
  end

  test "guest account cannot use owner membership for workspace device KEK writes", %{
    conn: conn,
    workspace: workspace,
    owner_id: owner_id
  } do
    guest_id = create_user("guest-encryption-controller@example.com", account_type: "guest")
    target_id = create_user("guest-sender-target@example.com")
    owner_device = create_device(owner_id)
    guest_device = create_device(guest_id)
    target_device = create_device(target_id)

    insert_initial_workspace_key_directory!(
      workspace,
      owner_id,
      owner_device.device,
      owner_device.signing_private_key
    )

    add_member(workspace.id, guest_id, "owner")
    add_member(workspace.id, target_id, "viewer")
    path = "/api/encryption/workspaces/#{workspace.id}/keys"

    body =
      workspace_device_kek_body(
        workspace.id,
        target_id,
        guest_device.device,
        target_device.device
      )

    conn =
      conn
      |> authed_conn(guest_id, guest_device.device)
      |> with_rrp_headers(
        guest_id,
        guest_device.device,
        guest_device.signing_private_key,
        "POST",
        path,
        body
      )
      |> post(path, test_json_body(body))

    assert json_response(conn, 403) == %{"error" => "forbidden"}
  end

  test "rejects non-admin sender for another user's workspace device KEK writes", %{
    conn: conn,
    workspace: workspace,
    owner_id: owner_id
  } do
    owner_device = create_device(owner_id)
    editor_id = create_user("editor-encryption-controller@example.com")
    target_id = create_user("target-encryption-controller@example.com")
    editor_device = create_device(editor_id)
    target_device = create_device(target_id)

    insert_initial_workspace_key_directory!(
      workspace,
      owner_id,
      owner_device.device,
      owner_device.signing_private_key
    )

    add_member(workspace.id, editor_id, "editor")
    add_member(workspace.id, target_id, "viewer")
    path = "/api/encryption/workspaces/#{workspace.id}/keys"

    body =
      workspace_device_kek_body(
        workspace.id,
        target_id,
        editor_device.device,
        target_device.device
      )

    conn =
      conn
      |> authed_conn(editor_id, editor_device.device)
      |> with_rrp_headers(
        editor_id,
        editor_device.device,
        editor_device.signing_private_key,
        "POST",
        path,
        body
      )
      |> post(path, test_json_body(body))

    assert json_response(conn, 403) == %{"error" => "forbidden"}
  end

  test "target wipe requirement does not block future KEK pre-provisioning", %{
    conn: conn,
    workspace: workspace,
    owner_id: owner_id
  } do
    workspace =
      workspace
      |> Ecto.Changeset.change(current_kek_version: 1, min_kek_version: 1)
      |> Repo.update!()

    target_user_id = create_user("wipe-target-encryption-controller@example.com")
    sender = create_device(owner_id)
    target = create_device(target_user_id)
    add_member(workspace.id, target_user_id, "viewer")

    insert_initial_workspace_key_directory!(
      workspace,
      owner_id,
      sender.device,
      sender.signing_private_key
    )

    append_test_workspace_member_device!(workspace.id, target_user_id, target.device)

    require_workspace_wipe!(workspace.id, target.device.id, 1)
    path = "/api/encryption/workspaces/#{workspace.id}/keys"

    body =
      signed_workspace_device_kek_request(
        workspace.id,
        sender.device,
        sender.signing_private_key,
        target.device,
        1
      )

    conn =
      conn
      |> authed_conn(owner_id, sender.device)
      |> with_rrp_headers(
        owner_id,
        sender.device,
        sender.signing_private_key,
        "POST",
        path,
        body
      )
      |> post(path, test_json_body(body))

    assert json_response(conn, 201) == %{"ok" => true}

    assert %WorkspaceEncryptedKey{key_version: 1, sender_device_id: sender_device_id} =
             Repo.get_by!(WorkspaceEncryptedKey,
               workspace_id: workspace.id,
               user_id: target_user_id,
               device_id: target.device.id,
               key_version: 1
             )

    assert sender_device_id == sender.device.id
    assert Workspaces.workspace_device_wipe_required?(workspace.id, target.device.id)
  end

  test "sender wipe requirement still blocks workspace KEK delivery", %{
    conn: conn,
    workspace: workspace,
    owner_id: owner_id
  } do
    workspace =
      workspace
      |> Ecto.Changeset.change(current_kek_version: 1, min_kek_version: 1)
      |> Repo.update!()

    target_user_id = create_user("sender-wipe-target-encryption-controller@example.com")
    sender = create_device(owner_id)
    target = create_device(target_user_id)
    add_member(workspace.id, target_user_id, "viewer")

    insert_initial_workspace_key_directory!(
      workspace,
      owner_id,
      sender.device,
      sender.signing_private_key
    )

    require_workspace_wipe!(workspace.id, sender.device.id, 1)
    path = "/api/encryption/workspaces/#{workspace.id}/keys"

    body =
      workspace_device_kek_body(workspace.id, target_user_id, sender.device, target.device)

    conn =
      conn
      |> authed_conn(owner_id, sender.device)
      |> with_rrp_headers(
        owner_id,
        sender.device,
        sender.signing_private_key,
        "POST",
        path,
        body
      )
      |> post(path, test_json_body(body))

    assert json_response(conn, 403) == %{"error" => "device_wipe_required"}
  end

  test "wipe-required device cannot retrieve pre-provisioned workspace keys", %{
    conn: conn,
    workspace: workspace,
    owner_id: owner_id
  } do
    device = create_device(owner_id)

    insert_initial_workspace_key_directory!(
      workspace,
      owner_id,
      device.device,
      device.signing_private_key
    )

    require_workspace_wipe!(workspace.id, device.device.id, 1)
    path = "/api/encryption/workspaces/#{workspace.id}/keys"
    query = URI.encode_query(%{"device_id" => device.device.id})

    conn =
      conn
      |> authed_conn(owner_id, device.device)
      |> put_test_rrp_headers(
        owner_id,
        device.device,
        device.signing_private_key,
        "GET",
        path,
        "",
        query
      )
      |> get(path <> "?" <> query)

    assert json_response(conn, 403) == %{"error" => "device_wipe_required"}
  end

  test "guest account cannot use a non-guest membership as member envelope authority", %{
    conn: conn,
    workspace: workspace,
    owner_id: owner_id
  } do
    guest_id = create_user("guest-member-envelope@example.com", account_type: "guest")
    owner_device = create_device(owner_id)
    guest_device = create_device(guest_id)

    insert_initial_workspace_key_directory!(
      workspace,
      owner_id,
      owner_device.device,
      owner_device.signing_private_key
    )

    add_member(workspace.id, guest_id, "owner")
    path = "/api/encryption/workspaces/#{workspace.id}/member-envelopes"
    body = current_workspace_key_directory_body(workspace.id) |> Map.put("envelopes", [])

    conn =
      conn
      |> authed_conn(guest_id, guest_device.device)
      |> with_rrp_headers(
        guest_id,
        guest_device.device,
        guest_device.signing_private_key,
        "POST",
        path,
        body
      )
      |> post(path, test_json_body(body))

    assert json_response(conn, 403) == %{"error" => "not_a_member"}
  end

  test "manual KEK rotation start requires a signed rotation_started key-directory event", %{
    conn: conn,
    workspace: workspace,
    owner_id: owner_id
  } do
    workspace =
      workspace
      |> Ecto.Changeset.change(current_kek_version: 1, min_kek_version: 1)
      |> Repo.update!()

    owner_device = create_device(owner_id)

    insert_initial_workspace_key_directory!(
      workspace,
      owner_id,
      owner_device.device,
      owner_device.signing_private_key
    )

    RefMD.Security.AuditEvent
    |> where(
      [event],
      event.chain_scope_kind == "workspace" and event.chain_scope_id == ^workspace.id
    )
    |> Repo.delete_all()

    install_signed_audit_genesis!("workspace", workspace.id, owner_id,
      signer_device_id: owner_device.device.id
    )

    path = "/api/encryption/workspaces/#{workspace.id}/kek-rotation/intent"
    current = current_workspace_key_directory_body(workspace.id)

    body = %{
      "old_key_version" => 1,
      "new_key_version" => 2,
      "reason" => "manual",
      "rotation_id" => Ecto.UUID.generate(),
      "events" => [],
      "checkpoint" => current["workspace_key_directory_checkpoint"]
    }

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "POST",
        path,
        body
      )
      |> post(path, test_json_body(body))

    assert %{"error" => "workspace_authority_mutation_candidate_invalid"} =
             json_response(conn, 422)

    refute Workspaces.get_workspace(workspace.id).needs_kek_rotation
  end

  defp workspace_device_kek_body(workspace_id, target_user_id, sender_device, target_device) do
    current_workspace_key_directory_body(workspace_id)
    |> Map.merge(%{
      "target_user_id" => target_user_id,
      "device_id" => target_device.id,
      "sender_device_id" => sender_device.id,
      "key_version" => 1,
      "is_active" => true
    })
    |> Map.merge(
      dummy_signed_pq_wrap_fields(
        "workspace_device_kek_wrap",
        workspace_id,
        target_user_id,
        sender_device,
        target_device
      )
    )
  end

  defp current_workspace_key_directory_body(workspace_id) do
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)

    %{
      "workspace_key_directory_events" => [],
      "workspace_key_directory_checkpoint" => %{
        "payload" => checkpoint.payload,
        "signatures" => checkpoint.signatures
      }
    }
  end

  defp dummy_signed_pq_wrap_fields(
         purpose,
         workspace_id,
         target_user_id,
         sender_device,
         target_device
       ) do
    signing_key_id = sender_device.signing_key_id
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)
    checkpoint_hash = checkpoint.checkpoint_hash
    transcript_hash = valid_hash()

    %{
      "protocol" => "refmd.signed-pq-hybrid-wrap",
      "protocol_version" => 1,
      "suite_id" =>
        "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65",
      "suite_rank" => 1000,
      "purpose" => purpose,
      "resource" => %{
        "workspace_id" => workspace_id,
        "target_user_id" => target_user_id,
        "target_device_id" => target_device.id,
        "kek_version" => 1
      },
      "sender" => %{
        "signer_kind" => "device",
        "user_id" => sender_device.user_id,
        "device_id" => sender_device.id,
        "signing_key_id" => signing_key_id,
        "key_scope_kind" => "workspace",
        "key_scope_id" => workspace_id,
        "key_checkpoint_sequence" => checkpoint.sequence,
        "key_checkpoint_hash" => checkpoint_hash
      },
      "recipient" => %{
        "recipient_kind" => "device",
        "user_id" => target_user_id,
        "device_id" => target_device.id,
        "encryption_key_id" => target_device.encryption_key_id,
        "key_scope_kind" => "workspace",
        "key_scope_id" => workspace_id,
        "key_checkpoint_sequence" => checkpoint.sequence,
        "key_checkpoint_hash" => checkpoint_hash
      },
      "event_scope" => %{"scope_kind" => "workspace", "scope_id" => workspace_id},
      "event" => %{
        "wrap_event_sequence" => checkpoint.payload["covered_event_head"]["head_sequence"] + 1,
        "wrap_event_hash" => valid_hash(),
        "wrap_event_body_hash" => valid_hash()
      },
      "operation_checkpoint" => %{
        "checkpoint_sequence" => checkpoint.sequence,
        "checkpoint_hash" => checkpoint_hash,
        "covered_event_head_sequence" =>
          checkpoint.payload["covered_event_head"]["head_sequence"],
        "covered_event_head_hash" => checkpoint.payload["covered_event_head"]["head_hash"]
      },
      "hpke" => %{
        "mode" => "base",
        "kem_id" => 0x647A,
        "kdf_id" => 0x0001,
        "aead_id" => 0x0003,
        "enc" => valid_base64url(1120),
        "ciphertext" => valid_base64url(48)
      },
      "transcript_hash" => transcript_hash,
      "signature" => dummy_hybrid_signature(signing_key_id, transcript_hash)
    }
  end

  defp dummy_hybrid_signature(signing_key_id, transcript_hash) do
    %{
      "protocol" => "refmd.hybrid-signature",
      "version" => 1,
      "suite_id" => "refmd-v2-hybrid-signature-ed25519-mldsa65",
      "suite_rank" => 1000,
      "signing_key_id" => signing_key_id,
      "transcript_hash" => transcript_hash,
      "ed25519" => valid_base64url(64),
      "mldsa65" => valid_base64url(3309)
    }
  end

  defp valid_hash, do: valid_base64url(32)

  defp valid_base64url(bytes),
    do: :crypto.strong_rand_bytes(bytes) |> Base.url_encode64(padding: false)

  test "manual KEK rotation start appends rotation_started and marks workspace", %{
    conn: conn,
    workspace: workspace,
    owner_id: owner_id
  } do
    workspace =
      workspace
      |> Ecto.Changeset.change(current_kek_version: 1, min_kek_version: 1)
      |> Repo.update!()

    owner_device = create_device(owner_id)

    insert_initial_workspace_key_directory!(
      workspace,
      owner_id,
      owner_device.device,
      owner_device.signing_private_key
    )

    RefMD.Security.AuditEvent
    |> where(
      [event],
      event.chain_scope_kind == "workspace" and event.chain_scope_id == ^workspace.id
    )
    |> Repo.delete_all()

    install_signed_audit_genesis!("workspace", workspace.id, owner_id,
      signer_device_id: owner_device.device.id
    )

    body =
      kek_rotation_start_key_directory_append(
        workspace.id,
        owner_id,
        owner_device.device.id,
        owner_device.signing_private_key,
        workspace.current_kek_version,
        workspace.current_kek_version + 1
      )

    rotation_id = Ecto.UUID.generate()
    intent_path = "/api/encryption/workspaces/#{workspace.id}/kek-rotation/intent"

    intent_body = %{
      "old_key_version" => workspace.current_kek_version,
      "new_key_version" => workspace.current_kek_version + 1,
      "reason" => "manual",
      "rotation_id" => rotation_id,
      "events" => body["workspace_key_directory_events"],
      "checkpoint" => body["workspace_key_directory_checkpoint"]
    }

    intent_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "POST",
        intent_path,
        intent_body
      )
      |> post(intent_path, test_json_body(intent_body))

    intent = json_response(intent_conn, 200)

    command = %{
      "workspace_id" => workspace.id,
      "old_key_version" => workspace.current_kek_version,
      "new_key_version" => workspace.current_kek_version + 1,
      "reason" => "manual",
      "rotation_id" => rotation_id
    }

    authorization =
      workspace_authority_authorization!(
        intent,
        owner_device.signing_private_key,
        command
      )

    commit_path = "/api/encryption/workspaces/#{workspace.id}/kek-rotation"

    commit_conn =
      recycle(intent_conn)
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "POST",
        commit_path,
        authorization
      )
      |> post(commit_path, test_json_body(authorization))

    assert %{
             "event_type" => "workspace.kek.rotation_started",
             "status" => "committed",
             "workspace_id" => workspace_id
           } = json_response(commit_conn, 200)

    assert workspace_id == workspace.id
    assert Workspaces.get_workspace(workspace.id).needs_kek_rotation

    pin = KeyDirectory.current_pin("workspace", workspace.id)
    event = Repo.get_by!(RefMD.Encryption.KeyDirectory.Event, event_hash: pin.event_head_hash)

    assert event.event_type == "rotation_started"
    assert event.payload["body"]["old_key_version"] == workspace.current_kek_version
    assert event.payload["body"]["new_key_version"] == workspace.current_kek_version + 1
  end

  test "document keys can only be rewrapped to the pending KEK version", %{
    workspace: workspace,
    owner_id: owner_id
  } do
    workspace =
      workspace
      |> Ecto.Changeset.change(
        current_kek_version: 1,
        min_kek_version: 1,
        needs_kek_rotation: true,
        kek_rotation_initiator_user_id: owner_id
      )
      |> Repo.update!()

    document =
      Repo.insert!(%RefMD.Documents.Document{
        workspace_id: workspace.id,
        created_by: owner_id,
        slug: "rewrap-document",
        path: "rewrap-document",
        doc_type: "document",
        is_encrypted: true,
        title: "Untitled",
        encrypted_title: :crypto.strong_rand_bytes(32),
        encrypted_title_nonce: :crypto.strong_rand_bytes(24),
        encrypted_title_key_version: 1,
        created_at: DateTime.utc_now(),
        updated_at: DateTime.utc_now()
      })

    key =
      Repo.insert!(%RefMD.Encryption.DocumentEncryptedKey{
        document_id: document.id,
        key_version: 1,
        kek_version: 1,
        encrypted_dek: :crypto.strong_rand_bytes(48),
        nonce: :crypto.strong_rand_bytes(24),
        is_active: true,
        created_at: DateTime.utc_now()
      })

    replacement = %{
      encrypted_dek: :crypto.strong_rand_bytes(48),
      nonce: :crypto.strong_rand_bytes(24)
    }

    assert {:error, :kek_rotation_rewrap_not_allowed} =
             RefMD.Encryption.rewrap_document_key_for_kek_rotation(
               document.id,
               key.key_version,
               3,
               replacement
             )

    assert {:ok, rewrapped} =
             RefMD.Encryption.rewrap_document_key_for_kek_rotation(
               document.id,
               key.key_version,
               2,
               replacement
             )

    assert rewrapped.kek_version == 2
    assert rewrapped.encrypted_dek == replacement.encrypted_dek
    assert rewrapped.nonce == replacement.nonce
  end
end
