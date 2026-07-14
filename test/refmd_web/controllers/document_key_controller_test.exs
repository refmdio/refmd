defmodule RefMDWeb.DocumentKeyControllerTest do
  use RefMDWeb.ConnCase, async: true

  import Ecto.Query

  alias RefMD.Auth
  alias RefMD.Crypto.{Hash, Signature}
  alias RefMD.Devices
  alias RefMD.{Documents, Encryption, Sharing}

  alias RefMD.Documents.{
    DekRotation,
    DocumentDekRotationDeletionEvidence,
    DocumentDeviceWipeRequirement,
    DocumentSnapshot,
    DocumentUpdate
  }

  alias RefMD.Encryption.DocumentEncryptedKey
  alias RefMD.Repo
  alias RefMD.Sharing.{Share, ShareKey, ShareKeyHistory}
  alias RefMD.Users.User
  alias RefMD.Workspaces
  alias RefMD.Workspaces.KekRotation.DeletionProofs
  alias RefMD.Workspaces.Workspace

  defp create_user(email) do
    user_id = Ecto.UUID.generate()

    Repo.insert!(%User{
      id: user_id,
      email: email,
      name: email
    })

    user_id
  end

  defp create_workspace_actor_device(user_id) do
    material = Process.get({:test_workspace_actor_material, user_id})
    client_nonce = :crypto.strong_rand_bytes(16)

    {:ok, device} =
      Devices.create_device(%{
        id: material.device_id,
        user_id: user_id,
        name: "Browser",
        device_type: "browser",
        hybrid_encryption_public_key_material: material.encryption_public,
        encryption_key_id: material.encryption_key_id,
        hybrid_signing_public_key_material: material.signing_public,
        signing_key_id: Signature.compute_signing_key_id!(material.signing_public),
        approval_signature:
          genesis_device_bootstrap_signature(
            user_id,
            material.device_id,
            material.signing_public,
            material.x25519_public_key,
            material.encryption_public,
            client_nonce
          ),
        approval_signature_surface: "genesis_device_bootstrap",
        approval_proof:
          genesis_device_approval_proof(
            user_id,
            material.device_id,
            material.signing_public,
            material.x25519_public_key,
            material.encryption_public,
            client_nonce
          ),
        client_nonce: client_nonce
      })

    Process.put({:test_share_actor_device, user_id}, {device, material.signing_private})
    %{device: device, signing_private_key: material.signing_private}
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

  setup do
    owner_id = create_user("owner-document-key-controller@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Document Key Controller")
    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)
    owner_device = create_workspace_actor_device(owner_id)

    {:ok, document} =
      Documents.create_document(%{
        "workspace_id" => workspace.id,
        "created_by" => owner_id,
        "encrypted_title" => :crypto.strong_rand_bytes(48),
        "encrypted_title_nonce" => :crypto.strong_rand_bytes(24),
        "encrypted_title_key_version" => 1,
        "doc_type" => "document"
      })

    %{document: document, owner_device: owner_device, owner_id: owner_id, workspace: workspace}
  end

  test "DEK rotation requires and atomically switches every current document share wrap", %{
    document: document,
    owner_device: owner_device,
    owner_id: owner_id,
    workspace: workspace
  } do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    Repo.update_all(
      from(w in Workspace, where: w.id == ^workspace.id),
      set: [
        current_kek_version: 1,
        min_kek_version: 1,
        needs_kek_rotation: false,
        kek_rotation_due_at: DateTime.add(now, 3600, :second)
      ]
    )

    Repo.insert!(%DocumentEncryptedKey{
      document_id: document.id,
      key_version: 1,
      kek_version: 1,
      encrypted_dek: :crypto.strong_rand_bytes(48),
      nonce: :crypto.strong_rand_bytes(24),
      is_active: true,
      created_at: now
    })

    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
    old_share_wrap = :crypto.strong_rand_bytes(48)

    attrs = %{
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
      "encrypted_dek" => old_share_wrap,
      "nonce" => :crypto.strong_rand_bytes(24),
      "max_views" => 9_007_199_254_740_991,
      "expires_event_sequence" => 9_007_199_254_740_991
    }

    assert {:ok, created} =
             Sharing.create_share(
               document,
               owner_id,
               with_test_share_security_artifacts(document, owner_id, attrs)
             )

    Repo.update_all(
      from(d in RefMD.Documents.Document, where: d.id == ^document.id),
      set: [needs_dek_rotation: true, dek_rotation_reason: "manual"]
    )

    key_attrs = %{
      document_id: document.id,
      key_version: 2,
      kek_version: 1,
      encrypted_dek: :crypto.strong_rand_bytes(48),
      nonce: :crypto.strong_rand_bytes(24)
    }

    start =
      test_dek_rotation_start_key_directory_append(
        workspace.id,
        owner_id,
        document.id,
        1,
        2,
        "manual"
      )

    assert {:error, :incomplete_share_key_rotation} =
             Encryption.create_document_key_with_rotation(key_attrs, %{
               share_key_replacements: [],
               dek_rotation_start_events: start["workspace_key_directory_events"],
               dek_rotation_start_checkpoint: start["workspace_key_directory_checkpoint"]
             })

    assert Repo.get!(ShareKey, created.share.id).key_version == 1
    assert Documents.get_document!(document.id).min_dek_version == 1

    replacement = %{
      root_share_id: created.share.id,
      share_id: created.share.id,
      document_id: document.id,
      key_version: 2,
      encrypted_dek: :crypto.strong_rand_bytes(48),
      nonce: :crypto.strong_rand_bytes(24)
    }

    signed =
      with_test_share_scope_key_directory_append(
        created.share,
        %{
          "add_keys" => [],
          "replace_keys" => [replacement]
        },
        start["workspace_key_directory_checkpoint"]
      )

    assert {:ok, _key} =
             Encryption.create_document_key_with_rotation(key_attrs, %{
               share_key_replacements: [replacement],
               dek_rotation_start_events: start["workspace_key_directory_events"],
               dek_rotation_start_checkpoint: start["workspace_key_directory_checkpoint"],
               workspace_key_directory_events: signed["workspace_key_directory_events"],
               workspace_key_directory_checkpoint: signed["workspace_key_directory_checkpoint"]
             })

    current = Repo.get!(ShareKey, created.share.id)
    assert current.key_version == 2
    assert current.encrypted_dek == replacement.encrypted_dek
    assert Documents.get_document!(document.id).min_dek_version == 2

    assert %ShareKeyHistory{key_version: 1, encrypted_dek: ^old_share_wrap} =
             Repo.get_by(ShareKeyHistory, share_id: created.share.id, key_version: 1)

    Repo.update_all(
      from(d in RefMD.Documents.Document, where: d.id == ^document.id),
      set: [encrypted_title_key_version: 2]
    )

    snapshot_id = Ecto.UUID.generate()

    Repo.insert!(%DocumentSnapshot{
      id: snapshot_id,
      document_id: document.id,
      latest_version: 1,
      data: <<1, 2, 3>>,
      nonce: :crypto.strong_rand_bytes(24),
      key_version: 2,
      hybrid_signature: %{},
      ciphertext_hash: "snapshot-ciphertext",
      snapshot_signature_hash: "snapshot-signature",
      snapshot_admission_event_hash: "snapshot-admission",
      proof_chain_hash: "snapshot-proof",
      clocks: %{},
      parent_snapshot_update_clocks: %{},
      parent_proof_hash: "GENESIS",
      created_by_signing_key_id: owner_device.device.signing_key_id,
      owner_kind: "device",
      owner_id: owner_device.device.id,
      authority_kind: "workspace_device",
      authority_id: workspace.id,
      authority_context_key: owner_device.device.signing_key_id,
      authority_scope_id: workspace.id,
      authority_permission_version: 1,
      key_checkpoint_sequence: 1,
      key_checkpoint_hash: "checkpoint"
    })

    Repo.update_all(
      from(d in RefMD.Documents.Document, where: d.id == ^document.id),
      set: [active_snapshot_id: snapshot_id]
    )

    Repo.insert!(%DocumentUpdate{
      document_id: document.id,
      snapshot_id: snapshot_id,
      clock: 1,
      version: 1,
      signing_key_id: owner_device.device.signing_key_id,
      update_data: <<4, 5, 6>>,
      nonce: :crypto.strong_rand_bytes(24),
      key_version: 1,
      update_hash: "old-update",
      hybrid_signature: %{},
      owner_kind: "device",
      owner_id: owner_device.device.id,
      authority_kind: "workspace_device",
      authority_id: workspace.id,
      authority_context_key: owner_device.device.signing_key_id,
      authority_scope_id: workspace.id,
      authority_permission_version: 1,
      key_checkpoint_sequence: 1,
      key_checkpoint_hash: "checkpoint",
      admission_event_hash: "update-admission",
      write_session_counter: 1,
      timestamp: 1
    })

    assert {:ok, materials} = DekRotation.completion_materials(document.id, 2)

    completion =
      dek_rotation_complete_key_directory_append(
        workspace.id,
        document.id,
        owner_id,
        owner_device.device.id,
        owner_device.signing_private_key,
        materials,
        device_key_deletion_proofs: [],
        wipe_required_device_ids: [owner_device.device.id]
      )

    assert :ok =
             DekRotation.complete(
               document.id,
               2,
               completion["workspace_key_directory_events"],
               completion["workspace_key_directory_checkpoint"],
               completion["device_key_deletion_proofs"],
               completion["wipe_required_device_ids"]
             )

    refute Repo.get_by(DocumentEncryptedKey, document_id: document.id, key_version: 1)
    refute Repo.get_by(DocumentUpdate, document_id: document.id, key_version: 1)
    refute Documents.get_document!(document.id).needs_rotation_snapshot

    assert %DocumentDekRotationDeletionEvidence{old_key_version: 1} =
             Repo.one!(DocumentDekRotationDeletionEvidence)

    assert DekRotation.wipe_required?(document.id, owner_device.device.id)
    assert {:ok, requirement} = DekRotation.wipe_requirement(document.id, owner_device.device.id)

    proof =
      signed_document_dek_deletion_proof(
        workspace.id,
        document.id,
        owner_id,
        owner_device.device.id,
        owner_device.signing_private_key,
        1,
        requirement.rotation_completed_event_hash
      )

    invalid_proof = put_in(proof, ["payload", "scope_id"], Ecto.UUID.generate())

    assert {:error, :invalid_deletion_proof} =
             DekRotation.acknowledge_wipe(
               document.id,
               owner_device.device.id,
               invalid_proof
             )

    assert DekRotation.wipe_required?(document.id, owner_device.device.id)

    assert :ok = DekRotation.acknowledge_wipe(document.id, owner_device.device.id, proof)
    refute DekRotation.wipe_required?(document.id, owner_device.device.id)
  end

  test "DEK rotation atomically switches a folder descendant share wrap", %{
    document: document,
    owner_id: owner_id,
    workspace: workspace
  } do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    Repo.update_all(
      from(w in Workspace, where: w.id == ^workspace.id),
      set: [
        current_kek_version: 1,
        min_kek_version: 1,
        needs_kek_rotation: false,
        kek_rotation_due_at: DateTime.add(now, 3600, :second)
      ]
    )

    Repo.insert!(%DocumentEncryptedKey{
      document_id: document.id,
      key_version: 1,
      kek_version: 1,
      encrypted_dek: :crypto.strong_rand_bytes(48),
      nonce: :crypto.strong_rand_bytes(24),
      is_active: true,
      created_at: now
    })

    {:ok, folder} =
      Documents.create_document(%{
        "workspace_id" => workspace.id,
        "created_by" => owner_id,
        "title" => "Folder",
        "doc_type" => "folder"
      })

    document
    |> Ecto.Changeset.change(parent_id: folder.id)
    |> Repo.update!()

    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
    child_share_id = Ecto.UUID.generate()
    old_child_wrap = :crypto.strong_rand_bytes(48)

    folder_attrs = %{
      "id" => Ecto.UUID.generate(),
      "scope" => "folder",
      "share_slug" => share_slug,
      "token_prefix" => String.slice(share_slug, 0, 4),
      "permission" => "edit",
      "password_protected" => false,
      "authorization_public_key_material" =>
        share_capability_public_key_material_for_slug(open_admission_key(), share_slug),
      "share_capability_secret_commitment" => open_share_capability_secret_commitment(),
      "authenticated_workspace_pin_bootstrap_hash" =>
        test_workspace_pin_bootstrap_hash!(workspace.id),
      "key_version" => folder.min_dek_version,
      "encrypted_dek" => :crypto.strong_rand_bytes(48),
      "nonce" => :crypto.strong_rand_bytes(24),
      "share_keys" => [
        %{
          "share_id" => child_share_id,
          "document_id" => document.id,
          "key_version" => document.min_dek_version,
          "encrypted_dek" => old_child_wrap,
          "nonce" => :crypto.strong_rand_bytes(24)
        }
      ],
      "max_views" => 9_007_199_254_740_991,
      "expires_event_sequence" => 9_007_199_254_740_991
    }

    assert {:ok, created} =
             Sharing.create_share(
               folder,
               owner_id,
               with_test_share_security_artifacts(folder, owner_id, folder_attrs)
             )

    Repo.update_all(
      from(d in RefMD.Documents.Document, where: d.id == ^document.id),
      set: [needs_dek_rotation: true, dek_rotation_reason: "manual"]
    )

    assert %Share{id: ^child_share_id, parent_share_id: parent_share_id} =
             Repo.get!(Share, child_share_id)

    assert parent_share_id == created.share.id

    key_attrs = %{
      document_id: document.id,
      key_version: 2,
      kek_version: 1,
      encrypted_dek: :crypto.strong_rand_bytes(48),
      nonce: :crypto.strong_rand_bytes(24)
    }

    start =
      test_dek_rotation_start_key_directory_append(
        workspace.id,
        owner_id,
        document.id,
        1,
        2,
        "manual"
      )

    assert {:error, :incomplete_share_key_rotation} =
             Encryption.create_document_key_with_rotation(key_attrs, %{
               share_key_replacements: [],
               dek_rotation_start_events: start["workspace_key_directory_events"],
               dek_rotation_start_checkpoint: start["workspace_key_directory_checkpoint"]
             })

    replacement = %{
      root_share_id: created.share.id,
      share_id: child_share_id,
      document_id: document.id,
      key_version: 2,
      encrypted_dek: :crypto.strong_rand_bytes(48),
      nonce: :crypto.strong_rand_bytes(24)
    }

    signed =
      with_test_share_scope_key_directory_append(
        created.share,
        %{
          "add_keys" => [],
          "replace_keys" => [replacement]
        },
        start["workspace_key_directory_checkpoint"]
      )

    assert {:ok, _key} =
             Encryption.create_document_key_with_rotation(key_attrs, %{
               share_key_replacements: [replacement],
               dek_rotation_start_events: start["workspace_key_directory_events"],
               dek_rotation_start_checkpoint: start["workspace_key_directory_checkpoint"],
               workspace_key_directory_events: signed["workspace_key_directory_events"],
               workspace_key_directory_checkpoint: signed["workspace_key_directory_checkpoint"]
             })

    assert %ShareKey{key_version: 2, encrypted_dek: encrypted_dek} =
             Repo.get!(ShareKey, child_share_id)

    assert encrypted_dek == replacement.encrypted_dek

    assert %ShareKeyHistory{key_version: 1, encrypted_dek: ^old_child_wrap} =
             Repo.get_by(ShareKeyHistory, share_id: child_share_id, key_version: 1)
  end

  test "DEK wipe acknowledgements process every outstanding rotation in order", %{
    document: document,
    owner_device: owner_device,
    owner_id: owner_id,
    workspace: workspace
  } do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    for {old_version, required_version} <- [{1, 2}, {2, 3}] do
      completed_hash = Hash.blake3_base64url("completed-#{old_version}")

      %DocumentDekRotationDeletionEvidence{}
      |> DocumentDekRotationDeletionEvidence.changeset(%{
        old_key_deleted_event_hash: Hash.blake3_base64url("deleted-#{old_version}"),
        document_id: document.id,
        workspace_id: workspace.id,
        rotation_kind: "dek",
        scope_kind: "document",
        scope_id: document.id,
        old_key_version: old_version,
        completion_manifest: %{"old_key_version" => old_version},
        deletion_manifest: %{
          "rotation_completed_event_hash" => completed_hash,
          "deleted_secret_ids_hash" =>
            DeletionProofs.deleted_document_dek_secret_ids_hash(document.id, old_version)
        },
        device_key_deletion_proofs: %{"proofs" => []},
        wipe_required_device_ids: [owner_device.device.id]
      })
      |> Repo.insert!()

      %DocumentDeviceWipeRequirement{}
      |> DocumentDeviceWipeRequirement.changeset(%{
        document_id: document.id,
        device_id: owner_device.device.id,
        required_dek_version: required_version,
        reason: "dek_rotation_deletion_proof_missing",
        required_at: now
      })
      |> Repo.insert!()
    end

    assert {:ok, %{old_key_version: 1, required_dek_version: 2} = first_requirement} =
             DekRotation.wipe_requirement(document.id, owner_device.device.id)

    first_proof =
      signed_document_dek_deletion_proof(
        workspace.id,
        document.id,
        owner_id,
        owner_device.device.id,
        owner_device.signing_private_key,
        1,
        first_requirement.rotation_completed_event_hash
      )

    assert :ok = DekRotation.acknowledge_wipe(document.id, owner_device.device.id, first_proof)

    assert {:ok, %{old_key_version: 2, required_dek_version: 3} = second_requirement} =
             DekRotation.wipe_requirement(document.id, owner_device.device.id)

    second_proof =
      signed_document_dek_deletion_proof(
        workspace.id,
        document.id,
        owner_id,
        owner_device.device.id,
        owner_device.signing_private_key,
        2,
        second_requirement.rotation_completed_event_hash
      )

    assert :ok = DekRotation.acknowledge_wipe(document.id, owner_device.device.id, second_proof)
    refute DekRotation.wipe_required?(document.id, owner_device.device.id)
  end

  test "document key upload rejects an overdue workspace KEK before the marker worker runs",
       %{
         conn: conn,
         document: document,
         owner_device: owner_device,
         owner_id: owner_id,
         workspace: workspace
       } do
    Repo.update_all(
      from(w in Workspace, where: w.id == ^workspace.id),
      set: [
        current_kek_version: 1,
        min_kek_version: 1,
        needs_kek_rotation: false,
        kek_rotation_due_at: DateTime.add(DateTime.utc_now(), -1, :second)
      ]
    )

    path = "/api/encryption/documents/#{document.id}/keys"

    body = %{
      "key_version" => 1,
      "kek_version" => max(workspace.current_kek_version, 1),
      "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(48), padding: false),
      "nonce" => Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)
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

    assert json_response(conn, 422) == %{"error" => "kek_rotation_required"}
  end
end
