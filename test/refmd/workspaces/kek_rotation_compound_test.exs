defmodule RefMD.Workspaces.KekRotationCompoundTest do
  use RefMD.DataCase, async: true

  alias RefMD.Crypto.{Hash, JCS, Signature}
  alias RefMD.Devices.Device

  alias RefMD.Encryption.{
    KeyDirectory,
    RotationPolicy,
    UserIdentityPublicKey,
    WorkspaceEncryptedKey,
    WorkspaceMemberEnvelope
  }

  alias RefMD.Repo
  alias RefMD.Security.AuditEvent
  alias RefMD.Users.User
  alias RefMD.Workspaces
  alias RefMD.Workspaces.AuthorityMutations
  alias RefMD.Workspaces.KekRotation.{DeletionProofs, Directory}
  alias RefMD.Workspaces.{WorkspaceDeviceWipeRequirement, WorkspaceKekRotationDeletionEvidence}

  test "completion atomically stores exact device and member wraps and replays the receipt" do
    owner = insert_user!()
    {:ok, workspace} = Workspaces.create_default_workspace(owner.id, "Compound KEK rotation")

    workspace =
      workspace
      |> Ecto.Changeset.change(current_kek_version: 1, min_kek_version: 1)
      |> Repo.update!()

    role = Enum.find(Workspaces.list_workspace_roles(workspace.id), &(&1.base_role == "owner"))
    device_id = Ecto.UUID.generate()
    identity_signing_private = hybrid_signing_private_key_material("identity", owner.id)
    identity_signing_public = hybrid_signing_public_key_material(identity_signing_private)
    device_signing_private = hybrid_signing_private_key_material("device", device_id)
    device_signing_public = hybrid_signing_public_key_material(device_signing_private)
    {identity_x25519, _} = :crypto.generate_key(:ecdh, :x25519)
    {device_x25519, _} = :crypto.generate_key(:ecdh, :x25519)

    identity_encryption =
      hybrid_encryption_public_key_material("identity", owner.id, identity_x25519)

    device_encryption =
      hybrid_encryption_public_key_material("device", device_id, device_x25519)

    insert_test_workspace_key_directory!(
      workspace.id,
      owner.id,
      role.id,
      identity_signing_private,
      identity_encryption.public,
      device_signing_private,
      device_encryption.public
    )

    insert_device!(owner.id, device_id, device_signing_public, device_encryption)
    insert_identity!(owner.id, identity_signing_public, identity_encryption.public)

    AuditEvent
    |> where(
      [event],
      event.chain_scope_kind == "workspace" and event.chain_scope_id == ^workspace.id
    )
    |> Repo.delete_all()

    install_signed_audit_genesis!("workspace", workspace.id, owner.id,
      signer_device_id: device_id
    )

    rotation_id = Ecto.UUID.generate()

    start_append =
      kek_rotation_start_key_directory_append(
        workspace.id,
        owner.id,
        device_id,
        device_signing_private,
        1,
        2
      )

    start_command = %{
      "workspace_id" => workspace.id,
      "rotation_id" => rotation_id,
      "old_key_version" => 1,
      "new_key_version" => 2,
      "reason" => "manual"
    }

    assert {:ok, start_intent} =
             AuthorityMutations.issue_intent(
               owner.id,
               device_id,
               "workspace.kek.rotation_started",
               start_command,
               %{
                 "events" => start_append["workspace_key_directory_events"],
                 "checkpoint" => start_append["workspace_key_directory_checkpoint"]
               }
             )

    start_authorization =
      workspace_authority_authorization!(start_intent, device_signing_private, start_command)

    assert {:ok, %{replay?: false}} =
             AuthorityMutations.commit(
               owner.id,
               device_id,
               start_authorization
             )

    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace.id)
    sender = sender(owner.id, device_id, device_signing_public, workspace.id, checkpoint)

    device_wrap =
      precommit_wrap(
        "workspace_device_kek_wrap",
        %{
          "workspace_id" => workspace.id,
          "target_user_id" => owner.id,
          "target_device_id" => device_id,
          "kek_version" => 2
        },
        sender,
        %{
          "recipient_kind" => "device",
          "user_id" => owner.id,
          "device_id" => device_id,
          "encryption_key_id" => device_encryption.encryption_key_id,
          "key_scope_kind" => "workspace",
          "key_scope_id" => workspace.id,
          "key_checkpoint_sequence" => checkpoint.sequence,
          "key_checkpoint_hash" => checkpoint.checkpoint_hash
        },
        workspace.id
      )

    member_wrap =
      precommit_wrap(
        "workspace_member_kek_wrap",
        %{"workspace_id" => workspace.id, "target_user_id" => owner.id, "kek_version" => 2},
        sender,
        %{
          "recipient_kind" => "user_identity",
          "user_id" => owner.id,
          "encryption_key_id" => identity_encryption.encryption_key_id,
          "key_scope_kind" => "workspace",
          "key_scope_id" => workspace.id,
          "key_checkpoint_sequence" => checkpoint.sequence,
          "key_checkpoint_hash" => checkpoint.checkpoint_hash
        },
        workspace.id
      )

    member_precommit = %{
      "protocol" => "refmd.workspace-member-envelope",
      "version" => 1,
      "workspace_id" => workspace.id,
      "target_user_id" => owner.id,
      "kek_version" => 2,
      "target_identity_encryption_key_id" => identity_encryption.encryption_key_id,
      "target_identity_key_material_hash" => hash(identity_encryption.public),
      "authorization_key_directory_checkpoint_sequence" => checkpoint.sequence,
      "authorization_key_directory_checkpoint_hash" => checkpoint.checkpoint_hash,
      "wrap" => member_wrap
    }

    completion_command = %{
      "workspace_id" => workspace.id,
      "rotation_id" => rotation_id,
      "old_key_version" => 1,
      "new_key_version" => 2,
      "device_wrap_precommits" => [
        %{"target_user_id" => owner.id, "target_device_id" => device_id, "wrap" => device_wrap}
      ],
      "member_envelope_precommits" => [member_precommit],
      "workspace_invitation_updates" => [],
      "guest_invitation_updates" => []
    }

    assert {:ok, completion_intent} =
             AuthorityMutations.issue_intent(
               owner.id,
               device_id,
               "workspace.kek.rotation_completed",
               completion_command,
               %{}
             )

    completion_authorization =
      workspace_authority_authorization!(
        completion_intent,
        device_signing_private,
        completion_command
      )

    assert {:ok, %{response: response, replay?: false}} =
             AuthorityMutations.commit(
               owner.id,
               device_id,
               completion_authorization,
               %{"workspace_id" => workspace.id, "rotation_id" => rotation_id}
             )

    assert response["rotation_completed_event_hash"]
    assert response["deleted_secret_ids_hash"]
    assert response["deleted_wrap_ids_hash"]
    assert response["server_rejects_old_key_uploads_after_sequence"]

    assert {:ok, %{response: ^response, replay?: true}} =
             AuthorityMutations.commit(
               owner.id,
               device_id,
               completion_authorization,
               %{"workspace_id" => workspace.id, "rotation_id" => rotation_id}
             )

    assert Repo.get_by!(WorkspaceEncryptedKey,
             workspace_id: workspace.id,
             user_id: owner.id,
             device_id: device_id,
             key_version: 2
           )

    assert Repo.get_by!(WorkspaceMemberEnvelope,
             workspace_id: workspace.id,
             target_user_id: owner.id,
             key_version: 2
           )

    completed = Workspaces.get_workspace(workspace.id)
    refute completed.needs_kek_rotation
    assert completed.current_kek_version == 2
    assert completed.current_kek_rotation_id == rotation_id

    deletion_manifest = %{
      "protocol" => "refmd.old-key-deletion-manifest",
      "version" => 1,
      "rotation_kind" => "kek",
      "scope_kind" => "workspace",
      "scope_id" => workspace.id,
      "old_key_version" => 1,
      "rotation_completed_event_hash" => response["rotation_completed_event_hash"],
      "deleted_secret_ids_hash" => response["deleted_secret_ids_hash"],
      "deleted_wrap_ids_hash" => response["deleted_wrap_ids_hash"],
      "active_device_deletion_proofs_hash" =>
        DeletionProofs.active_device_deletion_proofs_hash([]),
      "wipe_required_device_ids_hash" =>
        DeletionProofs.wipe_required_device_ids_hash([device_id]),
      "server_rejects_old_key_uploads_after_sequence" =>
        response["server_rejects_old_key_uploads_after_sequence"]
    }

    invalid_deletion_command = %{
      "workspace_id" => workspace.id,
      "rotation_id" => rotation_id,
      "old_key_version" => 1,
      "deletion_manifest" => deletion_manifest,
      "device_key_deletion_proofs" => [],
      "wipe_required_device_ids" => [Ecto.UUID.generate()]
    }

    assert {:error, "wipe_required_device_unknown"} =
             AuthorityMutations.issue_intent(
               owner.id,
               device_id,
               "workspace.kek.old_key_deleted",
               invalid_deletion_command,
               %{}
             )

    deletion_command = %{
      invalid_deletion_command
      | "wipe_required_device_ids" => [device_id]
    }

    assert {:ok, deletion_intent} =
             AuthorityMutations.issue_intent(
               owner.id,
               device_id,
               "workspace.kek.old_key_deleted",
               deletion_command,
               %{}
             )

    deletion_authorization =
      workspace_authority_authorization!(
        deletion_intent,
        device_signing_private,
        deletion_command
      )

    assert {:ok, %{response: deletion_response, replay?: false}} =
             AuthorityMutations.commit(
               owner.id,
               device_id,
               deletion_authorization,
               %{"workspace_id" => workspace.id, "rotation_id" => rotation_id}
             )

    assert {:ok, %{response: ^deletion_response, replay?: true}} =
             AuthorityMutations.commit(
               owner.id,
               device_id,
               deletion_authorization,
               %{"workspace_id" => workspace.id, "rotation_id" => rotation_id}
             )

    assert Repo.get_by!(WorkspaceDeviceWipeRequirement,
             workspace_id: workspace.id,
             device_id: device_id,
             required_kek_version: 2
           )

    assert Repo.get_by!(WorkspaceKekRotationDeletionEvidence,
             workspace_id: workspace.id,
             old_key_version: 1
           ).deletion_manifest == deletion_manifest

    refute Repo.get_by(WorkspaceEncryptedKey,
             workspace_id: workspace.id,
             key_version: 1
           )

    assert Directory.old_key_deletion_material(workspace.id, 1)["deleted_secret_ids_hash"] ==
             response["deleted_secret_ids_hash"]

    deleted = Workspaces.get_workspace(workspace.id)
    assert deleted.min_kek_version == 2
    assert is_nil(deleted.current_kek_rotation_id)
  end

  defp insert_user! do
    nonce = System.unique_integer([:positive])

    Repo.insert!(%User{
      id: Ecto.UUID.generate(),
      email: "compound-kek-#{nonce}@example.com",
      name: "Compound KEK #{nonce}"
    })
  end

  defp insert_device!(user_id, device_id, signing_public, encryption) do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    Repo.insert!(%Device{
      id: device_id,
      user_id: user_id,
      name: "Compound KEK device",
      device_type: "browser",
      hybrid_encryption_public_key_material: encryption.public,
      encryption_key_id: encryption.encryption_key_id,
      hybrid_signing_public_key_material: signing_public,
      signing_key_id: Signature.compute_signing_key_id!(signing_public),
      approval_signature: %{"fixture" => true},
      approval_signature_surface: "device_approval",
      approval_proof: %{},
      key_checkpoint_sequence: 1,
      key_checkpoint_hash: Hash.blake3_base64url("compound-kek-device"),
      client_nonce: :crypto.strong_rand_bytes(16),
      last_seen_at: now,
      created_at: now
    })
  end

  defp insert_identity!(user_id, signing_public, encryption_public) do
    %UserIdentityPublicKey{}
    |> UserIdentityPublicKey.changeset(%{
      user_id: user_id,
      hybrid_encryption_public_key_material: encryption_public,
      hybrid_signing_public_key_material: signing_public,
      pending_registration_challenge_hash: Hash.blake3_base64url("compound-kek-identity"),
      rotation_due_at: RotationPolicy.next_identity_due_at()
    })
    |> Repo.insert!()
  end

  defp sender(user_id, device_id, signing_public, workspace_id, checkpoint) do
    %{
      "signer_kind" => "device",
      "user_id" => user_id,
      "device_id" => device_id,
      "signing_key_id" => Signature.compute_signing_key_id!(signing_public),
      "key_scope_kind" => "workspace",
      "key_scope_id" => workspace_id,
      "key_checkpoint_sequence" => checkpoint.sequence,
      "key_checkpoint_hash" => checkpoint.checkpoint_hash
    }
  end

  defp precommit_wrap(purpose, resource, sender, recipient, workspace_id) do
    %{
      "protocol" => "refmd.signed-pq-hybrid-wrap",
      "protocol_version" => 1,
      "suite_id" =>
        "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65",
      "suite_rank" => 1000,
      "purpose" => purpose,
      "resource" => resource,
      "sender" => sender,
      "recipient" => recipient,
      "event_scope" => %{"scope_kind" => "workspace", "scope_id" => workspace_id},
      "hpke" => %{
        "mode" => "base",
        "kem_id" => 25_722,
        "kdf_id" => 1,
        "aead_id" => 3,
        "enc" => Base.url_encode64(:crypto.strong_rand_bytes(1120), padding: false),
        "ciphertext" => Base.url_encode64(:crypto.strong_rand_bytes(48), padding: false)
      }
    }
  end

  defp hash(value), do: value |> JCS.canonical_bytes!() |> Hash.blake3_base64url()
end
