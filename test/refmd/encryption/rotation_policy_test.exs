defmodule RefMD.Encryption.RotationPolicyTest do
  use RefMD.DataCase, async: false

  alias RefMD.Crypto.Hash
  alias RefMD.Devices.Device
  alias RefMD.Documents
  alias RefMD.Documents.Document
  alias RefMD.Encryption
  alias RefMD.Encryption.DocumentEncryptedKey
  alias RefMD.Encryption.RotationPolicy
  alias RefMD.Repo
  alias RefMD.Users.User
  alias RefMD.Workers.{MarkOverdueKeyRotations, RetryRotationMarking}
  alias RefMD.Workspaces
  alias RefMD.Workspaces.{Workspace, WorkspaceMember, WorkspaceRole}

  test "deadline predicates use explicit deadlines and fail closed when missing" do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    refute RotationPolicy.kek_overdue?(
             %Workspace{
               needs_kek_rotation: false,
               created_at: now,
               kek_rotation_due_at: DateTime.add(now, 1, :second)
             },
             now
           )

    assert RotationPolicy.dek_overdue?(
             %Document{
               needs_dek_rotation: false,
               created_at: now,
               dek_rotation_due_at: nil
             },
             now
           )
  end

  test "worker marks overdue workspace and document without marking future records" do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    user = insert_user()
    insert_active_device(user.id)

    overdue_workspace =
      insert_member_workspace(user.id, "overdue", DateTime.add(now, -1, :second))

    future_workspace =
      insert_member_workspace(user.id, "future", DateTime.add(now, 3600, :second))

    overdue_document =
      insert_document(overdue_workspace.id, user.id, "overdue", DateTime.add(now, -1, :second))

    future_document =
      insert_document(future_workspace.id, user.id, "future", DateTime.add(now, 3600, :second))

    assert %{workspaces: {workspace_count, _}, documents: {document_count, _}} =
             MarkOverdueKeyRotations.mark_overdue(now)

    assert workspace_count >= 1
    assert document_count >= 1

    assert Repo.reload!(overdue_workspace).needs_kek_rotation
    assert Repo.reload!(overdue_workspace).kek_rotation_initiator_user_id == user.id
    refute Repo.reload!(future_workspace).needs_kek_rotation
    assert Repo.reload!(overdue_document).needs_dek_rotation
    assert Repo.reload!(overdue_document).dek_rotation_reason == "time_based"
    refute Repo.reload!(future_document).needs_dek_rotation
  end

  test "worker chooses an eligible current admin when the original owner has no active device" do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    owner = insert_user()
    admin = insert_user()

    workspace =
      insert_member_workspace(owner.id, "admin-initiator", DateTime.add(now, -1, :second))

    admin_role =
      Repo.one!(
        from(r in WorkspaceRole,
          where: r.workspace_id == ^workspace.id and r.base_role == "admin"
        )
      )

    Repo.insert!(%WorkspaceMember{
      workspace_id: workspace.id,
      user_id: admin.id,
      role_id: admin_role.id,
      joined_at: now
    })

    insert_active_device(admin.id)

    MarkOverdueKeyRotations.mark_overdue(now)

    rotated = Repo.reload!(workspace)
    assert rotated.needs_kek_rotation
    assert rotated.kek_rotation_initiator_user_id == admin.id
  end

  test "worker never selects a guest account with conflicting owner membership" do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    owner = insert_user()
    insert_active_device(owner.id)

    workspace =
      insert_member_workspace(owner.id, "guest-owner", DateTime.add(now, -1, :second))

    guest_id = "00000000-0000-4000-8000-000000000001"

    Repo.insert!(%User{
      id: guest_id,
      email: "rotation-guest-owner@example.com",
      name: "Guest owner",
      account_type: "guest"
    })

    owner_role =
      Repo.one!(
        from(r in WorkspaceRole,
          where: r.workspace_id == ^workspace.id and r.base_role == "owner"
        )
      )

    Repo.insert!(%WorkspaceMember{
      workspace_id: workspace.id,
      user_id: guest_id,
      role_id: owner_role.id,
      joined_at: now
    })

    insert_active_device(guest_id)

    MarkOverdueKeyRotations.mark_overdue(now)

    rotated = Repo.reload!(workspace)
    assert rotated.needs_kek_rotation
    assert rotated.kek_rotation_initiator_user_id == owner.id
  end

  test "rotation domain and retry reject a supplied guest owner initiator" do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    owner = insert_user()
    insert_active_device(owner.id)

    workspace =
      insert_member_workspace(owner.id, "guest-retry", DateTime.add(now, 3600, :second))

    guest = insert_user() |> Ecto.Changeset.change(account_type: "guest") |> Repo.update!()

    owner_role =
      Repo.one!(
        from(r in WorkspaceRole,
          where: r.workspace_id == ^workspace.id and r.base_role == "owner"
        )
      )

    Repo.insert!(%WorkspaceMember{
      workspace_id: workspace.id,
      user_id: guest.id,
      role_id: owner_role.id,
      joined_at: now
    })

    insert_active_device(guest.id)

    refute Workspaces.rotation_initiator_eligible?(workspace.id, guest.id)
    assert Workspaces.next_rotation_initiator(workspace.id) == owner.id

    assert {:discard, :invalid_rotation_initiator} =
             RetryRotationMarking.perform(%Oban.Job{
               args: %{
                 "workspace_id" => workspace.id,
                 "initiator_user_id" => guest.id
               }
             })

    refute Repo.reload!(workspace).needs_kek_rotation
    assert Repo.reload!(workspace).kek_rotation_initiator_user_id == nil

    assert {1, nil} = Workspaces.mark_kek_rotation_needed([workspace.id], guest.id)
    assert Repo.reload!(workspace).kek_rotation_initiator_user_id == owner.id
  end

  test "worker does not strand an overdue workspace without an eligible initiator" do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    owner = insert_user()
    workspace = insert_member_workspace(owner.id, "no-initiator", DateTime.add(now, -1, :second))

    MarkOverdueKeyRotations.mark_overdue(now)

    refute Repo.reload!(workspace).needs_kek_rotation
    assert Repo.reload!(workspace).kek_rotation_initiator_user_id == nil
  end

  test "overdue DEK rejects current-version encryption but permits the next rotation version" do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    user = insert_user()
    {:ok, workspace} = Workspaces.create_default_workspace(user.id, "dek-write")

    workspace =
      workspace
      |> Ecto.Changeset.change(
        current_kek_version: 1,
        min_kek_version: 1,
        kek_rotation_due_at: DateTime.add(now, 3600, :second)
      )
      |> Repo.update!()

    {_member, role} = Workspaces.get_member_with_role(workspace.id, user.id)
    insert_test_workspace_key_directory!(workspace.id, user.id, role.id)
    document = insert_document(workspace.id, user.id, "dek-write", DateTime.add(now, -1, :second))

    Repo.insert!(%DocumentEncryptedKey{
      document_id: document.id,
      key_version: 1,
      kek_version: 1,
      encrypted_dek: :crypto.strong_rand_bytes(48),
      nonce: :crypto.strong_rand_bytes(24),
      is_active: true,
      created_at: now
    })

    assert {:error, :dek_rotation_required} =
             Encryption.create_document_key_with_rotation(%{
               document_id: document.id,
               key_version: 1,
               kek_version: 1,
               encrypted_dek: :crypto.strong_rand_bytes(48),
               nonce: :crypto.strong_rand_bytes(24)
             })

    mismatched_start =
      test_dek_rotation_start_key_directory_append(
        workspace.id,
        user.id,
        document.id,
        1,
        2,
        "security"
      )

    assert {:error, :invalid_key_directory} =
             Encryption.create_document_key_with_rotation(
               %{
                 document_id: document.id,
                 key_version: 2,
                 kek_version: 1,
                 encrypted_dek: :crypto.strong_rand_bytes(48),
                 nonce: :crypto.strong_rand_bytes(24)
               },
               %{
                 dek_rotation_start_events: mismatched_start["workspace_key_directory_events"],
                 dek_rotation_start_checkpoint:
                   mismatched_start["workspace_key_directory_checkpoint"]
               }
             )

    start =
      test_dek_rotation_start_key_directory_append(
        workspace.id,
        user.id,
        document.id,
        1,
        2
      )

    assert {:ok, key} =
             Encryption.create_document_key_with_rotation(
               %{
                 document_id: document.id,
                 key_version: 2,
                 kek_version: 1,
                 encrypted_dek: :crypto.strong_rand_bytes(48),
                 nonce: :crypto.strong_rand_bytes(24)
               },
               %{
                 dek_rotation_start_events: start["workspace_key_directory_events"],
                 dek_rotation_start_checkpoint: start["workspace_key_directory_checkpoint"]
               }
             )

    assert key.key_version == 2
    rotated = Repo.reload!(document)
    refute rotated.needs_dek_rotation
    assert rotated.dek_rotation_reason == nil
    assert rotated.needs_rotation_snapshot
    assert DateTime.compare(rotated.dek_rotation_due_at, now) == :gt
  end

  test "encrypted document metadata rejects stale and overdue DEK versions" do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    user = insert_user()
    workspace = insert_workspace(user.id, "document-metadata", DateTime.add(now, 3600, :second))

    overdue_workspace =
      insert_workspace(user.id, "overdue-document-metadata", DateTime.add(now, 3600, :second))

    stale =
      workspace.id
      |> insert_document(
        user.id,
        "stale-document-metadata",
        DateTime.add(now, 3600, :second)
      )
      |> mark_document_encrypted(1)
      |> Ecto.Changeset.change(min_dek_version: 2)
      |> Repo.update!()

    overdue =
      overdue_workspace.id
      |> insert_document(
        user.id,
        "overdue-document-metadata",
        DateTime.add(now, -1, :second)
      )
      |> mark_document_encrypted(1)

    for document <- [stale, overdue] do
      assert {:error, :dek_rotation_required} =
               Documents.update_document(document, %{
                 encrypted_title: :crypto.strong_rand_bytes(48),
                 encrypted_title_nonce: :crypto.strong_rand_bytes(24),
                 encrypted_title_key_version: 1
               })
    end
  end

  test "encrypted workspace metadata rejects stale and overdue KEK versions" do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    user = insert_user()

    stale =
      insert_workspace(user.id, "stale-workspace-metadata", DateTime.add(now, 3600, :second))
      |> Ecto.Changeset.change(current_kek_version: 2)
      |> Repo.update!()

    overdue =
      insert_workspace(user.id, "overdue-workspace-metadata", DateTime.add(now, -1, :second))

    partial =
      insert_workspace(user.id, "partial-workspace-metadata", DateTime.add(now, 3600, :second))

    for workspace <- [stale, overdue] do
      assert {:error, :kek_rotation_required} =
               Workspaces.update_workspace(workspace, %{
                 encrypted_name: :crypto.strong_rand_bytes(48),
                 encrypted_name_nonce: :crypto.strong_rand_bytes(24),
                 encrypted_name_key_version: 1
               })
    end

    assert {:error, :kek_rotation_required} =
             Workspaces.update_workspace(partial, %{
               encrypted_name: :crypto.strong_rand_bytes(48)
             })
  end

  defp insert_user do
    id = Ecto.UUID.generate()
    Repo.insert!(%User{id: id, email: "rotation-#{id}@example.com", name: "Rotation"})
  end

  defp insert_workspace(user_id, label, due_at) do
    Repo.insert!(%Workspace{
      name: label,
      slug: "#{label}-#{Ecto.UUID.generate()}",
      owner_id: user_id,
      current_kek_version: 1,
      min_kek_version: 1,
      kek_rotation_due_at: due_at
    })
  end

  defp insert_member_workspace(user_id, label, due_at) do
    {:ok, workspace} = Workspaces.create_default_workspace(user_id, label)

    workspace
    |> Ecto.Changeset.change(
      current_kek_version: 1,
      min_kek_version: 1,
      kek_rotation_due_at: due_at
    )
    |> Repo.update!()
  end

  defp insert_active_device(user_id) do
    device_id = Ecto.UUID.generate()
    signing = hybrid_device_material(device_id)
    {x25519_public, _private} = :crypto.generate_key(:ecdh, :x25519)
    encryption = hybrid_encryption_public_key_material("device", device_id, x25519_public)
    checkpoint_hash = Hash.blake3_base64url("rotation-device:" <> device_id)
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    Repo.insert!(%Device{
      id: device_id,
      user_id: user_id,
      name: "Rotation browser",
      device_type: "browser",
      hybrid_encryption_public_key_material: encryption.public,
      encryption_key_id: encryption.encryption_key_id,
      hybrid_signing_public_key_material: signing.public,
      signing_key_id: signing.signing_key_id,
      approval_signature: %{"fixture" => "rotation-device"},
      approval_signature_surface: "device_approval",
      approval_proof: %{
        "target_key_checkpoint_sequence" => 1,
        "target_key_checkpoint_hash" => checkpoint_hash
      },
      key_checkpoint_sequence: 1,
      key_checkpoint_hash: checkpoint_hash,
      client_nonce: :crypto.strong_rand_bytes(16),
      last_seen_at: now,
      created_at: now
    })
  end

  defp insert_document(workspace_id, user_id, label, due_at) do
    Repo.insert!(%Document{
      workspace_id: workspace_id,
      created_by: user_id,
      title: label,
      slug: "#{label}-#{Ecto.UUID.generate()}",
      path: "/#{label}",
      doc_type: "document",
      is_encrypted: false,
      min_dek_version: 1,
      dek_rotation_due_at: due_at
    })
  end

  defp mark_document_encrypted(document, key_version) do
    document
    |> Ecto.Changeset.change(
      is_encrypted: true,
      encrypted_title: :crypto.strong_rand_bytes(48),
      encrypted_title_nonce: :crypto.strong_rand_bytes(24),
      encrypted_title_key_version: key_version
    )
    |> Repo.update!()
  end
end
