defmodule RefMD.Workspaces.MembersTest do
  use RefMD.DataCase, async: true

  alias RefMD.Crypto.Hash
  alias RefMD.Devices.Device
  alias RefMD.Documents.Document
  alias RefMD.Encryption.KeyDirectory
  alias RefMD.Repo
  alias RefMD.Users.User
  alias RefMD.Workspaces
  alias RefMD.Workspaces.{WorkspaceMember, WorkspaceRolePermission}

  test "remove_member marks KEK rotation before returning success" do
    {workspace, owner} = workspace_fixture()
    insert_active_device(owner.id)
    target = user_fixture()

    document =
      Repo.insert!(%Document{
        workspace_id: workspace.id,
        created_by: owner.id,
        title: "Membership rotation",
        slug: "membership-rotation-#{Ecto.UUID.generate()}",
        doc_type: "document",
        is_encrypted: false
      })

    editor_role = role_by_base!(workspace.id, "editor")

    insert_test_workspace_key_directory!(
      workspace.id,
      owner.id,
      role_by_base!(workspace.id, "owner").id
    )

    Repo.insert!(%WorkspaceMember{
      workspace_id: workspace.id,
      user_id: target.id,
      role_id: editor_role.id,
      joined_at: DateTime.utc_now()
    })

    signer = Process.get({:test_workspace_signer_material, workspace.id})

    append =
      workspace_member_removal_key_directory_append(
        workspace.id,
        target.id,
        owner.id,
        signer.device_id,
        signer.signing_private
      )

    key_directory = %{
      workspace_events: append["workspace_key_directory_events"],
      workspace_checkpoint: append["workspace_key_directory_checkpoint"]
    }

    assert {:ok, %WorkspaceMember{user_id: target_user_id}} =
             Workspaces.remove_member(workspace.id, target.id, owner.id, key_directory)

    assert target_user_id == target.id
    refute Repo.get_by(WorkspaceMember, workspace_id: workspace.id, user_id: target.id)

    reloaded_workspace = Workspaces.get_workspace(workspace.id)
    assert reloaded_workspace.needs_kek_rotation
    assert reloaded_workspace.kek_rotation_initiator_user_id == owner.id
    assert Repo.reload!(document).needs_dek_rotation
    assert Repo.reload!(document).dek_rotation_reason == "membership_change"
  end

  test "change_member_role binds effective permissions and version, then rotates on read loss" do
    {workspace, owner} = workspace_fixture()
    insert_active_device(owner.id)
    target = user_fixture()
    editor_role = role_by_base!(workspace.id, "editor")

    {:ok, no_read_role} =
      Workspaces.create_custom_role(workspace.id, "No read", "viewer", [
        %{"permission" => "document:read", "granted" => false}
      ])

    member =
      Repo.insert!(%WorkspaceMember{
        workspace_id: workspace.id,
        user_id: target.id,
        role_id: editor_role.id,
        joined_at: DateTime.utc_now()
      })

    document =
      Repo.insert!(%Document{
        workspace_id: workspace.id,
        created_by: owner.id,
        title: "Role loss rotation",
        slug: "role-loss-#{Ecto.UUID.generate()}",
        doc_type: "document",
        is_encrypted: false
      })

    insert_test_workspace_key_directory!(
      workspace.id,
      owner.id,
      role_by_base!(workspace.id, "owner").id
    )

    signer = Process.get({:test_workspace_signer_material, workspace.id})

    append =
      workspace_member_role_changes_key_directory_append(
        workspace.id,
        owner.id,
        signer.device_id,
        signer.signing_private,
        [
          role_change_body(
            workspace.id,
            target.id,
            editor_role,
            no_read_role,
            member.permission_version
          )
        ]
      )

    Phoenix.PubSub.subscribe(RefMD.PubSub, "user_socket:#{target.id}")

    assert {:ok, updated} =
             Workspaces.change_member_role(
               workspace.id,
               target.id,
               no_read_role.id,
               owner.id,
               key_directory(append)
             )

    assert updated.role_id == no_read_role.id
    assert updated.permission_version == member.permission_version + 1
    assert_receive %Phoenix.Socket.Broadcast{event: "disconnect"}
    assert Workspaces.get_workspace(workspace.id).needs_kek_rotation
    assert Repo.reload!(document).needs_dek_rotation
  end

  test "custom role permission update emits one transition per member and increments all versions" do
    {workspace, owner} = workspace_fixture()
    insert_active_device(owner.id)

    {:ok, role} = Workspaces.create_custom_role(workspace.id, "Writers", "editor", [])

    members =
      for _ <- 1..2 do
        user = user_fixture()

        Repo.insert!(%WorkspaceMember{
          workspace_id: workspace.id,
          user_id: user.id,
          role_id: role.id,
          joined_at: DateTime.utc_now()
        })
      end
      |> Enum.sort_by(& &1.user_id)

    insert_test_workspace_key_directory!(
      workspace.id,
      owner.id,
      role_by_base!(workspace.id, "owner").id
    )

    signer = Process.get({:test_workspace_signer_material, workspace.id})
    proposed = [%{"permission" => "document:write", "granted" => false}]

    proposed_role = %{
      role
      | permissions: [
          %WorkspaceRolePermission{
            permission: "document:write",
            granted: false
          }
        ]
    }

    changes =
      Enum.map(members, fn member ->
        role_change_body(
          workspace.id,
          member.user_id,
          role,
          proposed_role,
          member.permission_version
        )
      end)

    append =
      workspace_member_role_changes_key_directory_append(
        workspace.id,
        owner.id,
        signer.device_id,
        signer.signing_private,
        changes
      )

    Enum.each(members, &Phoenix.PubSub.subscribe(RefMD.PubSub, "user_socket:#{&1.user_id}"))

    assert {:ok, updated_role} =
             Workspaces.update_role(role, %{},
               permissions: proposed,
               actor_role: role_by_base!(workspace.id, "owner"),
               actor_user_id: owner.id,
               key_directory: key_directory(append)
             )

    refute Workspaces.permission_granted?(updated_role, "document:write")

    Enum.each(members, fn member ->
      assert Workspaces.get_workspace_member(workspace.id, member.user_id).permission_version ==
               member.permission_version + 1

      assert_receive %Phoenix.Socket.Broadcast{topic: "user_socket:" <> _}
    end)

    refute Workspaces.get_workspace(workspace.id).needs_kek_rotation
  end

  test "custom role permission update rolls back role and member versions on invalid append" do
    {workspace, owner} = workspace_fixture()
    insert_active_device(owner.id)
    {:ok, role} = Workspaces.create_custom_role(workspace.id, "Rollback writers", "editor", [])
    target = user_fixture()

    member =
      Repo.insert!(%WorkspaceMember{
        workspace_id: workspace.id,
        user_id: target.id,
        role_id: role.id,
        joined_at: DateTime.utc_now()
      })

    insert_test_workspace_key_directory!(
      workspace.id,
      owner.id,
      role_by_base!(workspace.id, "owner").id
    )

    signer = Process.get({:test_workspace_signer_material, workspace.id})
    proposed = [%{"permission" => "document:write", "granted" => false}]

    proposed_role = %{
      role
      | permissions: [
          %WorkspaceRolePermission{
            permission: "document:write",
            granted: false
          }
        ]
    }

    append =
      workspace_member_role_changes_key_directory_append(
        workspace.id,
        owner.id,
        signer.device_id,
        signer.signing_private,
        [
          role_change_body(
            workspace.id,
            target.id,
            role,
            proposed_role,
            member.permission_version
          )
        ]
      )

    [event] = append["workspace_key_directory_events"]
    tampered_event = put_in(event, ["payload", "body", "permission_version"], 99)
    append = Map.put(append, "workspace_key_directory_events", [tampered_event])
    pin_before = KeyDirectory.current_pin("workspace", workspace.id)

    assert {:error, :invalid_key_directory} =
             Workspaces.update_role(role, %{},
               permissions: proposed,
               actor_role: role_by_base!(workspace.id, "owner"),
               actor_user_id: owner.id,
               key_directory: key_directory(append)
             )

    assert Workspaces.permission_granted?(
             Workspaces.get_role_with_permissions(workspace.id, role.id),
             "document:write"
           )

    assert Workspaces.get_workspace_member(workspace.id, target.id).permission_version ==
             member.permission_version

    assert KeyDirectory.current_pin("workspace", workspace.id) == pin_before
  end

  defp workspace_fixture do
    owner = user_fixture()
    {:ok, workspace} = Workspaces.create_default_workspace(owner.id, "Member removal")
    {workspace, owner}
  end

  defp user_fixture do
    uniq = System.unique_integer([:positive])

    Repo.insert!(%User{
      id: Ecto.UUID.generate(),
      email: "member-removal-#{uniq}@example.com",
      name: "Member Removal #{uniq}"
    })
  end

  defp role_by_base!(workspace_id, base_role) do
    Workspaces.list_workspace_roles(workspace_id)
    |> Enum.find(&(&1.base_role == base_role))
  end

  defp insert_active_device(user_id) do
    device_id = Ecto.UUID.generate()
    signing = hybrid_device_material(device_id)
    {x25519_public, _private} = :crypto.generate_key(:ecdh, :x25519)
    encryption = hybrid_encryption_public_key_material("device", device_id, x25519_public)
    checkpoint_hash = Hash.blake3_base64url("member-removal-device:" <> device_id)
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    Repo.insert!(%Device{
      id: device_id,
      user_id: user_id,
      name: "Member removal browser",
      device_type: "browser",
      hybrid_encryption_public_key_material: encryption.public,
      encryption_key_id: encryption.encryption_key_id,
      hybrid_signing_public_key_material: signing.public,
      signing_key_id: signing.signing_key_id,
      approval_signature: %{"fixture" => "member-removal-device"},
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

  defp role_change_body(_workspace_id, user_id, previous_role, role, permission_version) do
    %{
      "user_id" => user_id,
      "previous_role_id" => previous_role.id,
      "previous_base_role" => previous_role.base_role,
      "previous_effective_permissions" => effective_permissions(previous_role),
      "role_id" => role.id,
      "base_role" => role.base_role,
      "effective_permissions" => effective_permissions(role),
      "permission_version" => permission_version + 1
    }
  end

  defp effective_permissions(role) do
    role |> Workspaces.effective_permissions() |> MapSet.to_list() |> Enum.sort()
  end

  defp key_directory(append) do
    %{
      workspace_events: append["workspace_key_directory_events"],
      workspace_checkpoint: append["workspace_key_directory_checkpoint"]
    }
  end
end
