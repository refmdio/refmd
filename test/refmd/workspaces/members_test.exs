defmodule RefMD.Workspaces.MembersTest do
  use RefMD.DataCase, async: true

  alias RefMD.Crypto.{Hash, Signature}
  alias RefMD.Devices.Device
  alias RefMD.Documents.Document
  alias RefMD.Repo
  alias RefMD.Users.User
  alias RefMD.Workspaces
  alias RefMD.Workspaces.AuthorityMutations
  alias RefMD.Workspaces.WorkspaceMember

  alias RefMD.Security.{
    AuditEvent,
    ConsumedCompoundIntentReceipt,
    MutationOutboxItem,
    Notification,
    PendingCompoundIntent
  }

  test "remove_member marks KEK rotation before returning success" do
    {workspace, owner} = workspace_fixture()
    workspace = workspace |> Ecto.Changeset.change(current_kek_version: 1) |> Repo.update!()
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
    insert_workspace_signer_device!(owner.id, signer)
    install_workspace_audit_genesis!(workspace.id, owner.id)

    append =
      workspace_member_removal_key_directory_append(
        workspace.id,
        target.id,
        owner.id,
        signer.device_id,
        signer.signing_private
      )

    command = %{"workspace_id" => workspace.id, "target_user_id" => target.id}

    assert {:ok, intent} =
             AuthorityMutations.issue_intent(
               owner.id,
               signer.device_id,
               "workspace.member.removed",
               command,
               %{
                 "events" => append["workspace_key_directory_events"],
                 "checkpoint" => append["workspace_key_directory_checkpoint"]
               }
             )

    authorization = workspace_authority_authorization!(intent, signer.signing_private, command)

    assert {:error, :workspace_authority_mutation_route_binding_mismatch} =
             AuthorityMutations.commit(
               owner.id,
               signer.device_id,
               authorization,
               %{
                 "workspace_id" => workspace.id,
                 "target_user_id" => owner.id,
                 "mutation_kind" => "workspace.member.removed"
               }
             )

    assert Repo.get_by(WorkspaceMember, workspace_id: workspace.id, user_id: target.id)

    refute Repo.get_by(PendingCompoundIntent, compound_intent_id: intent["compound_intent_id"]).consumed_at

    assert {:ok, %{response: %{"status" => "committed"} = response, replay?: false}} =
             AuthorityMutations.commit(
               owner.id,
               signer.device_id,
               authorization,
               %{
                 "workspace_id" => workspace.id,
                 "target_user_id" => target.id,
                 "mutation_kind" => "workspace.member.removed"
               }
             )

    notification =
      Repo.get_by!(Notification,
        recipient_kind: "user",
        recipient_id: target.id,
        type: "workspace.member.removed"
      )

    assert notification.action_ref["mutation_id"] == intent["mutation_id"]

    assert Repo.aggregate(
             from(item in MutationOutboxItem,
               where: item.compound_intent_id == ^intent["compound_intent_id"]
             ),
             :count
           ) == 2

    assert Repo.get_by!(MutationOutboxItem,
             compound_intent_id: intent["compound_intent_id"],
             effect_kind: "security_notification_delivery"
           )

    assert Repo.get_by!(MutationOutboxItem,
             compound_intent_id: intent["compound_intent_id"],
             effect_kind: "pubsub_broadcast"
           )

    assert {:ok, %{response: ^response, replay?: true}} =
             AuthorityMutations.commit(
               owner.id,
               signer.device_id,
               authorization,
               %{
                 "workspace_id" => workspace.id,
                 "target_user_id" => target.id,
                 "mutation_kind" => "workspace.member.removed"
               }
             )

    assert Repo.aggregate(
             from(item in MutationOutboxItem,
               where: item.compound_intent_id == ^intent["compound_intent_id"]
             ),
             :count
           ) == 2

    assert Repo.get_by!(PendingCompoundIntent,
             compound_intent_id: intent["compound_intent_id"]
           ).consumed_at

    assert Repo.get_by!(ConsumedCompoundIntentReceipt,
             compound_intent_id: intent["compound_intent_id"]
           )

    tampered =
      put_in(authorization, ["effect_authorizations", Access.at(0), "approval_proof"], %{})

    assert {:error, "audit_checkpoint_intent_reuse"} =
             AuthorityMutations.commit(
               owner.id,
               signer.device_id,
               tampered,
               %{
                 "workspace_id" => workspace.id,
                 "target_user_id" => target.id,
                 "mutation_kind" => "workspace.member.removed"
               }
             )

    refute Repo.get_by(WorkspaceMember, workspace_id: workspace.id, user_id: target.id)

    reloaded_workspace = Workspaces.get_workspace(workspace.id)
    assert reloaded_workspace.needs_kek_rotation
    assert reloaded_workspace.kek_rotation_initiator_user_id == owner.id
    assert Repo.reload!(document).needs_dek_rotation
    assert Repo.reload!(document).dek_rotation_reason == "membership_change"
  end

  test "change_member_role binds effective permissions and version without unsigned rotation effects" do
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
    insert_workspace_signer_device!(owner.id, signer)
    install_workspace_audit_genesis!(workspace.id, owner.id)

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

    command = %{
      "workspace_id" => workspace.id,
      "target_user_id" => target.id,
      "new_role_id" => no_read_role.id
    }

    assert {:ok, intent} =
             AuthorityMutations.issue_intent(
               owner.id,
               signer.device_id,
               "workspace.member.role_changed",
               command,
               %{
                 "events" => append["workspace_key_directory_events"],
                 "checkpoint" => append["workspace_key_directory_checkpoint"]
               }
             )

    authorization = workspace_authority_authorization!(intent, signer.signing_private, command)

    assert {:error, :workspace_authority_mutation_route_binding_mismatch} =
             AuthorityMutations.commit(
               owner.id,
               signer.device_id,
               authorization,
               %{
                 "workspace_id" => workspace.id,
                 "target_user_id" => target.id,
                 "mutation_kind" => "workspace.member.removed"
               }
             )

    assert {:ok, %{response: %{"permission_loss" => true} = response}} =
             AuthorityMutations.commit(
               owner.id,
               signer.device_id,
               authorization,
               %{
                 "workspace_id" => workspace.id,
                 "target_user_id" => target.id,
                 "mutation_kind" => "workspace.member.role_changed"
               }
             )

    assert response["event_type"] == "workspace.member.role_changed"
    assert response["workspace_audit_checkpoint_hash"]
    assert response["workspace_key_directory_checkpoint_hash"]

    assert %AuditEvent{type: "workspace.member.role_changed"} =
             Repo.get_by!(AuditEvent,
               id:
                 intent["scopes"]
                 |> hd()
                 |> Map.fetch!("candidate_events")
                 |> hd()
                 |> Map.fetch!("event_id")
             )

    updated = Repo.get_by!(WorkspaceMember, workspace_id: workspace.id, user_id: target.id)

    assert updated.role_id == no_read_role.id
    assert updated.permission_version == member.permission_version + 1
    refute Workspaces.get_workspace(workspace.id).needs_kek_rotation
    refute Repo.reload!(document).needs_dek_rotation
  end

  test "custom role permission update increments all affected member versions" do
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

    proposed = [%{"permission" => "document:write", "granted" => false}]

    Enum.each(members, &Phoenix.PubSub.subscribe(RefMD.PubSub, "user_socket:#{&1.user_id}"))

    assert {:ok, updated_role} =
             Workspaces.update_role(role, %{},
               permissions: proposed,
               actor_role: role_by_base!(workspace.id, "owner"),
               actor_user_id: owner.id
             )

    refute Workspaces.permission_granted?(updated_role, "document:write")

    Enum.each(members, fn member ->
      assert Workspaces.get_workspace_member(workspace.id, member.user_id).permission_version ==
               member.permission_version + 1

      assert_receive %Phoenix.Socket.Broadcast{topic: "user_socket:" <> _}
    end)

    refute Workspaces.get_workspace(workspace.id).needs_kek_rotation
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

  defp insert_workspace_signer_device!(user_id, signer) do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    signing_key_id = Signature.compute_signing_key_id!(signer.signing_public)

    Repo.insert!(%Device{
      id: signer.device_id,
      user_id: user_id,
      name: "Workspace authority browser",
      device_type: "browser",
      hybrid_encryption_public_key_material: signer.encryption_public,
      encryption_key_id: signer.encryption_key_id,
      hybrid_signing_public_key_material: signer.signing_public,
      signing_key_id: signing_key_id,
      approval_signature: %{"fixture" => "workspace-authority-device"},
      approval_signature_surface: "device_approval",
      approval_proof: %{
        "target_key_checkpoint_sequence" => 1,
        "target_key_checkpoint_hash" => Hash.blake3_base64url("workspace-authority")
      },
      key_checkpoint_sequence: 1,
      key_checkpoint_hash: Hash.blake3_base64url("workspace-authority"),
      client_nonce: :crypto.strong_rand_bytes(16),
      last_seen_at: now,
      created_at: now
    })
  end

  defp install_workspace_audit_genesis!(workspace_id, owner_id) do
    AuditEvent
    |> Ecto.Query.where(
      [event],
      event.chain_scope_kind == "workspace" and event.chain_scope_id == ^workspace_id
    )
    |> Repo.delete_all()

    install_signed_audit_genesis!("workspace", workspace_id, owner_id)
  end

  defp role_change_body(_workspace_id, user_id, previous_role, role, _permission_version) do
    %{
      "user_id" => user_id,
      "previous_role_id" => previous_role.id,
      "previous_base_role" => previous_role.base_role,
      "new_role_id" => role.id,
      "new_base_role" => role.base_role
    }
  end
end
