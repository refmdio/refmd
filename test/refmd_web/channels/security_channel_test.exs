defmodule RefMDWeb.SecurityChannelTest do
  use RefMDWeb.ConnCase

  import Phoenix.ChannelTest

  alias RefMD.Auth
  alias RefMD.Crypto.{Hash, Signature}
  alias RefMD.Devices.{Device, DeviceRegistration}
  alias RefMD.Repo
  alias RefMD.Security
  alias RefMD.Security.{AuditEvent, Notification}
  alias RefMD.Users.User
  alias RefMD.Workspaces
  alias RefMD.Workspaces.{Workspace, WorkspaceMember, WorkspaceRole}

  @endpoint RefMDWeb.Endpoint

  test "existing device joins user security notifications and receives pending registration notifications" do
    user = create_user("security-user@example.com")
    device = create_device(user.id)
    {:ok, session, _token} = Auth.create_session(user.id, %{device_id: device.id})
    pending = create_registration(user.id)

    {:ok, _reply, _socket} =
      subscribe_and_join(user_socket(user.id, session), "security:user:#{user.id}", %{})

    assert {:ok, _} = Security.record_device_registration_created(user.id, pending)

    assert_push "notification", %{
      type: "device.pending_approval",
      audit_checkpoint: %{
        chain_scope: chain_scope,
        sequence: 1,
        event_hash: event_hash
      },
      action_ref: %{
        "device_id" => device_id,
        "name" => "New browser",
        "device_type" => "browser"
      }
    }

    assert chain_scope == "user:#{user.id}"
    assert is_binary(event_hash)
    assert device_id == pending.id

    assert Repo.get_by(AuditEvent,
             type: "device.registration.created",
             chain_scope: "user:#{user.id}"
           )

    assert Repo.get_by(Notification, type: "device.pending_approval", recipient_id: user.id)
  end

  test "user security notifications require an existing bound device session" do
    user = create_user("unbound-security@example.com")
    {:ok, session, _token} = Auth.create_session(user.id)

    assert {:error, %{reason: "existing_device_required"}} =
             subscribe_and_join(user_socket(user.id, session), "security:user:#{user.id}", %{})
  end

  test "pending registration joins its security topic and receives approval" do
    user = create_user("registration-security@example.com")
    pending = create_registration(user.id)
    {:ok, session, _token} = Auth.create_session(user.id)

    {:ok, _reply, _socket} =
      subscribe_and_join(
        user_socket(user.id, session),
        "security:pending_registration:#{pending.id}",
        %{}
      )

    assert {:ok, _} = Security.record_registration_approved(user.id, pending.id)

    assert_push "notification", %{
      type: "device.registration_approved",
      action_ref: %{"device_id" => device_id}
    }

    assert device_id == pending.id
  end

  test "pending registration receives non-terminal Initial AKE offer readiness" do
    user = create_user("registration-ake-ready@example.com")
    pending = create_registration(user.id)
    {:ok, session, _token} = Auth.create_session(user.id)

    {:ok, _reply, socket} =
      subscribe_and_join(
        user_socket(user.id, session),
        "security:pending_registration:#{pending.id}",
        %{}
      )

    assert {:ok, _} = Security.record_initial_ake_offers_ready(user.id, pending.id)

    assert_push "notification", %{
      type: "device.initial_ake_offers_ready",
      action_ref: %{"device_id" => device_id}
    }

    assert device_id == pending.id
    assert socket.channel_pid |> Process.alive?()
  end

  test "current device joins device security notifications" do
    user = create_user("device-security@example.com")
    device = create_device(user.id)
    {:ok, session, _token} = Auth.create_session(user.id, %{device_id: device.id})

    {:ok, _reply, _socket} =
      subscribe_and_join(user_socket(user.id, session), "security:device:#{device.id}", %{})

    assert {:ok, _} =
             Security.record_audit_event(
               security_event("security.device.test", "device", device.id),
               [
                 %{
                   recipient_kind: "device",
                   recipient_id: device.id,
                   type: "security.device.test",
                   severity: "warning",
                   action_ref: %{device_id: device.id},
                   dedupe_key: "security.device.test:#{device.id}"
                 }
               ]
             )

    assert_push "notification", %{
      type: "security.device.test",
      action_ref: %{"device_id" => device_id}
    }

    assert device_id == device.id
  end

  test "workspace owners join workspace security notifications" do
    user = create_user("workspace-security@example.com")
    device = create_device(user.id)
    workspace = create_workspace(user.id)
    {:ok, session, _token} = Auth.create_session(user.id, %{device_id: device.id})

    {:ok, _reply, _socket} =
      subscribe_and_join(
        user_socket(user.id, session),
        "security:workspace:#{workspace.id}",
        %{}
      )

    assert {:ok, _} =
             Security.record_audit_event(
               security_event("security.workspace.test", "plugin", "com.example.notes")
               |> put_in([:scope, "workspace_id"], workspace.id),
               [
                 %{
                   recipient_kind: "workspace_role",
                   recipient_id: workspace.id,
                   type: "security.workspace.test",
                   severity: "action_required",
                   action_ref: %{workspace_id: workspace.id},
                   dedupe_key: "security.workspace.test:#{workspace.id}"
                 }
               ]
             )

    assert_push "notification", %{
      type: "security.workspace.test",
      audit_checkpoint: %{
        chain_scope: chain_scope,
        sequence: 1,
        event_hash: event_hash
      },
      action_ref: %{"workspace_id" => workspace_id}
    }

    assert chain_scope == "workspace:#{workspace.id}"
    assert is_binary(event_hash)
    assert workspace_id == workspace.id
  end

  test "pending registration security topic rejects another user's registration" do
    user = create_user("registration-owner@example.com")
    other_user = create_user("registration-other@example.com")
    pending = create_registration(other_user.id)
    {:ok, session, _token} = Auth.create_session(user.id)

    assert {:error, %{reason: "registration_not_found"}} =
             subscribe_and_join(
               user_socket(user.id, session),
               "security:pending_registration:#{pending.id}",
               %{}
             )
  end

  test "device security topic rejects a different bound device" do
    user = create_user("device-owner@example.com")
    device = create_device(user.id)
    other_device = create_device(user.id)
    {:ok, session, _token} = Auth.create_session(user.id, %{device_id: device.id})

    assert {:error, %{reason: "existing_device_required"}} =
             subscribe_and_join(
               user_socket(user.id, session),
               "security:device:#{other_device.id}",
               %{}
             )
  end

  test "workspace security topic rejects non-admin users" do
    owner = create_user("workspace-owner@example.com")
    user = create_user("workspace-other@example.com")
    device = create_device(user.id)
    workspace = create_workspace(owner.id)
    {:ok, session, _token} = Auth.create_session(user.id, %{device_id: device.id})

    assert {:error, %{reason: "workspace_not_found"}} =
             subscribe_and_join(
               user_socket(user.id, session),
               "security:workspace:#{workspace.id}",
               %{}
             )
  end

  test "plugin consent-required notifications are delivered to regular member user topics" do
    owner = create_user("plugin-consent-owner@example.com")
    member = create_user("plugin-consent-member@example.com")
    device = create_device(member.id)
    {:ok, workspace} = Workspaces.create_default_workspace(owner.id, "Plugin consent workspace")
    add_workspace_member(workspace.id, member.id, "editor")
    {:ok, session, _token} = Auth.create_session(member.id, %{device_id: device.id})

    {:ok, _reply, _socket} =
      subscribe_and_join(user_socket(member.id, session), "security:user:#{member.id}", %{})

    assert {:ok, _} =
             Security.record_audit_event(
               security_event("plugin.bundle.promoted", "plugin", "com.example.notes"),
               [
                 %{
                   recipient_kind: "user",
                   recipient_id: member.id,
                   type: "plugin.consent_required",
                   severity: "action_required",
                   action_ref: %{
                     workspace_id: workspace.id,
                     application_id: Ecto.UUID.generate(),
                     plugin_id: "com.example.notes",
                     bundle_hash: hash("bundle")
                   },
                   dedupe_key: "plugin.consent_required:#{member.id}"
                 }
               ]
             )

    assert_push "notification", %{
      type: "plugin.consent_required",
      action_ref: %{"workspace_id" => workspace_id, "plugin_id" => "com.example.notes"}
    }

    assert workspace_id == workspace.id

    assert Repo.get_by(Notification,
             type: "plugin.consent_required",
             recipient_kind: "user",
             recipient_id: member.id
           )
  end

  test "security topics reject share participant sockets" do
    principal_id = Ecto.UUID.generate()
    share_session = %{device_id: Ecto.UUID.generate()}

    assert {:error, %{reason: "user_session_required"}} =
             subscribe_and_join(
               share_participant_socket(principal_id, share_session),
               "security:user:#{principal_id}",
               %{}
             )

    assert {:error, %{reason: "user_session_required"}} =
             subscribe_and_join(
               share_participant_socket(principal_id, share_session),
               "security:pending_registration:#{Ecto.UUID.generate()}",
               %{}
             )

    assert {:error, %{reason: "user_session_required"}} =
             subscribe_and_join(
               share_participant_socket(principal_id, share_session),
               "security:device:#{Ecto.UUID.generate()}",
               %{}
             )

    assert {:error, %{reason: "user_session_required"}} =
             subscribe_and_join(
               share_participant_socket(principal_id, share_session),
               "security:workspace:#{Ecto.UUID.generate()}",
               %{}
             )
  end

  defp user_socket(user_id, session) do
    socket(RefMDWeb.UserSocket, nil, %{
      current_user_id: user_id,
      current_session: session
    })
  end

  defp share_participant_socket(principal_id, session) do
    socket(RefMDWeb.UserSocket, nil, %{
      current_user_id: principal_id,
      current_session: session,
      session_kind: :share_participant
    })
  end

  defp create_user(email) do
    Repo.insert!(%User{
      id: Ecto.UUID.generate(),
      email: email,
      name: email
    })
  end

  defp create_device(user_id) do
    now = DateTime.utc_now()
    id = Ecto.UUID.generate()
    material = hybrid_material("device", id)
    ecdh_public_key = :crypto.strong_rand_bytes(32)
    encryption = hybrid_encryption_public_key_material("device", id, ecdh_public_key)
    client_nonce = :crypto.strong_rand_bytes(16)

    Repo.insert!(%Device{
      id: id,
      user_id: user_id,
      name: "Existing browser",
      device_type: "browser",
      hybrid_encryption_public_key_material: encryption.public,
      encryption_key_id: encryption.encryption_key_id,
      hybrid_signing_public_key_material: material,
      signing_key_id: Signature.compute_signing_key_id!(material),
      approval_signature: %{},
      approval_signature_surface: "genesis_device_bootstrap",
      key_checkpoint_sequence: 1,
      key_checkpoint_hash: Hash.blake3_base64url("checkpoint:" <> id),
      approval_proof:
        genesis_device_approval_proof(
          user_id,
          id,
          material,
          ecdh_public_key,
          encryption.public,
          client_nonce
        ),
      client_nonce: client_nonce,
      last_seen_at: now,
      created_at: now
    })
  end

  defp create_registration(user_id) do
    now = DateTime.utc_now()
    id = Ecto.UUID.generate()
    material = hybrid_material("device", id)
    ecdh_public_key = :crypto.strong_rand_bytes(32)
    encryption = hybrid_encryption_public_key_material("device", id, ecdh_public_key)

    Repo.insert!(%DeviceRegistration{
      id: id,
      user_id: user_id,
      name: "New browser",
      device_type: "browser",
      hybrid_encryption_public_key_material: encryption.public,
      encryption_key_id: encryption.encryption_key_id,
      hybrid_signing_public_key_material: material,
      signing_key_id: Signature.compute_signing_key_id!(material),
      pending_registration_challenge_hash: Hash.blake3_base64url("registration:" <> id),
      client_nonce: :crypto.strong_rand_bytes(16),
      ip_address: "127.0.0.1",
      created_at: now,
      expires_at: DateTime.add(now, 300, :second)
    })
  end

  defp create_workspace(owner_id) do
    Repo.insert!(%Workspace{
      id: Ecto.UUID.generate(),
      name: "Security workspace",
      slug: "security-workspace-#{System.unique_integer([:positive])}",
      owner_id: owner_id
    })
  end

  defp add_workspace_member(workspace_id, user_id, base_role) do
    role = Repo.get_by!(WorkspaceRole, workspace_id: workspace_id, base_role: base_role)

    Repo.insert!(%WorkspaceMember{
      workspace_id: workspace_id,
      user_id: user_id,
      role_id: role.id,
      joined_at: DateTime.utc_now()
    })
  end

  defp security_event(type, resource_kind, resource_id) do
    %{
      class: "security_runtime",
      type: type,
      actor: %{"kind" => "system", "id" => nil, "device_id" => nil},
      scope: %{"workspace_id" => nil, "document_id" => nil, "share_id" => nil},
      resource: %{"kind" => resource_kind, "id" => resource_id, "version_hash" => nil},
      action: %{"operation" => type, "result" => "completed", "reason_code" => nil},
      sensitivity: %{"category" => "none"},
      correlation: %{
        "request_id" => nil,
        "capability_id" => nil,
        "execution_context_id" => nil,
        "authority_event_ref" => nil
      }
    }
  end

  defp hash(value), do: Hash.blake3_base64url(value)

  defp hybrid_material(owner_kind, owner_id) do
    %{
      "protocol" => "refmd.hybrid-signing-key-material",
      "version" => 1,
      "owner_kind" => owner_kind,
      "owner_id" => owner_id,
      "ed25519_public" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
      "mldsa65_public" => Base.url_encode64(:crypto.strong_rand_bytes(1952), padding: false),
      "suite_id" => "refmd-v2-hybrid-signature-ed25519-mldsa65",
      "suite_rank" => 1000
    }
  end
end
