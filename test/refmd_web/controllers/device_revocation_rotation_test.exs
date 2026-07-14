defmodule RefMDWeb.DeviceRevocationRotationTest do
  use RefMDWeb.ConnCase, async: true

  alias RefMD.Auth
  alias RefMD.Crypto.{Encoding, Hash, JCS, Signature}
  alias RefMD.Devices.Device
  alias RefMD.Documents.Document
  alias RefMD.Encryption.KeyDirectory
  alias RefMD.Encryption.KeyDirectory.{Payload, State}
  alias RefMD.Repo
  alias RefMD.Users.User
  alias RefMD.Workspaces

  @protocol_version 1
  @signature_protocol "refmd.hybrid-signature"
  @suite_id "refmd-v2-hybrid-signature-ed25519-mldsa65"
  @suite_rank 1000
  @mldsa_context_prefix "RefMD:v2:"

  test "security device revocation returns affected workspaces and KEK rotation completion clears state",
       %{conn: conn} do
    user_id = create_user("device-revocation-rotation@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(user_id, "Device Revocation Rotation")

    workspace =
      workspace
      |> Ecto.Changeset.change(current_kek_version: 1, min_kek_version: 1)
      |> Repo.update!()

    document =
      Repo.insert!(%Document{
        workspace_id: workspace.id,
        created_by: user_id,
        title: "Security rotation",
        slug: "security-rotation-#{Ecto.UUID.generate()}",
        doc_type: "document",
        is_encrypted: false,
        needs_dek_rotation: true,
        dek_rotation_reason: "time_based"
      })

    current_device = create_device(user_id)
    target_device = insert_device_fixture(user_id)
    identity_private = hybrid_signing_private_key_material("identity", user_id)
    identity_encryption = RefMD.Encryption.get_user_identity_public_key(user_id)

    current = ensure_test_user_rrp_key_directory!(user_id, current_device.device)

    insert_test_workspace_key_directory!(
      workspace.id,
      user_id,
      owner_role_id(workspace.id),
      identity_private,
      identity_encryption.hybrid_encryption_public_key_material,
      current_device.signing_private_key,
      current.hybrid_encryption_public_key_material
    )

    append_device_to_user_key_directory!(user_id, target_device.device, identity_private)

    append_device_to_workspace_key_directory!(
      workspace.id,
      user_id,
      current,
      current_device.signing_private_key,
      target_device.device
    )

    user_append =
      user_revocation_key_directory_append!(
        user_id,
        target_device.device,
        identity_private,
        "security"
      )

    workspace_append =
      workspace_revocation_key_directory_append!(
        workspace.id,
        user_id,
        current,
        current_device.signing_private_key,
        target_device.device,
        "security"
      )

    revoked_at_ms = System.system_time(:millisecond)

    body = %{
      "revocation_mode" => "security",
      "revoked_at" => revoked_at_ms,
      "revocation_signature" =>
        device_revocation_signature(
          user_id,
          current,
          current_device.signing_private_key,
          target_device.device,
          "security",
          revoked_at_ms
        ),
      "user_key_directory_events" => user_append.events,
      "user_key_directory_checkpoint" => user_append.checkpoint,
      "workspace_key_directory_appends" => [
        %{
          "workspace_id" => workspace.id,
          "events" => workspace_append.events,
          "checkpoint" => workspace_append.checkpoint
        }
      ]
    }

    path = "/api/devices/#{target_device.device.id}"

    conn =
      conn
      |> authed_conn(user_id, current)
      |> put_test_rrp_headers(
        user_id,
        current,
        current_device.signing_private_key,
        "DELETE",
        path,
        body
      )
      |> delete(path, test_json_body(body))

    assert %{
             "revoked_device_id" => target_device.device.id,
             "revocation_mode" => "security",
             "workspaces_needing_kek_rotation" => [
               %{
                 "workspace_id" => workspace.id,
                 "current_kek_version" => 1
               }
             ]
           } == json_response(conn, 200)

    assert Repo.get!(Device, target_device.device.id).revoked_at

    rotating_workspace = Workspaces.get_workspace(workspace.id)
    assert rotating_workspace.needs_kek_rotation
    assert rotating_workspace.kek_rotation_initiator_user_id == user_id
    assert Repo.reload!(document).needs_dek_rotation
    assert Repo.reload!(document).dek_rotation_reason == "security"

    start_body =
      kek_rotation_start_key_directory_append(
        workspace.id,
        user_id,
        current.id,
        current_device.signing_private_key,
        rotating_workspace.current_kek_version,
        rotating_workspace.current_kek_version + 1
      )

    assert {:ok, _workspace} =
             Workspaces.start_kek_rotation(workspace.id, user_id,
               workspace_key_directory_events: start_body["workspace_key_directory_events"],
               workspace_key_directory_checkpoint:
                 start_body["workspace_key_directory_checkpoint"]
             )

    complete_body =
      kek_rotation_complete_key_directory_append(
        workspace.id,
        user_id,
        current.id,
        current_device.signing_private_key,
        rotating_workspace.current_kek_version,
        rotating_workspace.current_kek_version + 1
      )

    assert :ok =
             Workspaces.complete_kek_rotation(
               workspace.id,
               rotating_workspace.current_kek_version + 1,
               envelope_checks: fn -> :ok end,
               workspace_key_directory_events: complete_body["workspace_key_directory_events"],
               workspace_key_directory_checkpoint:
                 complete_body["workspace_key_directory_checkpoint"],
               device_key_deletion_proofs: complete_body["device_key_deletion_proofs"],
               wipe_required_device_ids: complete_body["wipe_required_device_ids"]
             )

    completed_workspace = Workspaces.get_workspace(workspace.id)
    refute completed_workspace.needs_kek_rotation
    assert completed_workspace.kek_rotation_initiator_user_id == nil
    assert completed_workspace.current_kek_version == 2
    assert completed_workspace.min_kek_version == 2
  end

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

  defp insert_device_fixture(user_id) do
    device_id = Ecto.UUID.generate()
    keys = hybrid_device_material(device_id)
    {ecdh_public_key, _ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)
    encryption = hybrid_encryption_public_key_material("device", device_id, ecdh_public_key)
    client_nonce = :crypto.strong_rand_bytes(16)
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    checkpoint_hash = Hash.blake3_base64url("fixture-device-checkpoint:" <> device_id)

    device =
      Repo.insert!(%Device{
        id: device_id,
        user_id: user_id,
        name: "Browser",
        device_type: "browser",
        hybrid_encryption_public_key_material: encryption.public,
        encryption_key_id: encryption.encryption_key_id,
        hybrid_signing_public_key_material: keys.public,
        signing_key_id: keys.signing_key_id,
        approval_signature: %{"fixture" => "direct-device"},
        approval_signature_surface: "device_approval",
        approval_proof: %{
          "target_key_checkpoint_sequence" => 1,
          "target_key_checkpoint_hash" => checkpoint_hash
        },
        key_checkpoint_sequence: 1,
        key_checkpoint_hash: checkpoint_hash,
        client_nonce: client_nonce,
        last_seen_at: now,
        created_at: now
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

  defp owner_role_id(workspace_id) do
    workspace_id
    |> Workspaces.list_workspace_roles()
    |> Enum.find(&(&1.base_role == "owner"))
    |> Map.fetch!(:id)
  end

  defp append_device_to_user_key_directory!(user_id, target_device, identity_private) do
    pin = KeyDirectory.current_pin("user", user_id)
    checkpoint = KeyDirectory.current_checkpoint("user", user_id)
    identity_public = hybrid_signing_public_key_material(identity_private)
    identity_signing_key_id = Signature.compute_signing_key_id!(identity_public)

    event =
      device_key_added_event(
        "user",
        user_id,
        pin,
        identity_actor(user_id, identity_signing_key_id),
        target_device
      )

    checkpoint_payload =
      checkpoint.payload
      |> append_device_key_entries("user", user_id, event, target_device)
      |> next_checkpoint_payload(checkpoint, event)

    KeyDirectory.append_signed_scope!(
      "user",
      user_id,
      [signed_key_directory_event_envelope(event, identity_private)],
      signed_key_directory_checkpoint_envelope(
        checkpoint_payload,
        "identity_active",
        identity_private
      ),
      checkpoint_signer_kind: "identity"
    )
  end

  defp append_device_to_workspace_key_directory!(
         workspace_id,
         user_id,
         actor_device,
         actor_private,
         target_device
       ) do
    pin = KeyDirectory.current_pin("workspace", workspace_id)
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)
    actor_public = hybrid_signing_public_key_material(actor_private)
    actor_signing_key_id = Signature.compute_signing_key_id!(actor_public)

    event =
      device_key_added_event(
        "workspace",
        workspace_id,
        pin,
        device_actor(user_id, actor_device.id, actor_signing_key_id),
        target_device
      )

    checkpoint_payload =
      checkpoint.payload
      |> append_device_key_entries("workspace", workspace_id, event, target_device)
      |> next_checkpoint_payload(checkpoint, event)

    KeyDirectory.append_signed_scope!(
      "workspace",
      workspace_id,
      [signed_key_directory_event_envelope(event, actor_private)],
      signed_key_directory_checkpoint_envelope(
        checkpoint_payload,
        "workspace_authorized",
        actor_private,
        user_id
      ),
      checkpoint_signer_kind: "device"
    )
  end

  defp user_revocation_key_directory_append!(user_id, target_device, identity_private, reason) do
    pin = KeyDirectory.current_pin("user", user_id)
    checkpoint = KeyDirectory.current_checkpoint("user", user_id)
    identity_public = hybrid_signing_public_key_material(identity_private)
    identity_signing_key_id = Signature.compute_signing_key_id!(identity_public)
    actor = identity_actor(user_id, identity_signing_key_id)

    {signing_event, encryption_event, checkpoint_payload} =
      revocation_events_and_checkpoint(
        "user",
        user_id,
        pin,
        checkpoint,
        actor,
        target_device,
        reason
      )

    %{
      events:
        Enum.map([signing_event, encryption_event], fn event ->
          signed_key_directory_event_envelope(event, identity_private)
        end),
      checkpoint:
        signed_key_directory_checkpoint_envelope(
          checkpoint_payload,
          "identity_active",
          identity_private
        )
    }
  end

  defp workspace_revocation_key_directory_append!(
         workspace_id,
         user_id,
         actor_device,
         actor_private,
         target_device,
         reason
       ) do
    pin = KeyDirectory.current_pin("workspace", workspace_id)
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)
    actor_public = hybrid_signing_public_key_material(actor_private)
    actor_signing_key_id = Signature.compute_signing_key_id!(actor_public)
    actor = device_actor(user_id, actor_device.id, actor_signing_key_id)

    {signing_event, encryption_event, checkpoint_payload} =
      revocation_events_and_checkpoint(
        "workspace",
        workspace_id,
        pin,
        checkpoint,
        actor,
        target_device,
        reason
      )

    %{
      events:
        Enum.map([signing_event, encryption_event], fn event ->
          signed_key_directory_event_envelope(event, actor_private)
        end),
      checkpoint:
        signed_key_directory_checkpoint_envelope(
          checkpoint_payload,
          "workspace_authorized",
          actor_private,
          user_id
        )
    }
  end

  defp device_key_added_event(scope_kind, scope_id, pin, actor, target_device) do
    event_sequence = pin.event_head_sequence + 1

    key_directory_event_payload!(%{
      "scope_kind" => scope_kind,
      "scope_id" => scope_id,
      "sequence" => event_sequence,
      "event_type" => "device_key_added",
      "actor" => actor,
      "previous_event_hash" => pin.event_head_hash,
      "body" => %{
        "user_id" => target_device.user_id,
        "device_id" => target_device.id,
        "signing_key_id" => target_device.signing_key_id,
        "encryption_key_id" => target_device.encryption_key_id
      }
    })
  end

  defp revocation_events_and_checkpoint(
         scope_kind,
         scope_id,
         pin,
         checkpoint,
         actor,
         target_device,
         reason
       ) do
    signing_sequence = pin.event_head_sequence + 1

    signing_event =
      key_directory_event_payload!(%{
        "scope_kind" => scope_kind,
        "scope_id" => scope_id,
        "sequence" => signing_sequence,
        "event_type" => "signing_key_revoked",
        "actor" => actor,
        "previous_event_hash" => pin.event_head_hash,
        "body" => %{
          "key_id" => target_device.signing_key_id,
          "reason" => reason,
          "revoked_at_event_sequence" => signing_sequence
        }
      })

    encryption_sequence = signing_sequence + 1

    encryption_event =
      key_directory_event_payload!(%{
        "scope_kind" => scope_kind,
        "scope_id" => scope_id,
        "sequence" => encryption_sequence,
        "event_type" => "encryption_key_revoked",
        "actor" => actor,
        "previous_event_hash" => KeyDirectory.event_hash(signing_event),
        "body" => %{
          "key_id" => target_device.encryption_key_id,
          "reason" => reason,
          "revoked_at_event_sequence" => encryption_sequence
        }
      })

    checkpoint_payload =
      checkpoint.payload
      |> State.revoke_key_entry!(target_device.signing_key_id, signing_event)
      |> State.revoke_key_entry!(target_device.encryption_key_id, encryption_event)
      |> next_checkpoint_payload(checkpoint, encryption_event)

    {signing_event, encryption_event, checkpoint_payload}
  end

  defp append_device_key_entries(checkpoint_payload, scope_kind, scope_id, event, target_device) do
    target_signing_material = target_device.hybrid_signing_public_key_material
    target_encryption_material = target_device.hybrid_encryption_public_key_material

    checkpoint_payload
    |> Map.update!("device_keys", fn keys ->
      keys ++
        [
          Payload.key_entry!(
            target_signing_material,
            key_directory_event_ref(scope_kind, scope_id, event)
          ),
          Payload.key_entry!(
            target_encryption_material,
            key_directory_event_ref(scope_kind, scope_id, event)
          )
        ]
    end)
  end

  defp next_checkpoint_payload(checkpoint_payload, checkpoint, head_event) do
    KeyDirectory.build_checkpoint_payload!(
      checkpoint_payload
      |> Map.put("sequence", checkpoint.sequence + 1)
      |> Map.put(
        "issued_at",
        DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601()
      )
      |> Map.put("previous_checkpoint_hash", checkpoint.checkpoint_hash)
      |> Map.put("covered_event_head", key_directory_event_head(head_event))
    )
  end

  defp key_directory_event_payload!(attrs) do
    attrs
    |> put_initial_event_actor_authority()
    |> KeyDirectory.build_event_payload!()
  end

  defp put_initial_event_actor_authority(
         %{
           "actor" => actor,
           "sequence" => sequence,
           "scope_kind" => scope_kind,
           "scope_id" => scope_id
         } =
           attrs
       )
       when is_map(actor) and is_integer(sequence) and sequence > 1 do
    if Map.has_key?(actor, "key_checkpoint_sequence") and
         Map.has_key?(actor, "key_checkpoint_hash") do
      attrs
    else
      Map.put(
        attrs,
        "actor",
        Map.merge(actor, initial_event_actor_authority(scope_kind, scope_id))
      )
    end
  end

  defp put_initial_event_actor_authority(attrs), do: attrs

  defp initial_event_actor_authority(scope_kind, scope_id) do
    %{
      "key_scope_kind" => scope_kind,
      "key_scope_id" => scope_id,
      "key_checkpoint_sequence" => 1,
      "key_checkpoint_hash" =>
        Hash.blake3_base64url(
          JCS.canonical_bytes!(%{
            "protocol" => "refmd.initial-key-directory-authority",
            "version" => 1,
            "scope_kind" => scope_kind,
            "scope_id" => scope_id
          })
        )
    }
  end

  defp identity_actor(user_id, signing_key_id) do
    %{"signer_kind" => "identity", "user_id" => user_id, "signing_key_id" => signing_key_id}
  end

  defp device_actor(user_id, device_id, signing_key_id) do
    %{
      "signer_kind" => "device",
      "user_id" => user_id,
      "device_id" => device_id,
      "signing_key_id" => signing_key_id
    }
  end

  defp device_revocation_signature(
         user_id,
         actor_device,
         actor_private,
         target_device,
         revocation_mode,
         revoked_at_ms
       ) do
    actor_public = hybrid_signing_public_key_material(actor_private)
    signing_key_id = Signature.compute_signing_key_id!(actor_public)

    transcript =
      Signature.build_device_revocation_transcript!(
        user_id,
        actor_device.id,
        signing_key_id,
        target_device.id,
        revocation_mode,
        revoked_at_ms
      )

    sign_transcript(actor_private, actor_public, "device_revocation", transcript)
  end

  defp sign_transcript(private_material, public_material, signing_purpose, transcript) do
    transcript_bytes = JCS.canonical_bytes!(transcript)

    %{
      "protocol" => @signature_protocol,
      "version" => @protocol_version,
      "suite_id" => @suite_id,
      "suite_rank" => @suite_rank,
      "signing_key_id" => Signature.compute_signing_key_id!(public_material),
      "transcript_hash" => Hash.blake3_base64url(transcript_bytes),
      "ed25519" =>
        private_material["ed25519_private"]
        |> Encoding.decode_base64url!(32)
        |> then(&:crypto.sign(:eddsa, :none, transcript_bytes, [&1, :ed25519]))
        |> Encoding.encode_base64url(),
      "mldsa65" =>
        mldsa65_sign(
          transcript_bytes,
          @mldsa_context_prefix <> signing_purpose,
          Encoding.decode_base64url!(private_material["mldsa65_private"], 4032)
        )
        |> Encoding.encode_base64url()
    }
  end
end
