defmodule RefMDWeb.UmkControllerTest do
  use RefMDWeb.ConnCase, async: true

  import Ecto.Query

  alias Ecto.Changeset
  alias RefMD.Crypto.{Hash, JCS}
  alias RefMD.Devices
  alias RefMD.Devices.{DeviceEncryptedUMK, DeviceRegistration}
  alias RefMD.Encryption
  alias RefMD.Repo
  alias RefMD.Security
  alias RefMD.Security.{AuditEvent, Notification}
  alias RefMD.TestCrypto
  alias RefMD.Users.User
  alias RefMD.Workspaces
  alias RefMDWeb.{DeviceController, UmkController}

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

  defp device_attrs(user_id, device_id) do
    keys = hybrid_device_material(device_id)
    {ecdh_public_key, _ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)
    encryption = hybrid_encryption_public_key_material("device", device_id, ecdh_public_key)
    client_nonce = :crypto.strong_rand_bytes(16)

    %{
      id: device_id,
      user_id: user_id,
      name: "Browser",
      device_type: "browser",
      hybrid_encryption_public_key_material: encryption.public,
      hybrid_signing_public_key_material: keys.public,
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
      client_nonce: client_nonce,
      pending_registration_challenge_hash: Hash.blake3_base64url("challenge"),
      expires_at: DateTime.add(DateTime.utc_now(), 300, :second)
    }
  end

  defp create_device(user_id) do
    device_id = Ecto.UUID.generate()
    {:ok, device} = Devices.create_device(device_attrs(user_id, device_id))
    device
  end

  defp create_approved_registration(user_id, sender_device) do
    device_id = Ecto.UUID.generate()
    {:ok, registration} = Devices.create_device_registration(device_attrs(user_id, device_id))

    commitments = %{
      "umk_distribution_delivery_commitment" => %{},
      "trust_transfer_delivery_commitment" => %{},
      "device_approval_kek_initial_delivery_commitments" => []
    }

    registration
    |> Changeset.change(%{
      approval_signature:
        device_approval_signature(
          user_id,
          sender_device.id,
          registration.id,
          registration.hybrid_signing_public_key_material,
          registration.hybrid_encryption_public_key_material,
          registration.client_nonce,
          commitments
        ),
      approval_signature_surface: "device_approval",
      approval_proof:
        device_approval_proof(
          user_id,
          sender_device.id,
          registration.id,
          registration.hybrid_signing_public_key_material,
          registration.hybrid_encryption_public_key_material,
          registration.client_nonce,
          commitments
        ),
      approval_delivery_commitments: commitments,
      approval_delivery_artifacts: %{
        "initial_ake_offers" => initial_ake_offer_bundle(sender_device.id, registration.id)
      },
      approval_key_directory: %{
        "user_key_directory_events" => [],
        "user_key_directory_checkpoint" => %{},
        "workspace_key_directory_appends" => []
      }
    })
    |> Repo.update!()
  end

  defp initial_ake_offer_bundle(sender_device_id, recipient_device_id) do
    %{
      "umk_distribution" =>
        initial_ake_offer("umk_distribution", sender_device_id, recipient_device_id, "umk-prekey"),
      "trust_transfer" =>
        initial_ake_offer("trust_transfer", sender_device_id, recipient_device_id, "trust-prekey"),
      "device_approval_kek_initial" => %{}
    }
  end

  defp initial_ake_offer(purpose, sender_device_id, recipient_device_id, prekey_id) do
    %{
      "purpose" => purpose,
      "transcript_hash" => Hash.blake3_base64url("#{purpose}-transcript"),
      "transcript" => %{
        "initiator" => %{"device_id" => sender_device_id},
        "responder" => %{"device_id" => recipient_device_id, "prekey_id" => prekey_id}
      }
    }
  end

  defp response_bundle(offers) do
    response = fn offer ->
      %{
        "protocol" => "refmd.initial-ake-responder-confirmation",
        "version" => 1,
        "purpose" => offer["purpose"],
        "transcript_hash" => offer["transcript_hash"],
        "prekey_id" => get_in(offer, ["transcript", "responder", "prekey_id"]),
        "responder_confirmation" =>
          Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
      }
    end

    %{
      "umk_distribution" => response.(offers["umk_distribution"]),
      "trust_transfer" => response.(offers["trust_transfer"]),
      "device_approval_kek_initial" => %{}
    }
  end

  defp approval_delivery_fixture(sender_device_id, recipient_device_id, workspace_id) do
    umk_delivery = initial_delivery_artifact("umk", sender_device_id, recipient_device_id)
    trust_delivery = initial_delivery_artifact("trust", sender_device_id, recipient_device_id)
    kek_delivery = initial_delivery_artifact("kek", sender_device_id, recipient_device_id)

    commitments = %{
      "umk_distribution_delivery_commitment" =>
        delivery_commitment(
          "umk_distribution",
          sender_device_id,
          recipient_device_id,
          umk_delivery
        ),
      "trust_transfer_delivery_commitment" =>
        delivery_commitment(
          "trust_transfer",
          sender_device_id,
          recipient_device_id,
          trust_delivery,
          %{
            "ake_session_id" => Ecto.UUID.generate(),
            "document_rollback_pin_set_hash" => Hash.blake3_base64url("rollback-pins"),
            "transfer_scope_hash" => Hash.blake3_base64url("transfer-scope"),
            "audit_checkpoint_pin_set_hash" => Hash.blake3_base64url("audit-pin-set")
          }
        ),
      "device_approval_kek_initial_delivery_commitments" => [
        delivery_commitment(
          "device_approval_kek_initial",
          sender_device_id,
          recipient_device_id,
          kek_delivery,
          %{"workspace_id" => workspace_id, "key_version" => 1}
        )
      ]
    }

    umk_attrs = %{
      sender_device_id: sender_device_id,
      initial_ake: %{"protocol" => "test"},
      initial_key_delivery: umk_delivery["initial_key_delivery"],
      initial_kek_deliveries: %{workspace_id => kek_delivery},
      device_state_delivery: trust_delivery
    }

    {commitments, umk_attrs}
  end

  defp initial_delivery_artifact(label, sender_device_id, recipient_device_id) do
    %{
      "initial_key_delivery" => %{
        "metadata" => %{
          "delivery_id" => Ecto.UUID.generate(),
          "sender_device_id" => sender_device_id,
          "recipient_device_id" => recipient_device_id,
          "key_confirmation_hash" => Hash.blake3_base64url("#{label}-confirmation")
        },
        "aead" => %{"ciphertext" => "#{label}-ciphertext"}
      }
    }
  end

  defp delivery_commitment(
         purpose,
         sender_device_id,
         recipient_device_id,
         artifact,
         extra \\ %{}
       ) do
    initial_key_delivery = artifact["initial_key_delivery"]
    metadata = initial_key_delivery["metadata"]

    Map.merge(
      %{
        "purpose" => purpose,
        "variant" => purpose,
        "delivery_id" => metadata["delivery_id"],
        "recipient_device_id" => recipient_device_id,
        "sender_device_id" => sender_device_id,
        "delivery_record_hash" =>
          Hash.blake3_base64url(
            JCS.canonical_bytes!(%{
              "metadata" => Map.delete(metadata, "key_confirmation_hash"),
              "aead" => initial_key_delivery["aead"]
            })
          ),
        "key_checkpoint_hash" => Hash.blake3_base64url("#{purpose}-checkpoint")
      },
      extra
    )
  end

  test "distribute_umk rejects invalid initial AKE delivery without finalizing the device", %{
    conn: conn
  } do
    user_id = create_user("umk-controller@example.com")
    sender = create_device(user_id)
    target = create_approved_registration(user_id, sender)

    response =
      conn
      |> Plug.Conn.assign(:current_user_id, user_id)
      |> Plug.Conn.assign(:rrp_device_id, sender.id)
      |> UmkController.distribute_umk(%{
        "device_id" => target.id,
        "sender_device_id" => sender.id,
        "initial_ake" => %{},
        "initial_key_delivery" => %{},
        "initial_kek_deliveries" => [],
        "device_state_delivery" => %{}
      })
      |> json_response(422)

    assert response["error"] == "invalid_initial_key_delivery"
    assert Repo.get(DeviceRegistration, target.id)
    refute Devices.get_device(target.id)
    refute Repo.get_by(DeviceEncryptedUMK, user_id: user_id, device_id: target.id)
  end

  test "pending responder stores one response bundle and rejects replay", %{conn: conn} do
    user_id = create_user("initial-ake-response@example.com")
    sender = create_device(user_id)
    target = create_approved_registration(user_id, sender)
    {:ok, %{offers: offers}} = Devices.get_initial_ake_exchange(user_id, target.id)
    responses = response_bundle(offers)
    pending_session = %{device_registration_id: target.id}

    response =
      conn
      |> Plug.Conn.assign(:current_user_id, user_id)
      |> Plug.Conn.assign(:current_session, pending_session)
      |> DeviceController.initial_ake_responses(%{
        "device_id" => target.id,
        "responses" => responses
      })
      |> json_response(201)

    assert response == %{"ok" => true}
    assert {:ok, %{responses: ^responses}} = Devices.get_initial_ake_exchange(user_id, target.id)

    replay =
      conn
      |> Plug.Conn.assign(:current_user_id, user_id)
      |> Plug.Conn.assign(:current_session, pending_session)
      |> DeviceController.initial_ake_responses(%{
        "device_id" => target.id,
        "responses" => responses
      })
      |> json_response(409)

    assert replay["error"] == "initial_ake_response_reused"
  end

  test "pending responder rejects a reflected or mismatched response bundle", %{conn: conn} do
    user_id = create_user("initial-ake-mismatch@example.com")
    sender = create_device(user_id)
    target = create_approved_registration(user_id, sender)
    {:ok, %{offers: offers}} = Devices.get_initial_ake_exchange(user_id, target.id)
    responses = response_bundle(offers)
    bad_responses = put_in(responses, ["umk_distribution", "purpose"], "trust_transfer")

    response =
      conn
      |> Plug.Conn.assign(:current_user_id, user_id)
      |> Plug.Conn.assign(:current_session, %{device_registration_id: target.id})
      |> DeviceController.initial_ake_responses(%{
        "device_id" => target.id,
        "responses" => bad_responses
      })
      |> json_response(422)

    assert response["error"] == "invalid_initial_ake_response"
    assert {:ok, %{responses: nil}} = Devices.get_initial_ake_exchange(user_id, target.id)
  end

  test "distribute_umk maps an audit failure to the fail-closed API response", %{conn: conn} do
    response =
      {:error, :security_audit_unavailable}
      |> UmkController.distribute_result_response(conn)
      |> json_response(503)

    assert response == %{"error" => "security_audit_unavailable"}
  end

  test "successful UMK finalization records and broadcasts one terminal event" do
    fixture = pending_delivery_fixture("umk-audit-success@example.com")
    :ok = Security.subscribe_pending_registration(fixture.target.id)

    assert {:ok, device} =
             Devices.finalize_pending_delivery(fixture.target, fixture.umk_attrs, [])

    assert device.id == fixture.target.id

    assert Repo.aggregate(
             from(event in AuditEvent,
               where:
                 event.chain_scope == ^"user:#{fixture.user_id}" and
                   event.type == "device.registration.approved"
             ),
             :count
           ) == 1

    assert Repo.aggregate(
             from(notification in Notification,
               where:
                 notification.recipient_kind == "pending_registration" and
                   notification.recipient_id == ^fixture.target.id and
                   notification.type == "device.registration_approved"
             ),
             :count
           ) == 1

    assert Repo.get!(Notification, fixture.pending_notification.id).acted_at
    assert_receive {:security_notification, %{type: "device.registration_approved"}}
    refute_receive {:security_notification, %{type: "device.registration_approved"}}
  end

  test "UMK finalization rolls back every mutation when the audit chain is invalid" do
    fixture = pending_delivery_fixture("umk-audit-atomicity@example.com")

    Repo.update_all(from(event in AuditEvent, where: event.id == ^fixture.created_event.id),
      set: [type: "device.registration_created_tampered"]
    )

    :ok = Security.subscribe_pending_registration(fixture.target.id)

    assert {:error, :security_audit_unavailable} =
             Devices.finalize_pending_delivery(
               fixture.target,
               fixture.umk_attrs,
               []
             )

    assert Repo.get(DeviceRegistration, fixture.target.id)
    refute Devices.get_device(fixture.target.id)

    refute Repo.get_by(DeviceEncryptedUMK,
             user_id: fixture.user_id,
             device_id: fixture.target.id
           )

    assert Encryption.current_user_key_directory_checkpoint(fixture.user_id).checkpoint_hash ==
             fixture.user_checkpoint.checkpoint_hash

    assert Encryption.current_workspace_key_directory_checkpoint(fixture.workspace.id).checkpoint_hash ==
             fixture.workspace_checkpoint.checkpoint_hash

    refute Repo.get!(Notification, fixture.pending_notification.id).acted_at

    refute Repo.get_by(AuditEvent,
             chain_scope: "user:#{fixture.user_id}",
             type: "device.registration.approved"
           )

    refute Repo.get_by(Notification,
             recipient_kind: "pending_registration",
             recipient_id: fixture.target.id,
             type: "device.registration_approved"
           )

    refute_receive {:security_notification, _payload}
  end

  defp pending_delivery_fixture(email) do
    %{
      user_id: user_id,
      workspace: workspace,
      sender: sender,
      sender_private: sender_private,
      identity_private: identity_private
    } = create_user_with_initial_device(email)

    target = create_approved_registration(user_id, sender)

    approval_key_directory =
      device_approval_key_directory_append(
        user_id,
        target.id,
        target.hybrid_signing_public_key_material,
        target.hybrid_encryption_public_key_material,
        identity_private,
        sender_private,
        [workspace.id]
      )

    target_checkpoint_payload = get_in(approval_key_directory, ["user_checkpoint", "payload"])
    approving_pin = Encryption.current_user_key_directory_pin(user_id)

    {approval_commitments, umk_attrs} =
      approval_delivery_fixture(sender.id, target.id, workspace.id)

    binding_context = %{
      "approved_device_registration_sas_hash" => Hash.blake3_base64url("sas"),
      "pending_registration_id" => target.id,
      "pending_registration_challenge_hash" => target.pending_registration_challenge_hash,
      "approving_owner_kind" => "device",
      "approving_owner_id" => sender.id,
      "approving_signing_key_id" => sender.signing_key_id,
      "approving_key_checkpoint_sequence" => approving_pin.checkpoint_sequence,
      "approving_key_checkpoint_hash" => approving_pin.checkpoint_hash,
      "approving_device_key_directory_proof_hash" => approving_pin.checkpoint_hash,
      "target_device_id" => target.id,
      "target_device_signing_key_id" => target.signing_key_id,
      "target_device_hybrid_signing_public_key_material_hash" =>
        Hash.blake3_base64url(JCS.canonical_bytes!(target.hybrid_signing_public_key_material)),
      "target_device_hybrid_encryption_public_key_material_hash" =>
        Hash.blake3_base64url(JCS.canonical_bytes!(target.hybrid_encryption_public_key_material)),
      "target_device_encryption_key_id" => target.encryption_key_id,
      "target_device_client_nonce_hash" => Hash.blake3_base64url(target.client_nonce),
      "target_key_checkpoint_sequence" => Map.fetch!(target_checkpoint_payload, "sequence"),
      "target_key_checkpoint_hash" =>
        Hash.blake3_base64url(JCS.canonical_bytes!(target_checkpoint_payload))
    }

    approval =
      device_approval_signature_and_proof(
        user_id,
        sender.id,
        target.id,
        target.hybrid_signing_public_key_material,
        target.hybrid_encryption_public_key_material,
        target.client_nonce,
        approval_commitments,
        binding_context
      )

    target =
      target
      |> Changeset.change(
        approval_signature: approval.signature,
        approval_proof: approval.proof,
        approval_delivery_commitments: approval_commitments,
        approval_key_directory: approval_key_directory
      )
      |> Repo.update!()

    {:ok, %{audit_event: created_event}} =
      Security.record_device_registration_created(user_id, target)

    pending_notification =
      Repo.get_by!(Notification,
        recipient_kind: "user",
        recipient_id: user_id,
        type: "device.pending_approval"
      )

    %{
      user_id: user_id,
      workspace: workspace,
      target: target,
      umk_attrs: umk_attrs,
      created_event: created_event,
      pending_notification: pending_notification,
      user_checkpoint: Encryption.current_user_key_directory_checkpoint(user_id),
      workspace_checkpoint: Encryption.current_workspace_key_directory_checkpoint(workspace.id)
    }
  end

  defp create_user_with_initial_device(email) do
    user_id = create_user(email)
    TestCrypto.install_signed_audit_genesis!("user", user_id, user_id)
    identity_private = hybrid_signing_private_key_material("identity", user_id)
    identity_public = hybrid_signing_public_key_material(identity_private)
    {identity_x25519_public, _} = :crypto.generate_key(:ecdh, :x25519)

    identity_encryption =
      hybrid_encryption_public_key_material("identity", user_id, identity_x25519_public)

    registration_challenge_hash = Hash.blake3_base64url("registration:initial")

    {:ok, _identity} =
      Encryption.create_user_identity_public_key(%{
        user_id: user_id,
        hybrid_encryption_public_key_material: identity_encryption.public,
        hybrid_signing_public_key_material: identity_public,
        pending_registration_challenge_hash: registration_challenge_hash
      })

    {:ok, workspace} = Workspaces.create_default_workspace(user_id, "UMK Audit Atomicity")
    {_member, owner_role} = Workspaces.get_member_with_role(workspace.id, user_id)
    sender_id = Ecto.UUID.generate()
    sender_signing = hybrid_device_material(sender_id)
    {sender_x25519_public, _} = :crypto.generate_key(:ecdh, :x25519)

    sender_encryption =
      hybrid_encryption_public_key_material("device", sender_id, sender_x25519_public)

    client_nonce = :crypto.strong_rand_bytes(16)
    registration_challenge_hash = Hash.blake3_base64url("registration:" <> sender_id)

    Encryption.get_user_identity_public_key(user_id)
    |> Changeset.change(pending_registration_challenge_hash: registration_challenge_hash)
    |> Repo.update!()

    key_directory =
      initial_key_directory_bootstrap(
        user_id,
        workspace.id,
        owner_role.id,
        identity_private,
        identity_encryption.public,
        sender_signing.private,
        sender_encryption.public
      )

    {:ok, sender} =
      Devices.create_device(%{
        id: sender_id,
        user_id: user_id,
        name: "Sender",
        device_type: "browser",
        hybrid_encryption_public_key_material: sender_encryption.public,
        hybrid_signing_public_key_material: sender_signing.public,
        client_nonce: client_nonce,
        pending_registration_challenge_hash: registration_challenge_hash,
        approval_signature:
          genesis_device_bootstrap_signature(
            user_id,
            sender_id,
            sender_signing.public,
            sender_x25519_public,
            sender_encryption.public,
            client_nonce
          ),
        approval_signature_surface: "genesis_device_bootstrap",
        approval_proof:
          genesis_device_approval_proof(
            user_id,
            sender_id,
            sender_signing.public,
            sender_x25519_public,
            sender_encryption.public,
            client_nonce
          )
      })

    Encryption.insert_initial_user_key_directory!(
      user_id,
      key_directory.user_events,
      key_directory.user_checkpoint,
      checkpoint_signer_kind: "identity"
    )

    Encryption.insert_initial_workspace_key_directory!(
      workspace.id,
      key_directory.workspace_events,
      key_directory.workspace_checkpoint,
      checkpoint_signer_kind: "device"
    )

    %{
      user_id: user_id,
      workspace: workspace,
      sender: sender,
      sender_private: sender_signing.private,
      identity_private: identity_private
    }
  end
end
