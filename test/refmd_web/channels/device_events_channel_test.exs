defmodule RefMDWeb.DeviceEventsChannelTest do
  use RefMDWeb.ConnCase

  import Phoenix.ChannelTest

  alias RefMD.Auth
  alias RefMD.Crypto.{Hash, Signature}
  alias RefMD.Devices
  alias RefMD.Devices.{Device, DeviceRegistration}
  alias RefMD.Repo
  alias RefMD.Users.User

  @endpoint RefMDWeb.Endpoint

  test "existing device joins user device events and receives pending registration events" do
    user = create_user("device-events@example.com")
    device = create_device(user.id)
    {:ok, session, _token} = Auth.create_session(user.id, %{device_id: device.id})
    pending = create_registration(user.id)

    {:ok, _reply, _socket} =
      subscribe_and_join(user_socket(user.id, session), "devices:user", %{})

    Devices.broadcast_device_registration_created(user.id, pending)

    assert_push "pending_device_created", %{
      device_id: device_id,
      name: "New browser",
      device_type: "browser"
    }

    assert device_id == pending.id
  end

  test "user device events require an existing bound device session" do
    user = create_user("unbound-device-events@example.com")
    {:ok, session, _token} = Auth.create_session(user.id)

    assert {:error, %{reason: "existing_device_required"}} =
             subscribe_and_join(user_socket(user.id, session), "devices:user", %{})
  end

  test "pending registration joins its registration topic and receives approval" do
    user = create_user("registration-events@example.com")
    pending = create_registration(user.id)
    {:ok, session, _token} = Auth.create_session(user.id)

    {:ok, _reply, _socket} =
      subscribe_and_join(
        user_socket(user.id, session),
        "devices:registration:#{pending.id}",
        %{}
      )

    Devices.broadcast_registration_approved(user.id, pending.id)

    assert_push "pending_approved", %{device_id: device_id}
    assert device_id == pending.id
  end

  test "pending registration topic rejects another user's registration" do
    user = create_user("registration-owner@example.com")
    other_user = create_user("registration-other@example.com")
    pending = create_registration(other_user.id)
    {:ok, session, _token} = Auth.create_session(user.id)

    assert {:error, %{reason: "device_not_found"}} =
             subscribe_and_join(
               user_socket(user.id, session),
               "devices:registration:#{pending.id}",
               %{}
             )
  end

  test "device event topics reject share participant sockets" do
    principal_id = Ecto.UUID.generate()
    share_session = %{device_id: Ecto.UUID.generate()}

    assert {:error, %{reason: "user_session_required"}} =
             subscribe_and_join(
               share_participant_socket(principal_id, share_session),
               "devices:user",
               %{}
             )

    assert {:error, %{reason: "user_session_required"}} =
             subscribe_and_join(
               share_participant_socket(principal_id, share_session),
               "devices:registration:#{Ecto.UUID.generate()}",
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
