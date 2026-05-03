defmodule RefMDWeb.DeviceEventsChannelTest do
  use RefMDWeb.ConnCase

  import Phoenix.ChannelTest

  alias RefMD.Auth
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

    Repo.insert!(%Device{
      user_id: user_id,
      name: "Existing browser",
      device_type: "browser",
      ecdh_public_key: :crypto.strong_rand_bytes(32),
      signing_public_key: :crypto.strong_rand_bytes(32),
      identity_signature: :crypto.strong_rand_bytes(64),
      client_nonce: :crypto.strong_rand_bytes(16),
      last_seen_at: now,
      created_at: now
    })
  end

  defp create_registration(user_id) do
    now = DateTime.utc_now()

    Repo.insert!(%DeviceRegistration{
      user_id: user_id,
      name: "New browser",
      device_type: "browser",
      ecdh_public_key: :crypto.strong_rand_bytes(32),
      signing_public_key: :crypto.strong_rand_bytes(32),
      client_nonce: :crypto.strong_rand_bytes(16),
      ip_address: "127.0.0.1",
      created_at: now,
      expires_at: DateTime.add(now, 300, :second)
    })
  end
end
