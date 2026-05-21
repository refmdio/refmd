defmodule RefMDWeb.UmkControllerTest do
  use RefMDWeb.ConnCase, async: true

  alias Ecto.Changeset
  alias RefMD.Crypto.Hash
  alias RefMD.Devices
  alias RefMD.Devices.{DeviceEncryptedUMK, DeviceRegistration}
  alias RefMD.Repo
  alias RefMD.Users.User
  alias RefMDWeb.UmkController

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
      approval_key_directory: %{
        "user_key_directory_events" => [],
        "user_key_directory_checkpoint" => %{},
        "workspace_key_directory_appends" => []
      }
    })
    |> Repo.update!()
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
      |> Plug.Conn.assign(:pop_device_id, sender.id)
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
end
