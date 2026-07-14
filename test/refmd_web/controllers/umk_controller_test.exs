defmodule RefMDWeb.UmkControllerTest do
  use RefMDWeb.ConnCase, async: true

  alias Ecto.Changeset
  alias RefMD.Crypto.Hash
  alias RefMD.Devices
  alias RefMD.Devices.{DeviceEncryptedUMK, DeviceRegistration}
  alias RefMD.Repo
  alias RefMD.Users.User
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
end
