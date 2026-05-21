defmodule RefMDWeb.AuthControllerTest do
  use RefMDWeb.ConnCase, async: true

  alias RefMD.Auth
  alias RefMD.Crypto.Hash
  alias RefMD.Encryption
  alias RefMD.Repo
  alias RefMD.Users.User

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

    device
  end

  defp create_login_keys(user_id) do
    recovery = recovery_authorization_material(user_id)
    identity_public_key = get_or_create_identity_public_key!(user_id)

    {:ok, _master_key} =
      Encryption.create_user_encrypted_master_key(%{
        user_id: user_id,
        auth_type: "password",
        encrypted_umk: <<1::256>>,
        umk_nonce: <<2::192>>,
        salt: <<3::128>>,
        kdf_type: "argon2id",
        kdf_params: %{"memory" => 65_536, "iterations" => 3, "parallelism" => 1},
        auth_key_hash: "auth-key-hash",
        recovery_encrypted_umk: <<4::256>>,
        recovery_nonce: <<5::192>>,
        recovery_authorization_public_material: recovery.public,
        recovery_authorization_key_id: recovery.key_id
      })

    {:ok, _identity_key} =
      Encryption.create_user_encrypted_identity_key(%{
        user_id: user_id,
        encrypted_identity_hybrid_encryption_private_key_material: <<7::256>>,
        identity_hybrid_encryption_private_key_material_nonce: <<8::192>>,
        encryption_key_id: identity_public_key.encryption_key_id,
        encrypted_identity_hybrid_signing_private_key_material: <<11::256>>,
        identity_hybrid_signing_private_key_material_nonce: <<12::192>>,
        signing_key_id: identity_public_key.signing_key_id
      })
  end

  defp get_or_create_identity_public_key!(user_id) do
    case Encryption.get_user_identity_public_key(user_id) do
      nil ->
        identity_private = hybrid_signing_private_key_material("identity", user_id)
        identity_public = hybrid_signing_public_key_material(identity_private)
        {x25519_public, _} = :crypto.generate_key(:ecdh, :x25519)
        encryption = hybrid_encryption_public_key_material("identity", user_id, x25519_public)

        {:ok, identity_public_key} =
          Encryption.create_user_identity_public_key(%{
            user_id: user_id,
            hybrid_encryption_public_key_material: encryption.public,
            hybrid_signing_public_key_material: identity_public,
            pending_registration_challenge_hash: Hash.blake3_base64url("challenge")
          })

        identity_public_key

      identity_public_key ->
        identity_public_key
    end
  end

  defp authed_conn(conn, user_id, device) do
    {:ok, _session, token} = Auth.create_session(user_id, %{device_id: device.id})

    put_req_header(conn, "cookie", "_refmd_session=#{Base.url_encode64(token, padding: false)}")
  end

  test "me returns only key restore metadata and key restore returns the key blob", %{conn: conn} do
    user_id = create_user("auth-controller@example.com")
    device = create_device(user_id)
    create_login_keys(user_id)

    conn = authed_conn(conn, user_id, device)

    me_response =
      conn
      |> get("/api/auth/me")
      |> json_response(200)

    refute Map.has_key?(me_response, "keys")
    assert me_response["key_restore_available"] == true
    assert me_response["key_restore_endpoint_ref"] == "auth-key-restore-v1"

    restore_response =
      conn
      |> recycle()
      |> put_req_header("cookie", "_refmd_session=#{get_session_cookie(conn)}")
      |> get("/api/auth/key-restore")
      |> json_response(200)

    assert restore_response["encrypted_umk"]
    assert restore_response["umk_nonce"]
    assert restore_response["encrypted_identity_hybrid_encryption_private_key_material"]
    assert restore_response["identity_encryption_key_id"]
    assert restore_response["encrypted_identity_hybrid_signing_private_key_material"]
    assert restore_response["identity_signing_key_id"]
  end

  defp get_session_cookie(conn) do
    conn
    |> get_req_header("cookie")
    |> List.first()
    |> String.replace_prefix("_refmd_session=", "")
  end
end
