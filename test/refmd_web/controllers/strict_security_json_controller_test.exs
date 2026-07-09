defmodule RefMDWeb.StrictSecurityJsonControllerTest do
  use RefMDWeb.ConnCase, async: true

  alias RefMD.{Auth, Repo, Workspaces}
  alias RefMD.Crypto.Hash
  alias RefMD.Encryption.KeyDirectory
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

    %{device: device, signing_private_key: keys.private}
  end

  defp authed_rrp_conn(conn, user_id, device, method, path, body) do
    {:ok, session, token} = Auth.create_session(user_id, %{device_id: device.device.id})

    conn
    |> put_req_header(
      "cookie",
      "__Host-refmd-session=#{Base.url_encode64(token, padding: false)}"
    )
    |> put_private(:test_session, session)
    |> put_test_rrp_headers(
      user_id,
      device.device,
      device.signing_private_key,
      method,
      path,
      body
    )
  end

  test "recovery key regeneration rejects duplicate keys in strict security JSON", %{conn: conn} do
    user_id = create_user("strict-recovery-json@example.com")
    device = create_device(user_id)
    path = "/api/auth/recovery-key"

    material_json =
      "identity"
      |> hybrid_signing_private_key_material(user_id)
      |> hybrid_signing_public_key_material()
      |> Jason.encode!()

    key_id = Hash.blake3_base64url(material_json)

    body =
      ~s({"new_recovery_encrypted_umk":"AA","new_recovery_nonce":"BB","new_recovery_authorization_public_material":#{material_json},"new_recovery_authorization_key_id":"#{key_id}","new_recovery_authorization_key_id":"#{key_id}"})

    conn =
      conn
      |> authed_rrp_conn(user_id, device, "PUT", path, body)
      |> put(path, body)

    assert json_response(conn, 422) == %{"error" => "invalid_strict_json"}
  end

  test "member removal rejects duplicate keys inside submitted key-directory envelope", %{
    conn: conn
  } do
    user_id = create_user("strict-member-json@example.com")
    device = create_device(user_id)
    {:ok, workspace} = Workspaces.create_default_workspace(user_id, "Strict Member JSON")
    role_id = owner_role_id(workspace.id)
    insert_test_workspace_key_directory!(workspace.id, user_id, role_id)

    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace.id)
    path = "/api/workspaces/#{workspace.id}/members/#{user_id}"
    checkpoint_json = checkpoint_envelope_json_with_duplicate_payload_key(checkpoint)

    body =
      ~s({"workspace_key_directory_events":[],"workspace_key_directory_checkpoint":#{checkpoint_json}})

    conn =
      conn
      |> authed_rrp_conn(user_id, device, "DELETE", path, body)
      |> delete(path, body)

    assert json_response(conn, 422) == %{"error" => "invalid_strict_json"}
  end

  defp owner_role_id(workspace_id) do
    workspace_id
    |> Workspaces.list_workspace_roles()
    |> Enum.find(&(&1.base_role == "owner"))
    |> Map.fetch!(:id)
  end

  defp checkpoint_envelope_json_with_duplicate_payload_key(checkpoint) do
    payload_json =
      checkpoint.payload
      |> Jason.encode!()
      |> String.replace_prefix("{", ~s({"scope_kind":"workspace",))

    ~s({"payload":#{payload_json},"signatures":#{Jason.encode!(checkpoint.signatures)}})
  end
end
