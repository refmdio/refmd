defmodule RefMDWeb.SettingsControllerTest do
  use RefMDWeb.ConnCase, async: true

  alias RefMD.Auth
  alias RefMD.Repo
  alias RefMD.Users
  alias RefMD.Users.User

  defp create_user(email) do
    user_id = Ecto.UUID.generate()

    Repo.insert!(%User{
      id: user_id,
      email: email,
      name: email
    })

    {:ok, _settings} = Users.create_user_settings(user_id)
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
        name: "Owner Browser",
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

  defp authed_conn(conn, user_id, device) do
    {:ok, session, token} = Auth.create_session(user_id, %{device_id: device.id})

    conn
    |> put_req_header("cookie", "_refmd_session=#{Base.url_encode64(token, padding: false)}")
    |> put_private(:test_session, session)
  end

  setup do
    user_id = create_user("settings-controller@example.com")
    device = create_device(user_id)
    %{user_id: user_id, device: device}
  end

  test "updates user plugin network proxy setting", %{
    conn: conn,
    user_id: user_id,
    device: device
  } do
    path = "/api/settings"

    body = %{
      "plugin_network_proxy" => %{
        "id" => "user-proxy",
        "label" => "User Proxy",
        "base_url" => "https://proxy.example/user/",
        "scope" => "user",
        "enabled" => true,
        "operator_label" => "Personal Proxy Operator",
        "allowed_workspace_ids" => [],
        "allowed_user_ids" => [user_id],
        "verification_material" => %{"response_signing_key" => "user-proxy-key"},
        "revoked" => false,
        "policy" => %{"allowed_route_classes" => ["plugin-network"]}
      }
    }

    conn =
      conn
      |> authed_conn(user_id, device.device)
      |> put_test_pop_headers(
        user_id,
        device.device,
        device.signing_private_key,
        "PATCH",
        path,
        body
      )
      |> patch(path, test_json_body(body))

    proxy = json_response(conn, 200)["plugin_network_proxy"]
    assert proxy["id"] == "user-proxy"
    assert proxy["label"] == "User Proxy"
    assert proxy["base_url"] == "https://proxy.example/user"
    assert proxy["scope"] == "user"
    assert proxy["enabled"] == true
    assert proxy["operator_label"] == "Personal Proxy Operator"
    assert proxy["allowed_workspace_ids"] == []
    assert proxy["allowed_user_ids"] == [user_id]
    assert proxy["verification_material"] == %{"response_signing_key" => "user-proxy-key"}
    assert proxy["revoked"] == false
    assert proxy["policy"] == %{"allowed_route_classes" => ["plugin-network"]}
  end

  test "rejects invalid user plugin network proxy url", %{
    conn: conn,
    user_id: user_id,
    device: device
  } do
    path = "/api/settings"

    body = %{
      "plugin_network_proxy" => %{
        "id" => "user-proxy",
        "label" => "User Proxy",
        "base_url" => "http://proxy.example/user",
        "scope" => "user",
        "enabled" => true
      }
    }

    conn =
      conn
      |> authed_conn(user_id, device.device)
      |> put_test_pop_headers(
        user_id,
        device.device,
        device.signing_private_key,
        "PATCH",
        path,
        body
      )
      |> patch(path, test_json_body(body))

    assert %{"error" => "validation_error"} = json_response(conn, 422)
  end
end
