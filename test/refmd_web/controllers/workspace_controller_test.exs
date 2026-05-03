defmodule RefMDWeb.WorkspaceControllerTest do
  use RefMDWeb.ConnCase, async: true

  alias RefMD.Auth
  alias RefMD.Repo
  alias RefMD.Users.User
  alias RefMD.Workspaces

  defp create_user(email) do
    user_id = Ecto.UUID.generate()

    Repo.insert!(%User{
      id: user_id,
      email: email,
      name: email
    })

    user_id
  end

  defp create_device(user_id) do
    {signing_public_key, signing_private_key} = :crypto.generate_key(:eddsa, :ed25519)
    {ecdh_public_key, _ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)

    {:ok, device} =
      RefMD.Devices.create_device(%{
        user_id: user_id,
        name: "Owner Browser",
        device_type: "browser",
        ecdh_public_key: ecdh_public_key,
        signing_public_key: signing_public_key,
        identity_signature: :crypto.strong_rand_bytes(64),
        client_nonce: :crypto.strong_rand_bytes(16)
      })

    %{device: device, signing_private_key: signing_private_key}
  end

  defp authed_conn(conn, user_id, device) do
    {:ok, _session, token} = Auth.create_session(user_id, %{device_id: device.id})

    put_req_header(conn, "cookie", "_refmd_session=#{Base.url_encode64(token, padding: false)}")
  end

  defp with_pop_headers(conn, user_id, device, signing_private_key) do
    {:ok, challenge} = Auth.create_pop_challenge(user_id, device.id)

    message =
      RefMD.Crypto.build_signature_message("pop_challenge", %{
        "challenge" => Base.url_encode64(challenge, padding: false),
        "device_id" => device.id
      })

    signature = :crypto.sign(:eddsa, :none, message, [signing_private_key, :ed25519])

    conn
    |> put_req_header("x-pop-device-id", device.id)
    |> put_req_header("x-pop-challenge", Base.url_encode64(challenge, padding: false))
    |> put_req_header("x-pop-signature", Base.url_encode64(signature, padding: false))
  end

  setup do
    owner_id = create_user("owner-workspace-controller@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Workspace Controller")
    owner_device = create_device(owner_id)

    %{owner_id: owner_id, workspace: workspace, owner_device: owner_device}
  end

  test "rejects invalid guest_member_limit type", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> patch("/api/workspaces/#{workspace.id}", %{"guest_member_limit" => "10"})

    assert json_response(conn, 400) == %{
             "error" => "invalid_value",
             "field" => "guest_member_limit"
           }
  end
end
