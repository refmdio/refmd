defmodule RefMDWeb.DocumentKeyControllerTest do
  use RefMDWeb.ConnCase, async: true

  import Ecto.Query

  alias RefMD.Auth
  alias RefMD.Documents
  alias RefMD.Repo
  alias RefMD.Users.User
  alias RefMD.Workspaces
  alias RefMD.Workspaces.Workspace

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

  defp authed_conn(conn, user_id, device) do
    {:ok, session, token} = Auth.create_session(user_id, %{device_id: device.id})

    conn
    |> put_req_header("cookie", "_refmd_session=#{Base.url_encode64(token, padding: false)}")
    |> put_private(:test_session, session)
  end

  defp with_pop_headers(conn, user_id, device, signing_private_key, method, path, body) do
    put_test_pop_headers(conn, user_id, device, signing_private_key, method, path, body)
  end

  setup do
    owner_id = create_user("owner-document-key-controller@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Document Key Controller")
    owner_device = create_device(owner_id)

    {:ok, document} =
      Documents.create_document(%{
        "workspace_id" => workspace.id,
        "created_by" => owner_id,
        "encrypted_title" => :crypto.strong_rand_bytes(48),
        "encrypted_title_nonce" => :crypto.strong_rand_bytes(24),
        "encrypted_title_key_version" => 1,
        "doc_type" => "document"
      })

    %{document: document, owner_device: owner_device, owner_id: owner_id, workspace: workspace}
  end

  test "document key upload returns semantic KEK rotation error while workspace rotation is pending",
       %{
         conn: conn,
         document: document,
         owner_device: owner_device,
         owner_id: owner_id,
         workspace: workspace
       } do
    Repo.update_all(
      from(w in Workspace, where: w.id == ^workspace.id),
      set: [needs_kek_rotation: true]
    )

    path = "/api/encryption/documents/#{document.id}/keys"

    body = %{
      "key_version" => 1,
      "kek_version" => max(workspace.current_kek_version, 1),
      "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(48), padding: false),
      "nonce" => Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)
    }

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "POST",
        path,
        body
      )
      |> post(path, test_json_body(body))

    assert json_response(conn, 422) == %{"error" => "kek_rotation_required"}
  end
end
