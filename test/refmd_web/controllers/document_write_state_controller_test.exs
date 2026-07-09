defmodule RefMDWeb.DocumentWriteStateControllerTest do
  use RefMDWeb.ConnCase, async: true

  alias RefMD.Auth
  alias RefMD.Documents
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

  defp create_document(workspace_id, created_by) do
    {:ok, document} =
      Documents.create_document(%{
        "id" => Ecto.UUID.generate(),
        "workspace_id" => workspace_id,
        "doc_type" => "document",
        "title" => "Untitled",
        "created_by" => created_by,
        "encrypted_title" => <<1, 2, 3>>,
        "encrypted_title_nonce" => :crypto.strong_rand_bytes(24),
        "encrypted_title_key_version" => 1
      })

    document
  end

  defp authed_conn(conn, user_id, device) do
    {:ok, session, token} = Auth.create_session(user_id, %{device_id: device.id})

    conn
    |> put_req_header(
      "cookie",
      "__Host-refmd-session=#{Base.url_encode64(token, padding: false)}"
    )
    |> put_private(:test_session, session)
  end

  defp write_state_body(workspace_id, user_id, signer, document_id, previous, target, reason) do
    document_write_state_key_directory_append(
      workspace_id,
      user_id,
      signer.device_id,
      signer.signing_private,
      [
        %{
          document_id: document_id,
          previous_write_state: previous,
          write_state: target
        }
      ],
      reason
    )
  end

  setup %{conn: conn} do
    user_id = create_user("document-write-state-controller@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(user_id, "Document Write State")
    {_member, role} = Workspaces.get_member_with_role(workspace.id, user_id)
    insert_test_workspace_key_directory!(workspace.id, user_id, role.id)

    %{
      conn: conn,
      user_id: user_id,
      workspace: workspace,
      document: create_document(workspace.id, user_id),
      device: create_device(user_id),
      signer: Process.get({:test_workspace_signer_material, workspace.id})
    }
  end

  test "POST read-only enable persists write state and update rejects writes", %{
    conn: conn,
    user_id: user_id,
    workspace: workspace,
    document: document,
    device: device,
    signer: signer
  } do
    path = "/api/documents/#{document.id}/read-only/enable"

    body =
      write_state_body(
        workspace.id,
        user_id,
        signer,
        document.id,
        "writable",
        "read_only",
        "read_only_enabled"
      )

    conn =
      conn
      |> authed_conn(user_id, device.device)
      |> put_test_rrp_headers(
        user_id,
        device.device,
        device.signing_private_key,
        "POST",
        path,
        body
      )
      |> post(path, test_json_body(body))

    response = json_response(conn, 200)
    assert response["write_state"] == "read_only"
    assert Documents.get_document(document.id).write_state == "read_only"

    patch_path = "/api/documents/#{document.id}"

    patch_body = %{
      "encrypted_title" => Base.url_encode64(:crypto.strong_rand_bytes(48), padding: false),
      "encrypted_title_nonce" => Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false),
      "encrypted_title_key_version" => 1
    }

    conn =
      build_conn()
      |> put_req_header("x-refmd-e2e-rate-limit-bypass", "1")
      |> authed_conn(user_id, device.device)
      |> put_test_rrp_headers(
        user_id,
        device.device,
        device.signing_private_key,
        "PATCH",
        patch_path,
        patch_body
      )
      |> patch(patch_path, test_json_body(patch_body))

    assert %{"error" => "document_read_only"} = json_response(conn, 422)
  end

  test "POST write-disable persists policy write state", %{
    conn: conn,
    user_id: user_id,
    workspace: workspace,
    document: document,
    device: device,
    signer: signer
  } do
    path = "/api/documents/#{document.id}/write-disable"

    body =
      write_state_body(
        workspace.id,
        user_id,
        signer,
        document.id,
        "writable",
        "write_disabled",
        "policy"
      )

    conn =
      conn
      |> authed_conn(user_id, device.device)
      |> put_test_rrp_headers(
        user_id,
        device.device,
        device.signing_private_key,
        "POST",
        path,
        body
      )
      |> post(path, test_json_body(body))

    response = json_response(conn, 200)
    assert response["write_state"] == "write_disabled"
    assert Documents.get_document(document.id).write_state == "write_disabled"
  end
end
