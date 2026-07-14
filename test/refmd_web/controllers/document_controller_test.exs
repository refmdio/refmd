defmodule RefMDWeb.DocumentControllerTest do
  use RefMDWeb.ConnCase, async: true

  import Ecto.Query

  alias RefMD.Auth
  alias RefMD.Documents.Document
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

  defp authed_conn(conn, user_id, device) do
    {:ok, session, token} = Auth.create_session(user_id, %{device_id: device.id})

    conn
    |> put_req_header(
      "cookie",
      "__Host-refmd-session=#{Base.url_encode64(token, padding: false)}"
    )
    |> put_private(:test_session, session)
  end

  defp post_document(conn, user_id, device, body) do
    path = "/api/documents"

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
  end

  defp patch_document(conn, user_id, device, document_id, body) do
    path = "/api/documents/#{document_id}"

    conn
    |> authed_conn(user_id, device.device)
    |> put_test_rrp_headers(
      user_id,
      device.device,
      device.signing_private_key,
      "PATCH",
      path,
      body
    )
    |> patch(path, test_json_body(body))
  end

  defp patch_reorder(conn, user_id, device, body) do
    path = "/api/documents/reorder"

    conn
    |> authed_conn(user_id, device.device)
    |> put_test_rrp_headers(
      user_id,
      device.device,
      device.signing_private_key,
      "PATCH",
      path,
      body
    )
    |> patch(path, test_json_body(body))
  end

  defp encrypted_create_body(workspace_id, doc_type) do
    %{
      "workspace_id" => workspace_id,
      "doc_type" => doc_type,
      "encrypted_title" => encoded_random(48),
      "encrypted_title_nonce" => encoded_random(24),
      "encrypted_title_key_version" => 1
    }
  end

  defp encoded_random(byte_size) do
    byte_size
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end

  setup do
    owner_id = create_user("owner-document-controller@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Document Controller")
    owner_device = create_device(owner_id)

    %{owner_id: owner_id, owner_device: owner_device, workspace: workspace}
  end

  test "POST /api/documents rejects plaintext document create without encrypted title metadata",
       %{conn: conn, owner_id: owner_id, owner_device: owner_device, workspace: workspace} do
    body = %{
      "workspace_id" => workspace.id,
      "doc_type" => "document"
    }

    conn = post_document(conn, owner_id, owner_device, body)

    assert %{"error" => "invalid_request_schema"} = json_response(conn, 422)

    refute Repo.exists?(
             from(d in Document,
               where:
                 d.workspace_id == ^workspace.id and d.title == "Plaintext Document" and
                   d.is_encrypted == false
             )
           )
  end

  test "POST /api/documents rejects plaintext folder create without encrypted title metadata",
       %{conn: conn, owner_id: owner_id, owner_device: owner_device, workspace: workspace} do
    body = %{
      "workspace_id" => workspace.id,
      "doc_type" => "folder"
    }

    conn = post_document(conn, owner_id, owner_device, body)

    assert %{"error" => "invalid_request_schema"} = json_response(conn, 422)

    refute Repo.exists?(
             from(d in Document,
               where:
                 d.workspace_id == ^workspace.id and d.title == "Plaintext Folder" and
                   d.is_encrypted == false
             )
           )
  end

  test "POST /api/documents creates encrypted documents",
       %{conn: conn, owner_id: owner_id, owner_device: owner_device, workspace: workspace} do
    body = encrypted_create_body(workspace.id, "document")

    conn = post_document(conn, owner_id, owner_device, body)

    response = json_response(conn, 201)
    document = Repo.get!(Document, response["id"])

    assert response["is_encrypted"] == true
    assert response["title"] == "Untitled"
    assert response["encrypted_title"] == body["encrypted_title"]
    assert response["encrypted_title_nonce"] == body["encrypted_title_nonce"]
    assert response["encrypted_title_key_version"] == 1
    assert document.is_encrypted == true
    assert document.title == "Untitled"
  end

  test "POST /api/documents rejects plaintext title even with encrypted metadata",
       %{conn: conn, owner_id: owner_id, owner_device: owner_device, workspace: workspace} do
    body =
      workspace.id
      |> encrypted_create_body("document")
      |> Map.put("title", "Plaintext Transport Title")

    conn = post_document(conn, owner_id, owner_device, body)

    assert %{"error" => "invalid_request_schema"} = json_response(conn, 422)

    refute Repo.exists?(
             from(d in Document,
               where:
                 d.workspace_id == ^workspace.id and d.title == "Plaintext Transport Title" and
                   d.is_encrypted == false
             )
           )
  end

  test "POST /api/documents rejects a future initial title DEK version",
       %{conn: conn, owner_id: owner_id, owner_device: owner_device, workspace: workspace} do
    body =
      Map.put(encrypted_create_body(workspace.id, "document"), "encrypted_title_key_version", 2)

    conn = post_document(conn, owner_id, owner_device, body)

    assert json_response(conn, 422) == %{
             "error" => "validation_error",
             "details" => %{
               "encrypted_title_key_version" => ["must be 1 for a new document"]
             }
           }
  end

  test "POST /api/documents rejects encrypted creation while the workspace KEK is overdue",
       %{conn: conn, owner_id: owner_id, owner_device: owner_device, workspace: workspace} do
    workspace
    |> Ecto.Changeset.change(needs_kek_rotation: true)
    |> Repo.update!()

    conn =
      post_document(conn, owner_id, owner_device, encrypted_create_body(workspace.id, "document"))

    assert json_response(conn, 422) == %{"error" => "kek_rotation_required"}
  end

  test "PATCH /api/documents/:id rejects plaintext title even with encrypted metadata",
       %{conn: conn, owner_id: owner_id, owner_device: owner_device, workspace: workspace} do
    create_conn =
      post_document(conn, owner_id, owner_device, encrypted_create_body(workspace.id, "document"))

    document_id = json_response(create_conn, 201)["id"]

    body =
      encrypted_create_body(workspace.id, "document")
      |> Map.take(["encrypted_title", "encrypted_title_nonce", "encrypted_title_key_version"])
      |> Map.put("title", "Plaintext Rename")

    conn = patch_document(build_conn(), owner_id, owner_device, document_id, body)

    assert %{"error" => "invalid_request_schema"} = json_response(conn, 422)

    document = Repo.get!(Document, document_id)
    assert document.title == "Untitled"
  end

  test "PATCH /api/documents/:id rejects partial encrypted title metadata",
       %{conn: conn, owner_id: owner_id, owner_device: owner_device, workspace: workspace} do
    create_conn =
      post_document(conn, owner_id, owner_device, encrypted_create_body(workspace.id, "document"))

    document_id = json_response(create_conn, 201)["id"]

    conn =
      patch_document(build_conn(), owner_id, owner_device, document_id, %{
        "encrypted_title_nonce" => encoded_random(24)
      })

    assert json_response(conn, 422) == %{
             "error" => "validation_error",
             "details" => %{
               "encrypted_title" => ["is required"],
               "encrypted_title_key_version" => ["is required"]
             }
           }
  end

  test "PATCH /api/documents/:id accepts complete encrypted title metadata",
       %{conn: conn, owner_id: owner_id, owner_device: owner_device, workspace: workspace} do
    create_conn =
      post_document(conn, owner_id, owner_device, encrypted_create_body(workspace.id, "document"))

    document_id = json_response(create_conn, 201)["id"]

    body =
      encrypted_create_body(workspace.id, "document")
      |> Map.take(["encrypted_title", "encrypted_title_nonce", "encrypted_title_key_version"])

    conn = patch_document(build_conn(), owner_id, owner_device, document_id, body)

    response = json_response(conn, 200)
    assert response["encrypted_title"] == body["encrypted_title"]
    assert response["encrypted_title_nonce"] == body["encrypted_title_nonce"]
    assert response["encrypted_title_key_version"] == body["encrypted_title_key_version"]
  end

  test "PATCH /api/documents/:id rejects encrypted title under an obsolete DEK",
       %{conn: conn, owner_id: owner_id, owner_device: owner_device, workspace: workspace} do
    create_conn =
      post_document(conn, owner_id, owner_device, encrypted_create_body(workspace.id, "document"))

    document_id = json_response(create_conn, 201)["id"]

    Repo.get!(Document, document_id)
    |> Ecto.Changeset.change(min_dek_version: 2)
    |> Repo.update!()

    body =
      encrypted_create_body(workspace.id, "document")
      |> Map.take(["encrypted_title", "encrypted_title_nonce", "encrypted_title_key_version"])

    conn = patch_document(build_conn(), owner_id, owner_device, document_id, body)

    assert json_response(conn, 422) == %{"error" => "dek_rotation_required"}
  end

  test "PATCH /api/documents/:id rejects malformed encrypted title metadata",
       %{conn: conn, owner_id: owner_id, owner_device: owner_device, workspace: workspace} do
    create_conn =
      post_document(conn, owner_id, owner_device, encrypted_create_body(workspace.id, "document"))

    document_id = json_response(create_conn, 201)["id"]

    body =
      workspace.id
      |> encrypted_create_body("document")
      |> Map.take(["encrypted_title", "encrypted_title_nonce", "encrypted_title_key_version"])
      |> Map.put("encrypted_title_nonce", encoded_random(12))

    conn = patch_document(build_conn(), owner_id, owner_device, document_id, body)

    assert %{"error" => "invalid_request_schema"} = json_response(conn, 422)
  end

  test "PATCH /api/documents/:id rejects nonpositive encrypted title key version",
       %{conn: conn, owner_id: owner_id, owner_device: owner_device, workspace: workspace} do
    create_conn =
      post_document(conn, owner_id, owner_device, encrypted_create_body(workspace.id, "document"))

    document_id = json_response(create_conn, 201)["id"]

    body =
      workspace.id
      |> encrypted_create_body("document")
      |> Map.take(["encrypted_title", "encrypted_title_nonce", "encrypted_title_key_version"])
      |> Map.put("encrypted_title_key_version", 0)

    conn = patch_document(build_conn(), owner_id, owner_device, document_id, body)

    assert %{"error" => "invalid_request_schema"} = json_response(conn, 422)
  end

  test "PATCH /api/documents/reorder moves a child back to root when parent_id is omitted",
       %{conn: conn, owner_id: owner_id, owner_device: owner_device, workspace: workspace} do
    folder_conn =
      post_document(conn, owner_id, owner_device, encrypted_create_body(workspace.id, "folder"))

    folder_id = json_response(folder_conn, 201)["id"]

    child_body =
      workspace.id
      |> encrypted_create_body("document")
      |> Map.put("parent_id", folder_id)

    child_conn = post_document(build_conn(), owner_id, owner_device, child_body)
    child_id = json_response(child_conn, 201)["id"]

    reorder_body = %{
      "workspace_id" => workspace.id,
      "document_id" => child_id,
      "position" => 0
    }

    conn = patch_reorder(build_conn(), owner_id, owner_device, reorder_body)

    response = json_response(conn, 200)
    assert response["parent_id"] == nil
    assert Repo.get!(Document, child_id).parent_id == nil
  end
end
