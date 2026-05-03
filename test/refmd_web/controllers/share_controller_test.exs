defmodule RefMDWeb.ShareControllerTest do
  use RefMDWeb.ConnCase, async: true
  import Ecto.Query

  alias RefMD.Documents
  alias RefMD.Repo
  alias RefMD.Sharing
  alias RefMD.Sharing.SharePasswordChallenge
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

  defp create_document(workspace_id, created_by, parent_id \\ nil) do
    {:ok, document} =
      Documents.create_document(%{
        "id" => Ecto.UUID.generate(),
        "workspace_id" => workspace_id,
        "doc_type" => "document",
        "parent_id" => parent_id,
        "title" => "Untitled",
        "encrypted_title" => <<1, 2, 3>>,
        "encrypted_title_nonce" => :crypto.strong_rand_bytes(24),
        "encrypted_title_key_version" => 1,
        "created_by" => created_by
      })

    document
  end

  defp create_folder(workspace_id, created_by, parent_id \\ nil) do
    {:ok, folder} =
      Documents.create_document(%{
        "id" => Ecto.UUID.generate(),
        "workspace_id" => workspace_id,
        "doc_type" => "folder",
        "parent_id" => parent_id,
        "title" => "Folder",
        "created_by" => created_by
      })

    folder
  end

  defp create_share(document, owner_id) do
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    {:ok, created} =
      Sharing.create_share(document, owner_id, %{
        "id" => Ecto.UUID.generate(),
        "scope" => "document",
        "share_slug" => share_slug,
        "token_prefix" => String.slice(share_slug, 0, 4),
        "permission" => "view",
        "password_protected" => false,
        "encrypted_dek" => :crypto.strong_rand_bytes(32),
        "nonce" => nil
      })

    created
  end

  defp create_password_protected_share(document, owner_id) do
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
    auth_key = :crypto.strong_rand_bytes(32)

    {:ok, created} =
      Sharing.create_share(document, owner_id, %{
        "id" => Ecto.UUID.generate(),
        "scope" => "document",
        "share_slug" => share_slug,
        "token_prefix" => String.slice(share_slug, 0, 4),
        "permission" => "view",
        "password_protected" => true,
        "encrypted_dek" => :crypto.strong_rand_bytes(48),
        "nonce" => :crypto.strong_rand_bytes(24),
        "salt" => :crypto.strong_rand_bytes(16),
        "kdf_params" => %{
          "algorithm" => "argon2id",
          "memory" => 65_536,
          "iterations" => 3,
          "parallelism" => 4,
          "hash_length" => 32
        },
        "auth_key" => auth_key
      })

    {created, auth_key}
  end

  defp create_folder_share(folder, owner_id, shared_nodes) do
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    {:ok, created} =
      Sharing.create_share(folder, owner_id, %{
        "id" => Ecto.UUID.generate(),
        "scope" => "folder",
        "share_slug" => share_slug,
        "token_prefix" => String.slice(share_slug, 0, 4),
        "permission" => "view",
        "password_protected" => false,
        "encrypted_dek" => :crypto.strong_rand_bytes(32),
        "nonce" => nil,
        "share_keys" =>
          Enum.map(shared_nodes, fn document ->
            %{
              "share_id" => Ecto.UUID.generate(),
              "document_id" => document.id,
              "encrypted_dek" => :crypto.strong_rand_bytes(32),
              "nonce" => nil
            }
          end)
      })

    created
  end

  defp valid_signing_public_key do
    key = :crypto.strong_rand_bytes(32)
    if RefMD.Crypto.valid_ed25519_public_key?(key), do: key, else: valid_signing_public_key()
  end

  defp valid_encryption_public_key do
    key = :crypto.strong_rand_bytes(32)
    if RefMD.Crypto.valid_x25519_public_key?(key), do: key, else: valid_encryption_public_key()
  end

  setup do
    owner_id = create_user("owner-share-controller@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Share Controller Workspace")
    document = create_document(workspace.id, owner_id)

    %{owner_id: owner_id, document: document}
  end

  test "GET /api/shares/:share_slug returns 404 for malformed slug", %{conn: conn} do
    conn = get(conn, "/api/shares/not-a-valid-token")

    assert json_response(conn, 404) == %{"error" => "not_found"}
  end

  test "POST /api/shares/:share_slug/bootstrap sets the share session cookie on /api", %{
    conn: conn,
    document: document,
    owner_id: owner_id
  } do
    created = create_share(document, owner_id)

    conn =
      post(conn, "/api/shares/#{created.share_slug}/bootstrap", %{
        "display_name" => "Guest User",
        "device_signing_pub_key" => Base.url_encode64(valid_signing_public_key(), padding: false),
        "device_encryption_pub_key" =>
          Base.url_encode64(valid_encryption_public_key(), padding: false)
      })

    assert %{"root" => %{"kind" => "document"}, "participant" => %{"grant" => "view"}} =
             json_response(conn, 200)

    assert conn.resp_cookies["_refmd_share_session"].path == "/api"
  end

  test "POST /api/shares/:share_slug/bootstrap rejects password-protected shares", %{
    conn: conn,
    document: document,
    owner_id: owner_id
  } do
    {created, _auth_key} = create_password_protected_share(document, owner_id)

    conn =
      post(conn, "/api/shares/#{created.share_slug}/bootstrap", %{
        "display_name" => "Guest User",
        "device_signing_pub_key" => Base.url_encode64(valid_signing_public_key(), padding: false),
        "device_encryption_pub_key" =>
          Base.url_encode64(valid_encryption_public_key(), padding: false)
      })

    assert json_response(conn, 409) == %{"error" => "password_required"}
  end

  test "password challenge endpoints bootstrap a protected share session", %{
    conn: conn,
    document: document,
    owner_id: owner_id
  } do
    {created, auth_key} = create_password_protected_share(document, owner_id)

    challenge_conn = get(conn, "/api/shares/#{created.share_slug}/challenge")

    assert %{
             "challenge" => challenge,
             "salt" => salt,
             "kdf_params" => %{"algorithm" => "argon2id"}
           } = json_response(challenge_conn, 200)

    assert is_binary(challenge)
    assert is_binary(salt)
    assert get_resp_header(challenge_conn, "cache-control") == ["no-store"]

    challenge_bytes = Base.url_decode64!(challenge, padding: false)
    response = :crypto.mac(:hmac, :sha256, auth_key, challenge_bytes)

    respond_conn =
      build_conn()
      |> post("/api/shares/#{created.share_slug}/challenge", %{
        "response" => Base.url_encode64(response, padding: false),
        "display_name" => "Guest User",
        "device_signing_pub_key" => Base.url_encode64(valid_signing_public_key(), padding: false),
        "device_encryption_pub_key" =>
          Base.url_encode64(valid_encryption_public_key(), padding: false)
      })

    assert %{"root" => %{"kind" => "document"}, "participant" => %{"grant" => "view"}} =
             json_response(respond_conn, 200)

    assert respond_conn.resp_cookies["_refmd_share_session"].path == "/api"
  end

  test "password challenge failure returns unified not_found", %{
    conn: conn,
    document: document,
    owner_id: owner_id
  } do
    {created, _auth_key} = create_password_protected_share(document, owner_id)

    challenge_conn = get(conn, "/api/shares/#{created.share_slug}/challenge")
    assert %{"challenge" => _challenge} = json_response(challenge_conn, 200)

    respond_conn =
      build_conn()
      |> post("/api/shares/#{created.share_slug}/challenge", %{
        "response" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
        "display_name" => "Guest User",
        "device_signing_pub_key" => Base.url_encode64(valid_signing_public_key(), padding: false),
        "device_encryption_pub_key" =>
          Base.url_encode64(valid_encryption_public_key(), padding: false)
      })

    assert json_response(respond_conn, 404) == %{"error" => "not_found"}
  end

  test "GET /api/shares/:share_slug/challenge uses per-slug dummy challenge rows for unknown slugs",
       %{
         conn: conn
       } do
    assert %{"challenge" => first_challenge} =
             conn
             |> get("/api/shares/not-a-real-share-slug/challenge")
             |> json_response(200)

    assert %{"challenge" => second_challenge} =
             build_conn()
             |> get("/api/shares/also-not-a-real-share-slug/challenge")
             |> json_response(200)

    stored =
      Repo.all(from(c in SharePasswordChallenge, where: is_nil(c.share_id)))

    assert first_challenge != second_challenge
    assert length(stored) == 2
  end

  test "GET /api/shares/d/:document_token returns bootstrap_required without session", %{
    conn: conn,
    document: document,
    owner_id: owner_id
  } do
    created = create_share(document, owner_id)
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    conn = get(conn, "/api/shares/d/#{landing.root.document_token}")

    assert json_response(conn, 200) == %{
             "bootstrap_required" => true,
             "share_slug" => created.share_slug
           }
  end

  test "GET /api/shares/d/:document_token returns canonical bootstrap with a share session", %{
    conn: conn,
    document: document,
    owner_id: owner_id
  } do
    created = create_share(document, owner_id)
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    {:ok, bootstrapped} =
      Sharing.bootstrap_participant(created.share_slug, %{
        "display_name" => "Guest User",
        "device_signing_pub_key" => valid_signing_public_key(),
        "device_encryption_pub_key" => valid_encryption_public_key()
      })

    conn =
      conn
      |> put_req_header(
        "cookie",
        "_refmd_share_session=#{Base.url_encode64(bootstrapped.session_token, padding: false)}"
      )
      |> get("/api/shares/d/#{landing.root.document_token}")

    assert %{
             "document_id" => document_id,
             "share_id" => share_id,
             "share_slug" => share_slug,
             "permission" => "view",
             "encrypted_dek" => encrypted_dek,
             "verification_directory" => %{}
           } = json_response(conn, 200)

    assert document_id == document.id
    assert share_id == created.share.id
    assert share_slug == created.share_slug
    assert is_binary(encrypted_dek)
  end

  test "GET /api/shares/f/:folder_token returns shared descendants", %{
    conn: conn,
    document: document,
    owner_id: owner_id
  } do
    folder = create_folder(document.workspace_id, owner_id)
    shared_document = create_document(document.workspace_id, owner_id, folder.id)
    nested_folder = create_folder(document.workspace_id, owner_id, folder.id)
    nested_document = create_document(document.workspace_id, owner_id, nested_folder.id)

    created =
      create_folder_share(folder, owner_id, [shared_document, nested_folder, nested_document])

    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    {:ok, bootstrapped} =
      Sharing.bootstrap_participant(created.share_slug, %{
        "display_name" => "Guest User",
        "device_signing_pub_key" => valid_signing_public_key(),
        "device_encryption_pub_key" => valid_encryption_public_key()
      })

    share_session_token = Base.url_encode64(bootstrapped.session_token, padding: false)

    conn =
      conn
      |> put_req_header(
        "cookie",
        "_refmd_share_session=#{share_session_token}"
      )
      |> get("/api/shares/f/#{landing.root.folder_token}")

    assert %{
             "share_id" => share_id,
             "share_slug" => share_slug,
             "password_protected" => false,
             "folder" => root_folder,
             "entries" => entries
           } =
             json_response(conn, 200)

    assert share_id == created.share.id
    assert share_slug == created.share_slug
    assert root_folder["share_id"] == created.share.id
    assert root_folder["parent_id"] == nil
    assert is_binary(root_folder["encrypted_dek"])
    assert is_nil(root_folder["nonce"])

    shared_entry = Enum.find(entries, &(&1["id"] == shared_document.id))
    assert is_binary(shared_entry["share_id"])
    refute shared_entry["share_id"] == created.share.id
    assert is_binary(shared_entry["document_token"])

    assert shared_entry["encrypted_title"] ==
             Base.url_encode64(shared_document.encrypted_title, padding: false)

    assert shared_entry["encrypted_title_nonce"] ==
             Base.url_encode64(shared_document.encrypted_title_nonce, padding: false)

    assert is_binary(shared_entry["encrypted_dek"])
    assert is_nil(shared_entry["nonce"])

    nested_folder_entry = Enum.find(entries, &(&1["id"] == nested_folder.id))
    assert is_binary(nested_folder_entry["share_id"])
    refute nested_folder_entry["share_id"] == created.share.id
    assert is_binary(nested_folder_entry["folder_token"])
    assert is_binary(nested_folder_entry["encrypted_dek"])
    assert is_nil(nested_folder_entry["nonce"])

    refute Enum.any?(entries, &(&1["id"] == nested_document.id))

    nested_conn =
      build_conn()
      |> put_req_header("cookie", "_refmd_share_session=#{share_session_token}")
      |> get("/api/shares/f/#{nested_folder_entry["folder_token"]}")

    assert %{"folder" => nested_folder_root, "entries" => nested_entries} =
             json_response(nested_conn, 200)

    assert nested_folder_root["id"] == nested_folder.id
    assert nested_folder_root["parent_id"] == nil

    nested_entry = Enum.find(nested_entries, &(&1["id"] == nested_document.id))
    assert nested_entry["parent_id"] == nested_folder.id
    assert is_binary(nested_entry["share_id"])
    refute nested_entry["share_id"] == created.share.id
    assert is_binary(nested_entry["document_token"])
    assert is_binary(nested_entry["encrypted_dek"])
    assert is_nil(nested_entry["nonce"])
  end
end
