defmodule RefMDWeb.ShareControllerTest do
  use RefMDWeb.ConnCase, async: true
  import Ecto.Query

  alias RefMD.Crypto.Blake3
  alias RefMD.Documents
  alias RefMD.Repo
  alias RefMD.Sharing
  alias RefMD.Sharing.SharePasswordChallenge
  alias RefMD.Users.User
  alias RefMD.Workspaces

  defp workspace_pin_bootstrap_hash,
    do: Process.get(:workspace_pin_bootstrap_hash, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

  defp password_challenge_hash(share_slug) do
    share_slug
    |> Base.url_decode64!(padding: false)
    |> Blake3.hash_base64url()
  end

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

    attrs =
      %{
        "id" => Ecto.UUID.generate(),
        "scope" => "document",
        "share_slug" => share_slug,
        "token_prefix" => String.slice(share_slug, 0, 4),
        "permission" => "view",
        "password_protected" => false,
        "authorization_public_key_material" =>
          share_capability_public_key_material_for_slug(open_admission_key(), share_slug),
        "share_capability_secret_commitment" => open_share_capability_secret_commitment(),
        "authenticated_workspace_pin_bootstrap_hash" => workspace_pin_bootstrap_hash(),
        "encrypted_dek" => :crypto.strong_rand_bytes(48),
        "nonce" => :crypto.strong_rand_bytes(24)
      }
      |> with_test_share_security_artifacts(document, owner_id)

    {:ok, created} = Sharing.create_share(document, owner_id, attrs)

    created
  end

  defp create_password_protected_share(document, owner_id) do
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
    auth_key = :crypto.strong_rand_bytes(32)

    attrs =
      %{
        "id" => Ecto.UUID.generate(),
        "scope" => "document",
        "share_slug" => share_slug,
        "token_prefix" => String.slice(share_slug, 0, 4),
        "permission" => "view",
        "password_protected" => true,
        "authorization_public_key_material" =>
          share_capability_public_key_material_for_slug(auth_key, share_slug),
        "auth_key" => auth_key,
        "share_capability_secret_commitment" => open_share_capability_secret_commitment(),
        "authenticated_workspace_pin_bootstrap_hash" => workspace_pin_bootstrap_hash(),
        "encrypted_dek" => :crypto.strong_rand_bytes(48),
        "nonce" => :crypto.strong_rand_bytes(24),
        "salt" => :crypto.strong_rand_bytes(16),
        "kdf_params" => %{
          "algorithm" => "argon2id",
          "memory" => 65_536,
          "iterations" => 3,
          "parallelism" => 4,
          "hash_length" => 32
        }
      }
      |> with_test_share_security_artifacts(document, owner_id)

    {:ok, created} = Sharing.create_share(document, owner_id, attrs)

    {created, auth_key}
  end

  defp create_folder_share(folder, owner_id, shared_nodes) do
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    attrs =
      %{
        "id" => Ecto.UUID.generate(),
        "scope" => "folder",
        "share_slug" => share_slug,
        "token_prefix" => String.slice(share_slug, 0, 4),
        "permission" => "view",
        "password_protected" => false,
        "authorization_public_key_material" =>
          share_capability_public_key_material_for_slug(open_admission_key(), share_slug),
        "share_capability_secret_commitment" => open_share_capability_secret_commitment(),
        "authenticated_workspace_pin_bootstrap_hash" => workspace_pin_bootstrap_hash(),
        "encrypted_dek" => :crypto.strong_rand_bytes(48),
        "nonce" => :crypto.strong_rand_bytes(24),
        "share_keys" =>
          Enum.map(shared_nodes, fn document ->
            %{
              "share_id" => Ecto.UUID.generate(),
              "document_id" => document.id,
              "encrypted_dek" => :crypto.strong_rand_bytes(48),
              "nonce" => :crypto.strong_rand_bytes(24)
            }
          end)
      }
      |> with_test_share_security_artifacts(folder, owner_id)

    {:ok, created} = Sharing.create_share(folder, owner_id, attrs)

    created
  end

  setup do
    owner_id = create_user("owner-share-controller@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Share Controller Workspace")
    document = create_document(workspace.id, owner_id)
    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)
    Process.put(:workspace_pin_bootstrap_hash, test_workspace_pin_bootstrap_hash!(workspace.id))

    %{owner_id: owner_id, document: document}
  end

  test "GET /api/shares/:share_slug returns 404 for malformed slug", %{conn: conn} do
    conn = get(conn, "/api/shares/not-a-valid-token")

    assert json_response(conn, 404) == %{"error" => "not_found"}
  end

  test "GET /api/shares/:share_slug returns only landing metadata", %{
    conn: conn,
    document: document,
    owner_id: owner_id
  } do
    created = create_share(document, owner_id)

    conn = get(conn, "/api/shares/#{created.share_slug}")

    assert %{
             "share" => share,
             "root" => %{"kind" => "document"}
           } = json_response(conn, 200)

    assert Map.keys(share) |> Enum.sort() == [
             "capability_context_hash",
             "created_event_hash",
             "document_id",
             "id",
             "latest_bootstrap_event_hash",
             "password_capability_secret_commitment",
             "password_protected",
             "permission",
             "scope",
             "share_capability_secret_commitment"
           ]
  end

  test "POST /api/shares/:share_slug/bootstrap sets the share session cookie on /api", %{
    conn: conn,
    document: document,
    owner_id: owner_id
  } do
    created = create_share(document, owner_id)

    conn =
      post(
        conn,
        "/api/shares/#{created.share_slug}/bootstrap",
        share_participant_request_attrs("Guest User", created, open_admission_key())
      )

    assert %{"root" => %{"kind" => "document"}, "participant" => %{"grant" => "view"}} =
             json_response(conn, 200)

    assert conn.resp_cookies["_refmd_share_session"].path == "/api"
  end

  test "POST /api/shares/:share_slug/bootstrap rejects password-protected shares", %{
    conn: conn,
    document: document,
    owner_id: owner_id
  } do
    {created, auth_key} = create_password_protected_share(document, owner_id)

    conn =
      post(
        conn,
        "/api/shares/#{created.share_slug}/bootstrap",
        share_participant_request_attrs("Guest User", created, auth_key)
      )

    assert json_response(conn, 409) == %{"error" => "password_required"}
  end

  test "POST /api/shares/:share_slug/bootstrap rejects extra authorization transcript fields", %{
    conn: conn,
    document: document,
    owner_id: owner_id
  } do
    created = create_share(document, owner_id)

    attrs =
      share_participant_request_attrs("Guest User", created, open_admission_key())
      |> put_in(["share_participant_device_authorization", "transcript", "extra"], "unexpected")

    conn = post(conn, "/api/shares/#{created.share_slug}/bootstrap", attrs)

    assert %{"error" => "invalid_request_schema"} = json_response(conn, 422)
  end

  test "GET /api/shares/:share_slug withholds password-protected root before challenge", %{
    conn: conn,
    document: document,
    owner_id: owner_id
  } do
    {created, _auth_key} = create_password_protected_share(document, owner_id)

    conn = get(conn, "/api/shares/#{created.share_slug}")

    assert %{
             "share" => %{"password_protected" => true},
             "password_challenge_required" => true
           } =
             json_response(conn, 200)
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
      |> post(
        "/api/shares/#{created.share_slug}/challenge",
        share_participant_request_attrs("Guest User", created, auth_key)
        |> Map.put("response", Base.url_encode64(response, padding: false))
        |> Map.put("password_challenge_hash", password_challenge_hash(created.share_slug))
      )

    assert %{"root" => %{"kind" => "document"}, "participant" => %{"grant" => "view"}} =
             json_response(respond_conn, 200)

    assert respond_conn.resp_cookies["_refmd_share_session"].path == "/api"
  end

  test "password challenge failure returns unified not_found", %{
    conn: conn,
    document: document,
    owner_id: owner_id
  } do
    {created, auth_key} = create_password_protected_share(document, owner_id)

    challenge_conn = get(conn, "/api/shares/#{created.share_slug}/challenge")
    assert %{"challenge" => _challenge} = json_response(challenge_conn, 200)

    respond_conn =
      build_conn()
      |> post(
        "/api/shares/#{created.share_slug}/challenge",
        share_participant_request_attrs("Guest User", created, auth_key)
        |> Map.put("response", Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false))
        |> Map.put("password_challenge_hash", password_challenge_hash(created.share_slug))
      )

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
             "share_token_hash" => created.share.token_hash
           }
  end

  test "POST /api/shares/d/:document_token/bootstrap returns canonical bootstrap with a share session",
       %{
         conn: conn,
         document: document,
         owner_id: owner_id
       } do
    created = create_share(document, owner_id)
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    {:ok, bootstrapped} =
      bootstrap_share_participant(created, "Guest User")

    conn =
      conn
      |> put_req_header(
        "cookie",
        "_refmd_share_session=#{Base.url_encode64(bootstrapped.session_token, padding: false)}"
      )
      |> post(
        "/api/shares/d/#{landing.root.document_token}/bootstrap",
        %{
          "authenticated_workspace_pin_bootstrap_hash" =>
            created.share.authenticated_workspace_pin_bootstrap_hash
        }
      )

    assert %{
             "document_id" => document_id,
             "share_id" => share_id,
             "share_token_hash" => share_token_hash,
             "permission" => "view",
             "encrypted_dek" => encrypted_dek,
             "verification_directory" => verification_directory
           } = json_response(conn, 200)

    assert document_id == document.id
    assert share_id == created.share.id
    assert share_token_hash == created.share.token_hash
    assert is_binary(encrypted_dek)

    assert %{
             "workspace_devices" => [_],
             "share_participant_devices" => [_]
           } = verification_directory
  end

  test "POST /api/shares/f/:folder_token/bootstrap returns shared descendants", %{
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
      bootstrap_share_participant(created, "Guest User")

    share_session_token = Base.url_encode64(bootstrapped.session_token, padding: false)

    conn =
      conn
      |> put_req_header(
        "cookie",
        "_refmd_share_session=#{share_session_token}"
      )
      |> post(
        "/api/shares/f/#{landing.root.folder_token}/bootstrap",
        %{
          "authenticated_workspace_pin_bootstrap_hash" =>
            created.share.authenticated_workspace_pin_bootstrap_hash
        }
      )

    assert %{
             "share_id" => share_id,
             "share_token_hash" => share_token_hash,
             "password_protected" => false,
             "folder" => root_folder,
             "entries" => entries
           } =
             json_response(conn, 200)

    assert share_id == created.share.id
    assert share_token_hash == created.share.token_hash
    assert root_folder["share_id"] == created.share.id
    assert root_folder["parent_id"] == nil
    assert is_binary(root_folder["encrypted_dek"])
    assert is_binary(root_folder["nonce"])

    shared_entry = Enum.find(entries, &(&1["id"] == shared_document.id))
    assert is_binary(shared_entry["share_id"])
    refute shared_entry["share_id"] == created.share.id
    assert is_binary(shared_entry["document_token"])

    assert shared_entry["encrypted_title"] ==
             Base.url_encode64(shared_document.encrypted_title, padding: false)

    assert shared_entry["encrypted_title_nonce"] ==
             Base.url_encode64(shared_document.encrypted_title_nonce, padding: false)

    assert is_binary(shared_entry["encrypted_dek"])
    assert is_binary(shared_entry["nonce"])

    nested_folder_entry = Enum.find(entries, &(&1["id"] == nested_folder.id))
    assert is_binary(nested_folder_entry["share_id"])
    refute nested_folder_entry["share_id"] == created.share.id
    assert is_binary(nested_folder_entry["folder_token"])
    assert is_binary(nested_folder_entry["encrypted_dek"])
    assert is_binary(nested_folder_entry["nonce"])

    refute Enum.any?(entries, &(&1["id"] == nested_document.id))

    nested_conn =
      build_conn()
      |> put_req_header("cookie", "_refmd_share_session=#{share_session_token}")
      |> post(
        "/api/shares/f/#{nested_folder_entry["folder_token"]}/bootstrap",
        %{
          "authenticated_workspace_pin_bootstrap_hash" =>
            created.share.authenticated_workspace_pin_bootstrap_hash
        }
      )

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
    assert is_binary(nested_entry["nonce"])
  end
end
