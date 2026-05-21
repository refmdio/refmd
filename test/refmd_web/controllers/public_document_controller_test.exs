defmodule RefMDWeb.PublicDocumentControllerTest do
  use RefMDWeb.ConnCase, async: true
  import Phoenix.ConnTest, except: [delete: 2, patch: 3, post: 3, put: 3]

  alias RefMD.Auth
  alias RefMD.Documents
  alias RefMD.Public
  alias RefMD.Repo
  alias RefMD.Users.User
  alias RefMD.Workspaces
  alias RefMD.Workspaces.WorkspaceMember

  defp create_user(email) do
    user_id = Ecto.UUID.generate()

    Repo.insert!(%User{
      id: user_id,
      email: email,
      name: email
    })

    user_id
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

  defp pop_conn(conn, user_id, user_device) do
    conn
    |> authed_conn(user_id, user_device.device)
    |> put_private(:test_pop_args, {user_id, user_device.device, user_device.signing_private_key})
  end

  defp post(conn, path, body) do
    conn
    |> maybe_put_deferred_pop("POST", path, body)
    |> Phoenix.ConnTest.dispatch(@endpoint, :post, path, test_json_body(body))
  end

  defp patch(conn, path, body) do
    conn
    |> maybe_put_deferred_pop("PATCH", path, body)
    |> Phoenix.ConnTest.dispatch(@endpoint, :patch, path, test_json_body(body))
  end

  defp put(conn, path, body) do
    conn
    |> maybe_put_deferred_pop("PUT", path, body)
    |> Phoenix.ConnTest.dispatch(@endpoint, :put, path, test_json_body(body))
  end

  defp delete(conn, path) do
    conn
    |> maybe_put_deferred_pop("DELETE", path, "")
    |> Phoenix.ConnTest.dispatch(@endpoint, :delete, path, "")
  end

  defp maybe_put_deferred_pop(conn, method, path, body) do
    case conn.private[:test_pop_args] do
      {user_id, device, signing_private_key} ->
        with_pop_headers(conn, user_id, device, signing_private_key, method, path, body)

      _ ->
        conn
    end
  end

  defp add_member(workspace_id, user_id, base_role) do
    role =
      workspace_id
      |> Workspaces.list_workspace_roles()
      |> Enum.find(&(&1.base_role == base_role))

    Repo.insert!(%WorkspaceMember{
      workspace_id: workspace_id,
      user_id: user_id,
      role_id: role.id,
      is_default: false,
      joined_at: DateTime.utc_now()
    })
  end

  defp publication_body(slug, title \\ "Public Title", content \\ "# Hello\n\nPublic body") do
    %{
      "slug" => slug,
      "title" => title,
      "content" => content,
      "content_hash" => Public.content_hash(title, content),
      "noindex" => false
    }
  end

  setup %{conn: conn} do
    owner_id = create_user("public-owner@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Public Workspace")
    {:ok, workspace} = Workspaces.update_workspace(workspace, %{public_publishing_enabled: true})

    {:ok, profile} =
      Public.upsert_author_profile(workspace.id, %{
        "public_author_display_name" => "Public Author",
        "public_author_slug" => "public-author",
        "public_author_bio" => "Author description"
      })

    document = create_document(workspace.id, owner_id)
    owner_device = create_device(owner_id)
    {_member, owner_role} = Workspaces.get_member_with_role(workspace.id, owner_id)

    %{
      conn: conn,
      authed: pop_conn(conn, owner_id, owner_device),
      owner_id: owner_id,
      owner_role: owner_role,
      owner_device: owner_device,
      author_slug: profile.slug,
      workspace: workspace,
      document: document
    }
  end

  test "POST /api/documents/:document_id/publication creates public projection", %{
    authed: conn,
    document: document,
    author_slug: author_slug
  } do
    conn =
      post(conn, "/api/documents/#{document.id}/publication", publication_body("public-title"))

    assert %{
             "document_id" => document_id,
             "slug" => "public-title",
             "url" => url,
             "noindex" => false
           } = json_response(conn, 201)

    assert document_id == document.id
    assert url == "/@#{author_slug}/public-title"
  end

  test "publication rejects invalid content hash", %{authed: conn, document: document} do
    body = Map.put(publication_body("bad-hash"), "content_hash", "wrong")

    conn = post(conn, "/api/documents/#{document.id}/publication", body)

    assert json_response(conn, 422) == %{"error" => "invalid_hash"}
  end

  test "duplicate slug returns suggested slug", %{
    conn: conn,
    document: first,
    owner_id: owner_id,
    owner_device: owner_device,
    workspace: workspace
  } do
    second = create_document(workspace.id, owner_id)

    assert json_response(
             conn
             |> pop_conn(owner_id, owner_device)
             |> post("/api/documents/#{first.id}/publication", publication_body("same-slug")),
             201
           )

    duplicate_conn =
      conn
      |> pop_conn(owner_id, owner_device)
      |> post("/api/documents/#{second.id}/publication", publication_body("same-slug"))

    assert %{"error" => "slug_conflict", "suggested_slug" => "same-slug-2"} =
             json_response(duplicate_conn, 409)
  end

  test "PUT /api/documents/:document_id/publication/content updates plaintext content", %{
    conn: conn,
    owner_id: owner_id,
    owner_device: owner_device,
    document: document,
    author_slug: author_slug
  } do
    assert json_response(
             conn
             |> pop_conn(owner_id, owner_device)
             |> post("/api/documents/#{document.id}/publication", publication_body("sync-doc")),
             201
           )

    title = "Updated Public Title"
    content = "Updated body"

    update_conn =
      conn
      |> pop_conn(owner_id, owner_device)
      |> put("/api/documents/#{document.id}/publication/content", %{
        "title" => title,
        "content" => content,
        "content_hash" => Public.content_hash(title, content)
      })

    assert %{"updated_at" => _updated_at} = json_response(update_conn, 200)

    public_conn = get(build_conn(), "/api/public/authors/#{author_slug}/documents/sync-doc")

    assert %{
             "title" => ^title,
             "content" => ^content,
             "author_description" => "Author description"
           } = json_response(public_conn, 200)
  end

  test "PUT /api/documents/:document_id/publication/content allows editor workspace members",
       %{
         conn: conn,
         owner_id: owner_id,
         owner_device: owner_device,
         document: document,
         workspace: workspace
       } do
    assert json_response(
             conn
             |> pop_conn(owner_id, owner_device)
             |> post("/api/documents/#{document.id}/publication", publication_body("editor-sync")),
             201
           )

    editor_id = create_user("public-editor@example.com")
    add_member(workspace.id, editor_id, "editor")
    editor_device = create_device(editor_id)
    title = "Editor Synced"
    content = "Editor content"

    sync_conn =
      build_conn()
      |> pop_conn(editor_id, editor_device)
      |> put("/api/documents/#{document.id}/publication/content", %{
        "title" => title,
        "content" => content,
        "content_hash" => Public.content_hash(title, content)
      })

    assert %{"updated_at" => _updated_at} = json_response(sync_conn, 200)
  end

  test "PUT /api/documents/:document_id/publication/content rejects same-hash sync when public publishing is disabled",
       %{
         conn: conn,
         owner_id: owner_id,
         owner_device: owner_device,
         document: document,
         workspace: workspace
       } do
    body = publication_body("disabled-sync")

    assert json_response(
             conn
             |> pop_conn(owner_id, owner_device)
             |> post("/api/documents/#{document.id}/publication", body),
             201
           )

    {:ok, _workspace} =
      Workspaces.update_workspace(workspace, %{public_publishing_enabled: false})

    sync_conn =
      conn
      |> pop_conn(owner_id, owner_device)
      |> put("/api/documents/#{document.id}/publication/content", %{
        "title" => body["title"],
        "content" => body["content"],
        "content_hash" => body["content_hash"]
      })

    assert json_response(sync_conn, 403) == %{"error" => "public_publishing_disabled"}
  end

  test "PATCH publication updates slug without retaining old URL history", %{
    conn: conn,
    owner_id: owner_id,
    owner_device: owner_device,
    document: document,
    author_slug: author_slug
  } do
    assert json_response(
             conn
             |> pop_conn(owner_id, owner_device)
             |> post("/api/documents/#{document.id}/publication", publication_body("old-slug")),
             201
           )

    update_conn =
      conn
      |> pop_conn(owner_id, owner_device)
      |> patch("/api/documents/#{document.id}/publication", %{
        "slug" => "new-slug",
        "noindex" => true
      })

    assert %{"slug" => "new-slug", "noindex" => true} = json_response(update_conn, 200)

    old_conn = get(build_conn(), "/@#{author_slug}/old-slug")
    assert response(old_conn, 404) == "Not Found"

    current_conn = get(build_conn(), "/@#{author_slug}/new-slug")
    assert response(current_conn, 200)
  end

  test "DELETE publication removes public URL without gone history", %{
    conn: conn,
    owner_id: owner_id,
    owner_device: owner_device,
    document: document,
    author_slug: author_slug
  } do
    assert json_response(
             conn
             |> pop_conn(owner_id, owner_device)
             |> post("/api/documents/#{document.id}/publication", publication_body("gone-slug")),
             201
           )

    delete_conn =
      conn
      |> pop_conn(owner_id, owner_device)
      |> delete("/api/documents/#{document.id}/publication")

    assert response(delete_conn, 204) == ""

    gone_conn = get(build_conn(), "/@#{author_slug}/gone-slug")
    assert response(gone_conn, 404) == "Not Found"
  end

  test "GET /api/public/authors/:author_slug returns flattened author fields", %{
    authed: conn,
    document: document,
    author_slug: author_slug
  } do
    assert json_response(
             post(
               conn,
               "/api/documents/#{document.id}/publication",
               publication_body("author-doc", "Author Doc", "# Heading\n\nDocument content")
             ),
             201
           )

    author_conn = get(build_conn(), "/api/public/authors/#{author_slug}")

    response = json_response(author_conn, 200)

    assert %{
             "author_slug" => ^author_slug,
             "author_name" => "Public Author",
             "author_description" => "Author description",
             "documents" => [
               %{
                 "slug" => "author-doc",
                 "excerpt" => "Heading Document content"
               }
             ]
           } = response

    refute Map.has_key?(response, "author")
  end

  test "same document can republish a previously used slug", %{
    conn: conn,
    owner_id: owner_id,
    owner_device: owner_device,
    document: document
  } do
    assert json_response(
             conn
             |> pop_conn(owner_id, owner_device)
             |> post("/api/documents/#{document.id}/publication", publication_body("reuse-slug")),
             201
           )

    assert response(
             conn
             |> pop_conn(owner_id, owner_device)
             |> delete("/api/documents/#{document.id}/publication"),
             204
           ) == ""

    republish_conn =
      conn
      |> pop_conn(owner_id, owner_device)
      |> post("/api/documents/#{document.id}/publication", publication_body("reuse-slug"))

    assert %{"slug" => "reuse-slug"} = json_response(republish_conn, 201)
  end

  test "deleting the underlying document broadcasts unpublished state", %{
    conn: conn,
    owner_id: owner_id,
    owner_device: owner_device,
    document: document
  } do
    assert json_response(
             conn
             |> pop_conn(owner_id, owner_device)
             |> post("/api/documents/#{document.id}/publication", publication_body("deleted-doc")),
             201
           )

    Phoenix.PubSub.subscribe(RefMD.PubSub, "document:#{document.id}")

    delete_document_conn =
      conn
      |> pop_conn(owner_id, owner_device)
      |> delete("/api/documents/#{document.id}")

    assert json_response(delete_document_conn, 200) == %{"ok" => true}

    assert_receive %Phoenix.Socket.Broadcast{
      event: "public-status-changed",
      topic: topic,
      payload: %{is_published: false, updated_at: nil}
    }

    assert topic == "document:#{document.id}"
  end

  test "public page includes noindex and escaped metadata", %{
    authed: conn,
    document: document,
    author_slug: author_slug
  } do
    title = ~s(<Title & Test>)
    content = "Searchable **summary**"

    body =
      "meta-doc"
      |> publication_body(title, content)
      |> Map.put("noindex", true)

    assert json_response(post(conn, "/api/documents/#{document.id}/publication", body), 201)

    conn = get(build_conn(), "/@#{author_slug}/meta-doc")
    html = response(conn, 200)

    assert get_resp_header(conn, "cache-control") == ["no-store"]
    assert html =~ ~s(<meta name="robots" content="noindex">)
    assert html =~ ~s(<meta property="og:title" content="&lt;Title &amp; Test&gt;">)
    assert html =~ ~s(<meta property="og:description" content="Searchable summary">)
    assert html =~ ~s(<meta property="og:image" content="/og-default.png">)
    assert html =~ "&lt;Title &amp; Test&gt;"
    refute html =~ title
  end

  test "public author page includes escaped metadata", %{
    authed: conn,
    document: document,
    author_slug: author_slug
  } do
    assert json_response(
             post(conn, "/api/documents/#{document.id}/publication", publication_body("og-doc")),
             201
           )

    conn = get(build_conn(), "/@#{author_slug}")
    html = response(conn, 200)

    assert get_resp_header(conn, "cache-control") == ["no-store"]
    assert html =~ ~s(<title>Public Author</title>)
    assert html =~ ~s(<meta property="og:title" content="Public Author">)
    assert html =~ ~s(<meta property="og:description" content="Author description">)
    assert html =~ ~s(<meta property="og:type" content="profile">)
    assert html =~ ~s(<meta property="og:url" content="http://www.example.com/@#{author_slug}">)
    assert html =~ ~s(<meta property="og:image" content="/og-default.png">)
  end
end
