defmodule RefMDWeb.ShareMountControllerTest do
  use RefMDWeb.ConnCase, async: true
  import Phoenix.ConnTest, except: [delete: 2, get: 2, patch: 3, post: 3]

  import Ecto.Query

  alias RefMD.Auth
  alias RefMD.Crypto.Blake3
  alias RefMD.Documents
  alias RefMD.Documents.Ordering
  alias RefMD.Repo
  alias RefMD.Sharing
  alias RefMD.Sharing.Share
  alias RefMD.Sharing.SharedDocumentToken
  alias RefMD.Sharing.SharedFolderToken
  alias RefMD.Sharing.ShareMount
  alias RefMD.Users.User
  alias RefMD.Workspaces

  defp workspace_pin_bootstrap_hash,
    do: Process.get(:workspace_pin_bootstrap_hash, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

  defp mount_password_challenge_hash(mount_id), do: Blake3.hash_base64url("mount:" <> mount_id)

  defp create_user(email) do
    user_id = Ecto.UUID.generate()

    Repo.insert!(%User{
      id: user_id,
      email: email,
      name: email
    })

    user_id
  end

  defp create_document(workspace_id, created_by, doc_type \\ "document", parent_id \\ nil) do
    attrs =
      %{
        "id" => Ecto.UUID.generate(),
        "workspace_id" => workspace_id,
        "doc_type" => doc_type,
        "parent_id" => parent_id,
        "title" => if(doc_type == "folder", do: "Folder", else: "Untitled"),
        "created_by" => created_by
      }
      |> maybe_put_encrypted_title(doc_type)

    {:ok, document} = Documents.create_document(attrs)
    document
  end

  defp maybe_put_encrypted_title(attrs, "folder"), do: attrs

  defp maybe_put_encrypted_title(attrs, _doc_type) do
    Map.merge(attrs, %{
      "encrypted_title" => <<1, 2, 3>>,
      "encrypted_title_nonce" => :crypto.strong_rand_bytes(24),
      "encrypted_title_key_version" => 1
    })
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

  defp authed_conn_with_share_session(conn, user_id, device, share_session_token) do
    {:ok, session, token} = Auth.create_session(user_id, %{device_id: device.id})

    conn
    |> put_req_header(
      "cookie",
      "_refmd_session=#{Base.url_encode64(token, padding: false)}; _refmd_share_session=#{Base.url_encode64(share_session_token, padding: false)}"
    )
    |> put_private(:test_session, session)
  end

  defp authed_conn_with_mount_session(conn, user_id, device, mount_session_cookie) do
    {:ok, session, token} = Auth.create_session(user_id, %{device_id: device.id})

    conn
    |> put_req_header(
      "cookie",
      "_refmd_session=#{Base.url_encode64(token, padding: false)}; _refmd_mount_session=#{mount_session_cookie}"
    )
    |> put_private(:test_session, session)
  end

  defp mount_session_cookie(conn) do
    conn.resp_cookies["_refmd_mount_session"].value
  end

  defp with_pop_headers(conn, user_id, device, signing_private_key) do
    put_private(conn, :test_pop_args, {user_id, device, signing_private_key})
  end

  defp post(conn, path, body) do
    {request_path, query} = split_request_path(path)

    conn
    |> maybe_put_deferred_pop("POST", request_path, body, query)
    |> put_json_content_type()
    |> Phoenix.ConnTest.dispatch(@endpoint, :post, path, test_json_body(body))
  end

  defp patch(conn, path, body) do
    {request_path, query} = split_request_path(path)

    conn
    |> maybe_put_deferred_pop("PATCH", request_path, body, query)
    |> put_json_content_type()
    |> Phoenix.ConnTest.dispatch(@endpoint, :patch, path, test_json_body(body))
  end

  defp delete(conn, path) do
    {request_path, query} = split_request_path(path)

    conn
    |> maybe_put_deferred_pop("DELETE", request_path, "", query)
    |> Phoenix.ConnTest.dispatch(@endpoint, :delete, path, nil)
  end

  defp get(conn, path) do
    {request_path, query} = split_request_path(path)

    conn
    |> maybe_put_deferred_pop("GET", request_path, "", query)
    |> Phoenix.ConnTest.dispatch(@endpoint, :get, path, nil)
  end

  defp maybe_put_deferred_pop(conn, method, path, body, query) do
    case conn.private[:test_pop_args] do
      {user_id, device, signing_private_key} ->
        put_test_pop_headers(
          conn,
          user_id,
          device,
          signing_private_key,
          method,
          path,
          body,
          query
        )

      _ ->
        conn
    end
  end

  defp split_request_path(path) do
    case String.split(path, "?", parts: 2) do
      [request_path, query] -> {request_path, query}
      [request_path] -> {request_path, ""}
    end
  end

  defp put_json_content_type(conn), do: put_req_header(conn, "content-type", "application/json")

  defp create_document_share(document, owner_id, opts \\ []) do
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
    password_protected = Keyword.get(opts, :password_protected, false)

    attrs =
      %{
        "id" => Ecto.UUID.generate(),
        "scope" => "document",
        "share_slug" => share_slug,
        "token_prefix" => String.slice(share_slug, 0, 4),
        "permission" => "view",
        "password_protected" => password_protected,
        "authorization_public_key_material" =>
          share_capability_public_key_material_for_slug(open_admission_key(), share_slug),
        "share_capability_secret_commitment" => open_share_capability_secret_commitment(),
        "authenticated_workspace_pin_bootstrap_hash" => workspace_pin_bootstrap_hash(),
        "encrypted_dek" => :crypto.strong_rand_bytes(48),
        "nonce" => :crypto.strong_rand_bytes(24),
        "max_views" => Keyword.get(opts, :max_views)
      }
      |> maybe_put_password_fields(opts)
      |> with_test_share_security_artifacts(document, owner_id)

    {:ok, created} = Sharing.create_share(document, owner_id, attrs)
    {created, Keyword.get(opts, :auth_key)}
  end

  defp create_folder_share(folder, owner_id, shared_nodes, opts \\ []) do
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
    password_protected = Keyword.get(opts, :password_protected, false)

    attrs =
      %{
        "id" => Ecto.UUID.generate(),
        "scope" => "folder",
        "share_slug" => share_slug,
        "token_prefix" => String.slice(share_slug, 0, 4),
        "permission" => "view",
        "password_protected" => password_protected,
        "authorization_public_key_material" =>
          share_capability_public_key_material_for_slug(open_admission_key(), share_slug),
        "share_capability_secret_commitment" => open_share_capability_secret_commitment(),
        "authenticated_workspace_pin_bootstrap_hash" => workspace_pin_bootstrap_hash(),
        "encrypted_dek" => :crypto.strong_rand_bytes(48),
        "nonce" => :crypto.strong_rand_bytes(24),
        "max_views" => Keyword.get(opts, :max_views),
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
      |> maybe_put_password_fields(opts)
      |> with_test_share_security_artifacts(folder, owner_id)

    {:ok, created} = Sharing.create_share(folder, owner_id, attrs)
    {created, Keyword.get(opts, :auth_key)}
  end

  defp maybe_put_password_fields(attrs, opts) do
    if Keyword.get(opts, :password_protected, false) do
      auth_key = Keyword.get_lazy(opts, :auth_key, fn -> :crypto.strong_rand_bytes(32) end)

      Map.merge(attrs, %{
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
    else
      attrs
    end
  end

  setup do
    owner_id = create_user("owner-share-mount@example.com")
    mount_user_id = create_user("mount-user@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Share Mount Workspace")
    {:ok, mount_workspace} = Workspaces.create_default_workspace(mount_user_id, "Mount Workspace")
    document = create_document(workspace.id, owner_id)
    folder = create_document(workspace.id, owner_id, "folder")
    mount_user_device = create_device(mount_user_id)
    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)
    Process.put(:workspace_pin_bootstrap_hash, test_workspace_pin_bootstrap_hash!(workspace.id))

    %{
      owner_id: owner_id,
      mount_user_id: mount_user_id,
      workspace: workspace,
      mount_workspace: mount_workspace,
      document: document,
      folder: folder,
      mount_user_device: mount_user_device
    }
  end

  test "POST /api/mounts creates a document mount", %{
    conn: conn,
    owner_id: owner_id,
    mount_user_id: mount_user_id,
    document: document,
    mount_workspace: mount_workspace,
    mount_user_device: mount_user_device
  } do
    {created, _auth_key} = create_document_share(document, owner_id, max_views: 1)
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    conn =
      conn
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> post("/api/mounts", %{
        "workspace_id" => mount_workspace.id,
        "share_slug" => created.share_slug,
        "target_kind" => "document",
        "target_token" => landing.root.document_token,
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    response = json_response(conn, 201)

    refute Map.has_key?(response, "title_state")

    assert %{
             "id" => mount_id,
             "workspace_id" => workspace_id,
             "share_id" => share_id,
             "target_kind" => "document",
             "status" => "active",
             "target" => %{"document_id" => document_id}
           } = response

    assert workspace_id == mount_workspace.id
    assert share_id == created.share.id
    assert document_id == document.id
    assert Ecto.UUID.cast(mount_id) != :error
  end

  test "POST /api/mounts rejects a mismatched authenticated workspace pin bootstrap hash", %{
    conn: conn,
    owner_id: owner_id,
    mount_user_id: mount_user_id,
    document: document,
    mount_workspace: mount_workspace,
    mount_user_device: mount_user_device
  } do
    {created, _auth_key} = create_document_share(document, owner_id, max_views: 1)
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    conn =
      conn
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> post("/api/mounts", %{
        "workspace_id" => mount_workspace.id,
        "share_slug" => created.share_slug,
        "target_kind" => "document",
        "target_token" => landing.root.document_token,
        "authenticated_workspace_pin_bootstrap_hash" =>
          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      })

    assert %{"error" => "not_found"} = json_response(conn, 404)

    refute Repo.get_by(ShareMount,
             user_id: mount_user_id,
             share_id: created.share.id,
             target_document_id: document.id
           )
  end

  test "mounted document bootstrap rejects when source workspace share links are disabled", %{
    conn: conn,
    owner_id: owner_id,
    mount_user_id: mount_user_id,
    workspace: workspace,
    document: document,
    mount_workspace: mount_workspace,
    mount_user_device: mount_user_device
  } do
    {created, _auth_key} = create_document_share(document, owner_id)
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    create_conn =
      conn
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> post("/api/mounts", %{
        "workspace_id" => mount_workspace.id,
        "share_slug" => created.share_slug,
        "target_kind" => "document",
        "target_token" => landing.root.document_token,
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    %{"id" => mount_id} = json_response(create_conn, 201)

    assert {:ok, _workspace} =
             Workspaces.update_workspace(workspace, %{share_links_enabled: false})

    detail_conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> post("/api/mounts/#{mount_id}/documents/#{landing.root.document_token}/bootstrap", %{
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    assert json_response(detail_conn, 404)
  end

  test "document creation uses combined document and mount ordering", %{
    conn: conn,
    owner_id: owner_id,
    mount_user_id: mount_user_id,
    document: document,
    mount_workspace: mount_workspace,
    mount_user_device: mount_user_device
  } do
    local_document = create_document(mount_workspace.id, mount_user_id)
    {created, _auth_key} = create_document_share(document, owner_id)
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    create_conn =
      conn
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> post("/api/mounts", %{
        "workspace_id" => mount_workspace.id,
        "share_slug" => created.share_slug,
        "target_kind" => "document",
        "target_token" => landing.root.document_token,
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    %{"id" => mount_id} = json_response(create_conn, 201)
    next_document = create_document(mount_workspace.id, mount_user_id)

    assert Repo.reload!(local_document).position == 0
    assert Repo.get!(ShareMount, mount_id).position == 1
    assert Repo.reload!(next_document).position == 2
  end

  test "document creation appends after combined ordering gaps", %{
    mount_user_id: mount_user_id,
    mount_workspace: mount_workspace
  } do
    first_document = create_document(mount_workspace.id, mount_user_id)
    gap_document = create_document(mount_workspace.id, mount_user_id)
    assert {:ok, _deleted} = Documents.delete_document(gap_document)

    next_document = create_document(mount_workspace.id, mount_user_id)

    assert Repo.reload!(first_document).position == 0
    assert Repo.reload!(next_document).position == 1
  end

  test "document parent updates normalize combined document and mount ordering", %{
    conn: conn,
    owner_id: owner_id,
    mount_user_id: mount_user_id,
    document: document,
    mount_workspace: mount_workspace,
    mount_user_device: mount_user_device
  } do
    destination_folder = create_document(mount_workspace.id, mount_user_id, "folder")
    moving_document = create_document(mount_workspace.id, mount_user_id)
    {created, _auth_key} = create_document_share(document, owner_id)
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    create_conn =
      conn
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> post("/api/mounts", %{
        "workspace_id" => mount_workspace.id,
        "share_slug" => created.share_slug,
        "target_kind" => "document",
        "target_token" => landing.root.document_token,
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    %{"id" => mount_id} = json_response(create_conn, 201)

    assert {:ok, updated_document} =
             Documents.update_document(moving_document, %{"parent_id" => destination_folder.id})

    assert Repo.reload!(destination_folder).position == 0
    assert Repo.get!(ShareMount, mount_id).position == 1
    assert updated_document.parent_id == destination_folder.id
    assert updated_document.position == 0
  end

  test "folder delete rejects folders containing only share mounts", %{
    conn: conn,
    owner_id: owner_id,
    mount_user_id: mount_user_id,
    document: document,
    mount_workspace: mount_workspace,
    mount_user_device: mount_user_device
  } do
    destination_folder = create_document(mount_workspace.id, mount_user_id, "folder")
    {created, _auth_key} = create_document_share(document, owner_id)
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    create_conn =
      conn
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> post("/api/mounts", %{
        "workspace_id" => mount_workspace.id,
        "share_slug" => created.share_slug,
        "target_kind" => "document",
        "target_token" => landing.root.document_token,
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    %{"id" => mount_id} = json_response(create_conn, 201)

    assert {:ok, _mount} =
             Sharing.update_share_mount(mount_user_id, mount_id, %{
               "parent_id" => destination_folder.id,
               "position" => 0
             })

    assert {:error, :folder_not_empty} = Documents.delete_document(destination_folder)
  end

  test "document reorder normalizes combined document and mount ordering", %{
    conn: conn,
    owner_id: owner_id,
    mount_user_id: mount_user_id,
    document: document,
    mount_workspace: mount_workspace,
    mount_user_device: mount_user_device
  } do
    first_document = create_document(mount_workspace.id, mount_user_id)
    {created, _auth_key} = create_document_share(document, owner_id)
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    create_conn =
      conn
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> post("/api/mounts", %{
        "workspace_id" => mount_workspace.id,
        "share_slug" => created.share_slug,
        "target_kind" => "document",
        "target_token" => landing.root.document_token,
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    %{"id" => mount_id} = json_response(create_conn, 201)
    second_document = create_document(mount_workspace.id, mount_user_id)

    assert {:ok, _document} =
             Documents.reorder_document(mount_workspace.id, second_document.id, nil, 1)

    assert Repo.reload!(first_document).position == 0
    assert Repo.reload!(second_document).position == 1
    assert Repo.get!(ShareMount, mount_id).position == 2
  end

  test "combined ordering tie-break matches sidebar id ordering", %{
    conn: conn,
    owner_id: owner_id,
    mount_user_id: mount_user_id,
    document: document,
    mount_workspace: mount_workspace,
    mount_user_device: mount_user_device
  } do
    local_document = create_document(mount_workspace.id, mount_user_id)
    {created, _auth_key} = create_document_share(document, owner_id)
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    create_conn =
      conn
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> post("/api/mounts", %{
        "workspace_id" => mount_workspace.id,
        "share_slug" => created.share_slug,
        "target_kind" => "document",
        "target_token" => landing.root.document_token,
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    %{"id" => mount_id} = json_response(create_conn, 201)

    from(m in ShareMount, where: m.id == ^mount_id)
    |> Repo.update_all(set: [position: local_document.position])

    assert :ok = Ordering.normalize_combined_siblings!(mount_workspace.id, nil)

    ordered =
      [
        {local_document.id, Repo.reload!(local_document).position},
        {mount_id, Repo.get!(ShareMount, mount_id).position}
      ]
      |> Enum.sort_by(fn {_id, position} -> position end)
      |> Enum.map(fn {id, _position} -> id end)

    assert ordered == Enum.sort([local_document.id, mount_id])
  end

  test "POST /api/mounts returns 409 for duplicate mounts", %{
    conn: conn,
    owner_id: owner_id,
    mount_user_id: mount_user_id,
    document: document,
    mount_workspace: mount_workspace,
    mount_user_device: mount_user_device
  } do
    {created, _auth_key} = create_document_share(document, owner_id)
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    authed =
      conn
      |> authed_conn(mount_user_id, mount_user_device.device)

    assert json_response(
             post(authed, "/api/mounts", %{
               "workspace_id" => mount_workspace.id,
               "share_slug" => created.share_slug,
               "target_kind" => "document",
               "target_token" => landing.root.document_token,
               "authenticated_workspace_pin_bootstrap_hash" =>
                 created.share.authenticated_workspace_pin_bootstrap_hash
             }),
             201
           )

    duplicate_conn =
      post(authed, "/api/mounts", %{
        "workspace_id" => mount_workspace.id,
        "share_slug" => created.share_slug,
        "target_kind" => "document",
        "target_token" => landing.root.document_token,
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    assert %{
             "mount" => %{
               "workspace_id" => workspace_id,
               "target_document_id" => target_document_id
             }
           } =
             json_response(duplicate_conn, 409)

    assert workspace_id == mount_workspace.id
    assert target_document_id == document.id
  end

  test "POST /api/mounts reopens existing mount after consuming the share admission limit", %{
    conn: conn,
    owner_id: owner_id,
    mount_user_id: mount_user_id,
    document: document,
    mount_workspace: mount_workspace,
    mount_user_device: mount_user_device
  } do
    {created, _auth_key} = create_document_share(document, owner_id, max_views: 1)
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    first_conn =
      conn
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> post("/api/mounts", %{
        "workspace_id" => mount_workspace.id,
        "share_slug" => created.share_slug,
        "target_kind" => "document",
        "target_token" => landing.root.document_token,
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    assert %{"id" => mount_id} = json_response(first_conn, 201)
    assert Repo.get!(Share, created.share.id).view_count == 1

    reopen_conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> post("/api/mounts/#{mount_id}/documents/#{landing.root.document_token}/bootstrap", %{
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    assert %{"mount" => %{"id" => ^mount_id}} = json_response(reopen_conn, 200)
    assert Repo.get!(Share, created.share.id).view_count == 1
  end

  test "POST /api/mounts accepts an admitted session after the share admission limit", %{
    conn: conn,
    owner_id: owner_id,
    mount_user_id: mount_user_id,
    document: document,
    mount_workspace: mount_workspace,
    mount_user_device: mount_user_device
  } do
    {created, _auth_key} = create_document_share(document, owner_id, max_views: 1)
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    {:ok, participant} = bootstrap_share_participant(created, "Mount Guest")

    assert {:ok, _canonical} =
             Sharing.get_document_bootstrap(
               landing.root.document_token,
               Base.url_encode64(participant.session_token, padding: false),
               workspace_pin_bootstrap_hash()
             )

    assert Repo.get!(Share, created.share.id).view_count == 1

    conn =
      conn
      |> authed_conn_with_share_session(
        mount_user_id,
        mount_user_device.device,
        participant.session_token
      )
      |> post("/api/mounts", %{
        "workspace_id" => mount_workspace.id,
        "share_slug" => created.share_slug,
        "target_kind" => "document",
        "target_token" => landing.root.document_token,
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    assert %{"id" => mount_id} = json_response(conn, 201)
    assert is_binary(mount_id)
    assert Repo.get!(Share, created.share.id).view_count == 1
  end

  test "mounted document bootstrap reopens from mount state without public participant ids", %{
    conn: conn,
    owner_id: owner_id,
    mount_user_id: mount_user_id,
    document: document,
    mount_workspace: mount_workspace,
    mount_user_device: mount_user_device
  } do
    {created, _auth_key} = create_document_share(document, owner_id, max_views: 1)
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)
    {:ok, participant} = bootstrap_share_participant(created, "Mount Guest")

    assert {:ok, _canonical} =
             Sharing.get_document_bootstrap(
               landing.root.document_token,
               Base.url_encode64(participant.session_token, padding: false),
               workspace_pin_bootstrap_hash()
             )

    create_conn =
      conn
      |> authed_conn_with_share_session(
        mount_user_id,
        mount_user_device.device,
        participant.session_token
      )
      |> post("/api/mounts", %{
        "workspace_id" => mount_workspace.id,
        "share_slug" => created.share_slug,
        "target_kind" => "document",
        "target_token" => landing.root.document_token,
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    %{"id" => mount_id} = json_response(create_conn, 201)

    reopen_conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> post("/api/mounts/#{mount_id}/documents/#{landing.root.document_token}/bootstrap", %{
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    assert %{"mount" => %{"id" => ^mount_id}} = json_response(reopen_conn, 200)

    refute get_resp_header(reopen_conn, "set-cookie")
           |> Enum.any?(&String.contains?(&1, "_refmd_share_session"))

    assert Repo.get!(Share, created.share.id).view_count == 1
  end

  test "POST /api/mounts rejects a new mount admission after the share admission limit",
       %{
         conn: conn,
         owner_id: owner_id,
         mount_user_id: mount_user_id,
         document: document,
         mount_workspace: mount_workspace,
         mount_user_device: mount_user_device
       } do
    {created, _auth_key} = create_document_share(document, owner_id, max_views: 1)
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    {:ok, first_participant} = bootstrap_share_participant(created, "First Mount Guest")

    assert {:ok, _canonical} =
             Sharing.get_document_bootstrap(
               landing.root.document_token,
               Base.url_encode64(first_participant.session_token, padding: false),
               workspace_pin_bootstrap_hash()
             )

    assert Repo.get!(Share, created.share.id).view_count == 1
    assert {:error, :not_found} = bootstrap_share_participant(created, "Second Mount Guest")

    conn =
      conn
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> post("/api/mounts", %{
        "workspace_id" => mount_workspace.id,
        "share_slug" => created.share_slug,
        "target_kind" => "document",
        "target_token" => landing.root.document_token,
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    assert json_response(conn, 404)
    assert Repo.get!(Share, created.share.id).view_count == 1
  end

  test "GET /api/mounts returns current user mounts for the workspace", %{
    conn: conn,
    owner_id: owner_id,
    mount_user_id: mount_user_id,
    document: document,
    mount_workspace: mount_workspace,
    mount_user_device: mount_user_device
  } do
    {created, _auth_key} = create_document_share(document, owner_id)
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    _create_conn =
      conn
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> post("/api/mounts", %{
        "workspace_id" => mount_workspace.id,
        "share_slug" => created.share_slug,
        "target_kind" => "document",
        "target_token" => landing.root.document_token,
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> get("/api/mounts?workspace_id=#{mount_workspace.id}")

    assert %{"mounts" => [%{"share_id" => share_id, "status" => "active"}]} =
             json_response(conn, 200)

    assert share_id == created.share.id
  end

  test "POST /api/mounts/:mount_id/documents/:document_token/bootstrap returns document bootstrap",
       %{
         conn: conn,
         owner_id: owner_id,
         mount_user_id: mount_user_id,
         document: document,
         mount_workspace: mount_workspace,
         mount_user_device: mount_user_device
       } do
    {created, _auth_key} = create_document_share(document, owner_id)
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    create_conn =
      conn
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> post("/api/mounts", %{
        "workspace_id" => mount_workspace.id,
        "share_slug" => created.share_slug,
        "target_kind" => "document",
        "target_token" => landing.root.document_token,
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    %{"id" => mount_id} = json_response(create_conn, 201)
    assert Repo.get!(Share, created.share.id).view_count == 1

    conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> post("/api/mounts/#{mount_id}/documents/#{landing.root.document_token}/bootstrap", %{
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    response = json_response(conn, 200)

    assert %{
             "mount" => %{
               "id" => ^mount_id,
               "share_id" => mount_share_id,
               "status" => "active"
             },
             "document" => %{
               "document_id" => document_id,
               "share_id" => share_id,
               "encrypted_dek" => encrypted_dek
             }
           } = response

    assert Map.keys(response["mount"]) |> Enum.sort() == ["id", "share_id", "status"]
    assert mount_share_id == created.share.id
    assert document_id == document.id
    assert share_id == created.share.id
    assert is_binary(encrypted_dek)
    assert Repo.get!(Share, created.share.id).view_count == 1
  end

  test "POST /api/mounts/:mount_id/folders/:folder_token/bootstrap returns folder subtree", %{
    conn: conn,
    owner_id: owner_id,
    mount_user_id: mount_user_id,
    folder: folder,
    mount_workspace: mount_workspace,
    mount_user_device: mount_user_device
  } do
    child_folder = create_document(folder.workspace_id, owner_id, "folder", folder.id)
    child_document = create_document(folder.workspace_id, owner_id, "document", folder.id)
    nested_document = create_document(folder.workspace_id, owner_id, "document", child_folder.id)

    {created, _auth_key} =
      create_folder_share(folder, owner_id, [child_folder, child_document, nested_document])

    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    create_conn =
      conn
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> post("/api/mounts", %{
        "workspace_id" => mount_workspace.id,
        "share_slug" => created.share_slug,
        "target_kind" => "folder",
        "target_token" => landing.root.folder_token,
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    %{"id" => mount_id} = json_response(create_conn, 201)

    conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> post("/api/mounts/#{mount_id}/folders/#{landing.root.folder_token}/bootstrap", %{
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    assert %{
             "mount" => %{"id" => ^mount_id},
             "folder" => %{"id" => folder_id},
             "entries" => entries
           } = json_response(conn, 200)

    assert folder_id == folder.id
    refute Map.has_key?(json_response(conn, 200)["folder"], "title")
    assert Enum.any?(entries, &(&1["id"] == child_folder.id))
    assert Enum.any?(entries, &(&1["id"] == child_document.id))
    refute Enum.any?(entries, &(&1["id"] == nested_document.id))
    refute Enum.any?(entries, &Map.has_key?(&1, "title"))

    child_folder_entry = Enum.find(entries, &(&1["id"] == child_folder.id))
    assert is_binary(child_folder_entry["folder_token"])

    nested_conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> post(
        "/api/mounts/#{mount_id}/folders/#{child_folder_entry["folder_token"]}/bootstrap",
        %{
          "authenticated_workspace_pin_bootstrap_hash" =>
            created.share.authenticated_workspace_pin_bootstrap_hash
        }
      )

    assert %{
             "folder" => %{"id" => nested_folder_id},
             "entries" => nested_entries
           } = json_response(nested_conn, 200)

    assert nested_folder_id == child_folder.id
    assert Enum.any?(nested_entries, &(&1["id"] == nested_document.id))
    refute Enum.any?(nested_entries, &(&1["id"] == child_document.id))
  end

  test "POST /api/mounts can save a nested folder as its own mount root", %{
    conn: conn,
    owner_id: owner_id,
    mount_user_id: mount_user_id,
    folder: folder,
    mount_workspace: mount_workspace,
    mount_user_device: mount_user_device
  } do
    child_folder = create_document(folder.workspace_id, owner_id, "folder", folder.id)
    sibling_document = create_document(folder.workspace_id, owner_id, "document", folder.id)
    nested_document = create_document(folder.workspace_id, owner_id, "document", child_folder.id)

    {created, _auth_key} =
      create_folder_share(folder, owner_id, [child_folder, sibling_document, nested_document])

    child_folder_token = Repo.get_by!(SharedFolderToken, document_id: child_folder.id).token

    create_conn =
      conn
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> post("/api/mounts", %{
        "workspace_id" => mount_workspace.id,
        "share_slug" => created.share_slug,
        "target_kind" => "folder",
        "target_token" => child_folder_token,
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    assert %{
             "id" => mount_id,
             "target_kind" => "folder",
             "target" => %{"document_id" => target_document_id}
           } = json_response(create_conn, 201)

    assert target_document_id == child_folder.id

    detail_conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> post("/api/mounts/#{mount_id}/folders/#{child_folder_token}/bootstrap", %{
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    assert %{
             "mount" => %{"id" => ^mount_id},
             "folder" => %{"id" => mounted_folder_id},
             "entries" => mounted_entries
           } = json_response(detail_conn, 200)

    assert mounted_folder_id == child_folder.id
    assert Enum.any?(mounted_entries, &(&1["id"] == nested_document.id))
    refute Enum.any?(mounted_entries, &(&1["id"] == sibling_document.id))
  end

  test "POST /api/mounts/:mount_id/documents/:document_token/bootstrap returns document bootstrap for mounted folder child",
       %{
         conn: conn,
         owner_id: owner_id,
         mount_user_id: mount_user_id,
         folder: folder,
         mount_workspace: mount_workspace,
         mount_user_device: mount_user_device
       } do
    child_document = create_document(folder.workspace_id, owner_id, "document", folder.id)
    {created, _auth_key} = create_folder_share(folder, owner_id, [child_document])
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    create_conn =
      conn
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> post("/api/mounts", %{
        "workspace_id" => mount_workspace.id,
        "share_slug" => created.share_slug,
        "target_kind" => "folder",
        "target_token" => landing.root.folder_token,
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    %{"id" => mount_id} = json_response(create_conn, 201)

    child_document_token = Repo.get_by!(SharedDocumentToken, document_id: child_document.id).token

    conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> post("/api/mounts/#{mount_id}/documents/#{child_document_token}/bootstrap", %{
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    assert %{
             "mount" => %{"id" => ^mount_id, "share_id" => mount_share_id, "status" => "active"},
             "document" => %{
               "document_id" => document_id,
               "share_id" => share_id,
               "encrypted_dek" => encrypted_dek
             }
           } = json_response(conn, 200)

    assert document_id == child_document.id
    assert mount_share_id == created.share.id
    assert share_id != created.share.id
    assert is_binary(encrypted_dek)
  end

  test "POST mounted document bootstrap returns document bootstrap for mounted folder child share",
       %{
         conn: conn,
         owner_id: owner_id,
         mount_user_id: mount_user_id,
         folder: folder,
         mount_workspace: mount_workspace,
         mount_user_device: mount_user_device
       } do
    child_document = create_document(folder.workspace_id, owner_id, "document", folder.id)
    {created, _auth_key} = create_folder_share(folder, owner_id, [child_document])
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    create_conn =
      conn
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> post("/api/mounts", %{
        "workspace_id" => mount_workspace.id,
        "share_slug" => created.share_slug,
        "target_kind" => "folder",
        "target_token" => landing.root.folder_token,
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    %{"id" => mount_id} = json_response(create_conn, 201)

    child_share =
      Repo.one!(
        from s in Share,
          where: s.parent_share_id == ^created.share.id,
          where: s.document_id == ^child_document.id
      )

    child_document_token = Repo.get_by!(SharedDocumentToken, document_id: child_document.id).token

    conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> post("/api/mounts/#{mount_id}/documents/#{child_document_token}/bootstrap", %{
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    assert %{
             "mount" => %{"id" => ^mount_id, "share_id" => mount_share_id, "status" => "active"},
             "document" => %{
               "document_id" => document_id,
               "share_id" => share_id,
               "encrypted_dek" => encrypted_dek
             }
           } = json_response(conn, 200)

    assert document_id == child_document.id
    assert mount_share_id == created.share.id
    assert share_id == child_share.id
    assert is_binary(encrypted_dek)
  end

  test "PATCH /api/mounts/:mount_id updates parent and position", %{
    conn: conn,
    owner_id: owner_id,
    mount_user_id: mount_user_id,
    document: document,
    mount_workspace: mount_workspace,
    mount_user_device: mount_user_device
  } do
    destination_folder = create_document(mount_workspace.id, mount_user_id, "folder")
    {created, _auth_key} = create_document_share(document, owner_id)
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    create_conn =
      conn
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> post("/api/mounts", %{
        "workspace_id" => mount_workspace.id,
        "share_slug" => created.share_slug,
        "target_kind" => "document",
        "target_token" => landing.root.document_token,
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    %{"id" => mount_id} = json_response(create_conn, 201)

    conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> patch("/api/mounts/#{mount_id}", %{"parent_id" => destination_folder.id, "position" => 0})

    assert %{"id" => ^mount_id, "parent_id" => parent_id, "position" => 0} =
             json_response(conn, 200)

    assert parent_id == destination_folder.id
  end

  test "DELETE /api/mounts/:mount_id deletes the mount", %{
    conn: conn,
    owner_id: owner_id,
    mount_user_id: mount_user_id,
    document: document,
    mount_workspace: mount_workspace,
    mount_user_device: mount_user_device
  } do
    {created, _auth_key} = create_document_share(document, owner_id)
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    create_conn =
      conn
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> post("/api/mounts", %{
        "workspace_id" => mount_workspace.id,
        "share_slug" => created.share_slug,
        "target_kind" => "document",
        "target_token" => landing.root.document_token,
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    %{"id" => mount_id} = json_response(create_conn, 201)

    conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> delete("/api/mounts/#{mount_id}")

    assert response(conn, 204)
    refute Repo.get(RefMD.Sharing.ShareMount, mount_id)
  end

  test "password-protected mounts return document bootstrap with local trust anchor", %{
    conn: conn,
    owner_id: owner_id,
    mount_user_id: mount_user_id,
    document: document,
    mount_workspace: mount_workspace,
    mount_user_device: mount_user_device
  } do
    auth_key = :crypto.strong_rand_bytes(32)

    {created, _auth_key} =
      create_document_share(document, owner_id,
        password_protected: true,
        auth_key: auth_key
      )

    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    create_conn =
      conn
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> post("/api/mounts", %{
        "workspace_id" => mount_workspace.id,
        "share_slug" => created.share_slug,
        "target_kind" => "document",
        "target_token" => landing.root.document_token,
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    %{"id" => mount_id} = json_response(create_conn, 201)

    show_conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> post("/api/mounts/#{mount_id}/documents/#{landing.root.document_token}/bootstrap", %{
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    assert %{"error" => "not_found"} = json_response(show_conn, 404)

    challenge_conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> get("/api/mounts/#{mount_id}/challenge")

    assert %{"challenge" => challenge, "salt" => _salt} = json_response(challenge_conn, 200)

    response =
      challenge
      |> Base.url_decode64!(padding: false)
      |> then(&:crypto.mac(:hmac, :sha256, auth_key, &1))
      |> Base.url_encode64(padding: false)

    missing_anchor_conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> post("/api/mounts/#{mount_id}/challenge", %{"response" => response})

    assert %{"error" => "invalid_request_schema"} = json_response(missing_anchor_conn, 422)

    wrong_anchor_conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> post("/api/mounts/#{mount_id}/challenge", %{
        "response" => response,
        "password_challenge_hash" => "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      })

    assert %{"error" => "not_found"} = json_response(wrong_anchor_conn, 404)

    respond_conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> post("/api/mounts/#{mount_id}/challenge", %{
        "response" => response,
        "password_challenge_hash" => mount_password_challenge_hash(mount_id)
      })

    assert %{"mount_id" => ^mount_id, "bootstrap_required" => true} =
             json_response(respond_conn, 200)

    mount_session_cookie = mount_session_cookie(respond_conn)

    show_after_challenge_conn =
      build_conn()
      |> authed_conn_with_mount_session(
        mount_user_id,
        mount_user_device.device,
        mount_session_cookie
      )
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> post("/api/mounts/#{mount_id}/documents/#{landing.root.document_token}/bootstrap", %{
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    assert %{
             "document" => %{
               "document_id" => document_id,
               "password_protected" => true
             },
             "mount" => %{"id" => ^mount_id, "share_id" => mount_share_id, "status" => "active"}
           } = json_response(show_after_challenge_conn, 200)

    assert document_id == document.id
    assert mount_share_id == created.share.id

    assert Repo.get!(Share, created.share.id).view_count == 1
  end

  test "password-protected mount challenge rejects a PoP device outside the mount user", %{
    conn: conn,
    owner_id: owner_id,
    mount_user_id: mount_user_id,
    document: document,
    mount_workspace: mount_workspace,
    mount_user_device: mount_user_device
  } do
    other_user_id = create_user("other-mount-device@example.com")
    other_user_device = create_device(other_user_id)
    auth_key = :crypto.strong_rand_bytes(32)

    {created, _auth_key} =
      create_document_share(document, owner_id,
        password_protected: true,
        auth_key: auth_key
      )

    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    create_conn =
      conn
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> post("/api/mounts", %{
        "workspace_id" => mount_workspace.id,
        "share_slug" => created.share_slug,
        "target_kind" => "document",
        "target_token" => landing.root.document_token,
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    %{"id" => mount_id} = json_response(create_conn, 201)

    assert {:ok, %{challenge: challenge}} =
             Sharing.get_share_mount_challenge(mount_user_id, mount_id)

    response =
      challenge
      |> then(&:crypto.mac(:hmac, :sha256, auth_key, &1))
      |> Base.url_encode64(padding: false)

    assert {:error, :not_found} =
             Sharing.respond_share_mount_challenge(
               mount_user_id,
               mount_id,
               other_user_device.device.id,
               response,
               nil,
               mount_password_challenge_hash(mount_id)
             )
  end

  test "password-protected folder mounts reopen from local trust anchor", %{
    conn: conn,
    owner_id: owner_id,
    mount_user_id: mount_user_id,
    folder: folder,
    mount_workspace: mount_workspace,
    mount_user_device: mount_user_device
  } do
    auth_key = :crypto.strong_rand_bytes(32)
    child_folder = create_document(folder.workspace_id, owner_id, "folder", folder.id)
    child_document = create_document(folder.workspace_id, owner_id, "document", folder.id)
    nested_document = create_document(folder.workspace_id, owner_id, "document", child_folder.id)

    {created, _auth_key} =
      create_folder_share(folder, owner_id, [child_folder, child_document, nested_document],
        password_protected: true,
        auth_key: auth_key
      )

    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    create_conn =
      conn
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> post("/api/mounts", %{
        "workspace_id" => mount_workspace.id,
        "share_slug" => created.share_slug,
        "target_kind" => "folder",
        "target_token" => landing.root.folder_token,
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    %{"id" => mount_id} = json_response(create_conn, 201)

    show_conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> post("/api/mounts/#{mount_id}/folders/#{landing.root.folder_token}/bootstrap", %{
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    assert %{"error" => "not_found"} = json_response(show_conn, 404)

    root_folder_conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> post("/api/mounts/#{mount_id}/folders/#{landing.root.folder_token}/bootstrap", %{
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    assert %{"error" => "not_found"} = json_response(root_folder_conn, 404)

    challenge_conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> get("/api/mounts/#{mount_id}/challenge")

    %{"challenge" => challenge} = json_response(challenge_conn, 200)

    response =
      challenge
      |> Base.url_decode64!(padding: false)
      |> then(&:crypto.mac(:hmac, :sha256, auth_key, &1))
      |> Base.url_encode64(padding: false)

    root_respond_conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> post("/api/mounts/#{mount_id}/challenge", %{
        "response" => response,
        "password_challenge_hash" => mount_password_challenge_hash(mount_id)
      })

    assert %{"mount_id" => ^mount_id, "bootstrap_required" => true} =
             json_response(root_respond_conn, 200)

    mount_session_cookie = mount_session_cookie(root_respond_conn)

    root_after_challenge_conn =
      build_conn()
      |> authed_conn_with_mount_session(
        mount_user_id,
        mount_user_device.device,
        mount_session_cookie
      )
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> post("/api/mounts/#{mount_id}/folders/#{landing.root.folder_token}/bootstrap", %{
        "authenticated_workspace_pin_bootstrap_hash" =>
          created.share.authenticated_workspace_pin_bootstrap_hash
      })

    assert %{
             "folder" => %{"id" => root_folder_id},
             "entries" => challenge_root_entries,
             "mount" => %{"id" => ^mount_id}
           } =
             json_response(root_after_challenge_conn, 200)

    assert root_folder_id == folder.id
    assert Enum.any?(challenge_root_entries, &(&1["id"] == child_folder.id))
    assert Enum.any?(challenge_root_entries, &(&1["id"] == child_document.id))
    refute Enum.any?(challenge_root_entries, &(&1["id"] == nested_document.id))

    child_folder_entry = Enum.find(challenge_root_entries, &(&1["id"] == child_folder.id))
    assert is_binary(child_folder_entry["folder_token"])

    nested_conn =
      build_conn()
      |> authed_conn_with_mount_session(
        mount_user_id,
        mount_user_device.device,
        mount_session_cookie
      )
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> post(
        "/api/mounts/#{mount_id}/folders/#{child_folder_entry["folder_token"]}/bootstrap",
        %{
          "authenticated_workspace_pin_bootstrap_hash" =>
            created.share.authenticated_workspace_pin_bootstrap_hash
        }
      )

    assert %{
             "folder" => %{"id" => nested_folder_id},
             "entries" => nested_entries
           } = json_response(nested_conn, 200)

    assert nested_folder_id == child_folder.id
    assert Enum.any?(nested_entries, &(&1["id"] == nested_document.id))
    refute Enum.any?(nested_entries, &(&1["id"] == child_document.id))

    challenge_conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> get("/api/mounts/#{mount_id}/challenge")

    %{"challenge" => challenge} = json_response(challenge_conn, 200)

    response =
      challenge
      |> Base.url_decode64!(padding: false)
      |> then(&:crypto.mac(:hmac, :sha256, auth_key, &1))
      |> Base.url_encode64(padding: false)

    respond_conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> post("/api/mounts/#{mount_id}/challenge", %{
        "response" => response,
        "password_challenge_hash" => mount_password_challenge_hash(mount_id)
      })

    assert %{"mount_id" => ^mount_id, "bootstrap_required" => true} =
             json_response(respond_conn, 200)
  end
end
