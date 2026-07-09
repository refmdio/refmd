defmodule RefMDWeb.DocumentShareControllerTest do
  use RefMDWeb.ConnCase, async: true
  import Phoenix.ConnTest, except: [delete: 3, get: 2, patch: 3, post: 3]

  import Ecto.Query

  alias RefMD.Auth
  alias RefMD.Documents
  alias RefMD.Repo
  alias RefMD.Sharing
  alias RefMD.Sharing.{Share, ShareKey}
  alias RefMD.Users.User
  alias RefMD.Workspaces
  alias RefMD.Workspaces.WorkspaceMember

  defp workspace_pin_bootstrap_hash, do: Process.get(:workspace_pin_bootstrap_hash)

  defp create_user(email, opts \\ []) do
    user_id = Ecto.UUID.generate()

    Repo.insert!(%User{
      id: user_id,
      email: email,
      name: email,
      account_type: Keyword.get(opts, :account_type, "registered")
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
    |> put_req_header(
      "cookie",
      "__Host-refmd-session=#{Base.url_encode64(token, padding: false)}"
    )
    |> put_private(:test_session, session)
  end

  defp with_rrp_headers(conn, user_id, device, signing_private_key) do
    put_private(conn, :test_rrp_args, {user_id, device, signing_private_key})
  end

  defp with_rrp_headers(conn, user_id, device, signing_private_key, method, path, body) do
    put_test_rrp_headers(conn, user_id, device, signing_private_key, method, path, body)
  end

  defp recycle_owner_rrp_conn(conn, owner_id, owner_device) do
    conn
    |> recycle()
    |> authed_conn(owner_id, owner_device.device)
    |> with_rrp_headers(owner_id, owner_device.device, owner_device.signing_private_key)
  end

  defp post(conn, path, body) do
    conn
    |> maybe_put_deferred_rrp("POST", path, body)
    |> Phoenix.ConnTest.dispatch(@endpoint, :post, path, test_json_body(body))
  end

  defp patch(conn, path, body) do
    conn
    |> maybe_put_deferred_rrp("PATCH", path, body)
    |> Phoenix.ConnTest.dispatch(@endpoint, :patch, path, test_json_body(body))
  end

  defp delete(conn, path, body) do
    conn
    |> maybe_put_deferred_rrp("DELETE", path, body)
    |> Phoenix.ConnTest.dispatch(@endpoint, :delete, path, test_json_body(body))
  end

  defp get(conn, path) do
    conn
    |> maybe_put_deferred_rrp("GET", path, "")
    |> Phoenix.ConnTest.dispatch(@endpoint, :get, path, "")
  end

  defp maybe_put_deferred_rrp(conn, method, path, body) do
    case conn.private[:test_rrp_args] do
      {user_id, device, signing_private_key} ->
        with_rrp_headers(conn, user_id, device, signing_private_key, method, path, body)

      _ ->
        conn
    end
  end

  defp create_share(document, owner_id, opts \\ []) do
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    attrs = %{
      "id" => Ecto.UUID.generate(),
      "scope" => "document",
      "share_slug" => share_slug,
      "token_prefix" => String.slice(share_slug, 0, 4),
      "permission" => Keyword.get(opts, :permission, "view"),
      "password_protected" => false,
      "authorization_public_key_material" =>
        share_capability_public_key_material_for_slug(open_admission_key(), share_slug),
      "share_capability_secret_commitment" => open_share_capability_secret_commitment(),
      "authenticated_workspace_pin_bootstrap_hash" => workspace_pin_bootstrap_hash(),
      "encrypted_dek" => :crypto.strong_rand_bytes(48),
      "nonce" => :crypto.strong_rand_bytes(24),
      "expires_event_sequence" =>
        Keyword.get(opts, :expires_event_sequence, 9_007_199_254_740_991),
      "max_views" => Keyword.get(opts, :max_views, 9_007_199_254_740_991)
    }

    Sharing.create_share(
      document,
      owner_id,
      with_test_share_security_artifacts(document, owner_id, attrs)
    )
  end

  defp sign_create_share_payload(document, owner_id, attrs) do
    document
    |> with_test_share_security_artifacts(owner_id, attrs)
    |> Map.drop(["actor_device_id"])
  end

  defp sign_share_settings_payload(share_id, attrs) do
    share = Repo.get!(Share, share_id)
    internal_attrs = share_settings_cache_attrs(attrs)

    share
    |> with_test_share_management_append("share_metadata_updated", internal_attrs)
    |> Map.drop(["max_views", "expires_event_sequence"])
    |> Map.merge(attrs)
  end

  defp share_settings_cache_attrs(attrs), do: attrs

  defp sign_share_delete_payload(share_id) do
    share = Repo.get!(Share, share_id)
    with_test_share_management_append(share, "share_revoked")
  end

  defp sign_share_exclusion_payload(share_id, attrs) do
    share = Repo.get!(Share, share_id)
    with_test_share_management_append(share, "share_exclusion_changed", attrs)
  end

  defp sign_share_key_update_payload(share_id, attrs) do
    share = Repo.get!(Share, share_id)
    with_test_share_scope_key_directory_append(share, attrs)
  end

  defp create_folder_share_response(conn, owner_id, owner_device, folder, share_keys) do
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    attrs =
      sign_create_share_payload(folder, owner_id, %{
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
        "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(48), padding: false),
        "nonce" => Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false),
        "share_keys" => share_keys
      })

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post("/api/documents/#{folder.id}/shares", attrs)

    {conn, json_response(conn, 201), share_slug}
  end

  defp encoded_folder_share_key(document) do
    %{
      "share_id" => Ecto.UUID.generate(),
      "document_id" => document.id,
      "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(48), padding: false),
      "nonce" => Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)
    }
  end

  setup %{conn: conn} do
    owner_id = create_user("owner-document-share@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Document Share Workspace")
    document = create_document(workspace.id, owner_id)
    owner_device = create_device(owner_id)
    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    identity_private = hybrid_signing_private_key_material("identity", owner_id)
    {identity_x25519_public, _} = :crypto.generate_key(:ecdh, :x25519)

    insert_test_workspace_key_directory!(
      workspace.id,
      owner_id,
      role.id,
      identity_private,
      hybrid_encryption_public_key_material("identity", owner_id, identity_x25519_public).public,
      owner_device.signing_private_key,
      owner_device.device.hybrid_encryption_public_key_material
    )

    Process.put(:workspace_pin_bootstrap_hash, test_workspace_pin_bootstrap_hash!(workspace.id))

    %{
      conn:
        conn
        |> authed_conn(owner_id, owner_device.device)
        |> with_rrp_headers(owner_id, owner_device.device, owner_device.signing_private_key),
      owner_id: owner_id,
      document: document,
      owner_device: owner_device
    }
  end

  test "creates a password-protected share", %{
    conn: conn,
    owner_id: owner_id,
    document: document,
    owner_device: owner_device
  } do
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
    auth_key = :crypto.strong_rand_bytes(32)

    attrs =
      sign_create_share_payload(document, owner_id, %{
        "id" => Ecto.UUID.generate(),
        "scope" => "document",
        "share_slug" => share_slug,
        "token_prefix" => String.slice(share_slug, 0, 4),
        "permission" => "view",
        "password_protected" => true,
        "authorization_public_key_material" =>
          share_capability_public_key_material_for_slug(auth_key, share_slug),
        "share_capability_secret_commitment" => open_share_capability_secret_commitment(),
        "authenticated_workspace_pin_bootstrap_hash" => workspace_pin_bootstrap_hash(),
        "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(48), padding: false),
        "nonce" => Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false),
        "salt" => Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false),
        "kdf_params" => %{
          "algorithm" => "argon2id",
          "memory" => 65_536,
          "iterations" => 3,
          "parallelism" => 4,
          "hash_length" => 32
        },
        "auth_key" => Base.url_encode64(auth_key, padding: false)
      })

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post("/api/documents/#{document.id}/shares", attrs)

    assert %{
             "id" => share_id,
             "share_slug" => ^share_slug
           } = json_response(conn, 201)

    assert Ecto.UUID.cast(share_id) == {:ok, share_id}
  end

  test "rejects share creation with max_views zero", %{
    conn: conn,
    owner_id: owner_id,
    document: document,
    owner_device: owner_device
  } do
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    attrs =
      sign_create_share_payload(document, owner_id, %{
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
        "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(48), padding: false),
        "nonce" => Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false),
        "max_views" => 1
      })
      |> Map.put("max_views", 0)

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post("/api/documents/#{document.id}/shares", attrs)

    assert %{"error" => "invalid_request_schema"} = json_response(conn, 422)
    assert {:error, :not_found} = Sharing.get_share_landing(share_slug)
  end

  test "rejects guest users from share management APIs", %{
    conn: conn,
    document: document,
    owner_id: owner_id
  } do
    guest_id = create_user("guest-document-share@example.com", account_type: "guest")
    guest_device = create_device(guest_id)

    guest_role =
      Repo.one!(
        from(r in RefMD.Workspaces.WorkspaceRole,
          where: r.workspace_id == ^document.workspace_id and r.base_role == "guest"
        )
      )

    Repo.insert!(%WorkspaceMember{
      workspace_id: document.workspace_id,
      user_id: guest_id,
      role_id: guest_role.id,
      joined_at: DateTime.utc_now()
    })

    list_conn =
      conn
      |> authed_conn(guest_id, guest_device.device)
      |> with_rrp_headers(guest_id, guest_device.device, guest_device.signing_private_key)
      |> get("/api/documents/#{document.id}/shares")

    assert json_response(list_conn, 403) == %{"error" => "forbidden"}

    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    create_attrs =
      sign_create_share_payload(document, owner_id, %{
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
        "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(48), padding: false),
        "nonce" => Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)
      })

    create_conn =
      build_conn()
      |> authed_conn(guest_id, guest_device.device)
      |> with_rrp_headers(guest_id, guest_device.device, guest_device.signing_private_key)
      |> post("/api/documents/#{document.id}/shares", create_attrs)

    assert json_response(create_conn, 403) == %{"error" => "forbidden"}
  end

  test "creates a folder share with descendant keys", %{
    conn: conn,
    owner_id: owner_id,
    document: document,
    owner_device: owner_device
  } do
    folder = create_folder(document.workspace_id, owner_id)
    shared_document = create_document(document.workspace_id, owner_id, folder.id)
    child_folder = create_folder(document.workspace_id, owner_id, folder.id)
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    attrs =
      sign_create_share_payload(folder, owner_id, %{
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
        "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(48), padding: false),
        "nonce" => Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false),
        "share_keys" => [
          %{
            "share_id" => Ecto.UUID.generate(),
            "document_id" => shared_document.id,
            "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(48), padding: false),
            "nonce" => Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)
          },
          %{
            "share_id" => Ecto.UUID.generate(),
            "document_id" => child_folder.id,
            "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(48), padding: false),
            "nonce" => Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)
          }
        ]
      })

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post("/api/documents/#{folder.id}/shares", attrs)

    assert %{"id" => share_id, "share_slug" => ^share_slug} = json_response(conn, 201)

    {:ok, landing} = Sharing.get_share_landing(share_slug)
    assert landing.share.id == share_id
    assert landing.share.scope == "folder"
    assert landing.root.kind == "folder"

    {:ok, bootstrapped} =
      bootstrap_share_participant(%{share_slug: share_slug, share: landing.share}, "Guest User")

    session_token = Base.url_encode64(bootstrapped.session_token, padding: false)

    assert {:ok, folder_bootstrap} =
             Sharing.get_folder_bootstrap(
               landing.root.folder_token,
               session_token,
               workspace_pin_bootstrap_hash()
             )

    shared_entry = Enum.find(folder_bootstrap.entries, &(&1.id == shared_document.id))
    assert is_binary(shared_entry.share_id)
    refute shared_entry.share_id == share_id
    assert is_binary(shared_entry.document_token)
    assert is_binary(shared_entry.encrypted_dek)
    assert byte_size(shared_entry.nonce) == 24

    child_folder_entry = Enum.find(folder_bootstrap.entries, &(&1.id == child_folder.id))
    assert is_binary(child_folder_entry.share_id)
    refute child_folder_entry.share_id == share_id
    assert is_binary(child_folder_entry.folder_token)
    assert is_binary(child_folder_entry.encrypted_dek)
    assert byte_size(child_folder_entry.nonce) == 24
  end

  test "rejects folder shares when descendant keys are incomplete", %{
    conn: conn,
    owner_id: owner_id,
    document: document,
    owner_device: owner_device
  } do
    folder = create_folder(document.workspace_id, owner_id)
    shared_document = create_document(document.workspace_id, owner_id, folder.id)
    _omitted_document = create_document(document.workspace_id, owner_id, folder.id)
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    attrs =
      sign_create_share_payload(folder, owner_id, %{
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
        "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(48), padding: false),
        "nonce" => Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false),
        "share_keys" => [
          %{
            "share_id" => Ecto.UUID.generate(),
            "document_id" => shared_document.id,
            "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(48), padding: false),
            "nonce" => Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)
          }
        ]
      })

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post("/api/documents/#{folder.id}/shares", attrs)

    assert json_response(conn, 422) == %{"error" => "invalid_value", "field" => "share_keys"}
  end

  test "rejects folder shares when share_keys are omitted", %{
    conn: conn,
    owner_id: owner_id,
    document: document,
    owner_device: owner_device
  } do
    folder = create_folder(document.workspace_id, owner_id)
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    attrs =
      sign_create_share_payload(folder, owner_id, %{
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
        "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(48), padding: false),
        "nonce" => Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)
      })
      |> Map.delete("share_keys")

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post("/api/documents/#{folder.id}/shares", attrs)

    assert %{"error" => "invalid_request_schema"} = json_response(conn, 422)
  end

  test "creates an empty folder share when share_keys is empty", %{
    conn: conn,
    owner_id: owner_id,
    document: document,
    owner_device: owner_device
  } do
    folder = create_folder(document.workspace_id, owner_id)
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    attrs =
      sign_create_share_payload(folder, owner_id, %{
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
        "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(48), padding: false),
        "nonce" => Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false),
        "share_keys" => []
      })

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post("/api/documents/#{folder.id}/shares", attrs)

    assert %{"id" => share_id, "share_slug" => ^share_slug} = json_response(conn, 201)

    {:ok, landing} = Sharing.get_share_landing(share_slug)
    assert landing.share.id == share_id

    {:ok, bootstrapped} =
      bootstrap_share_participant(%{share_slug: share_slug, share: landing.share}, "Guest User")

    session_token = Base.url_encode64(bootstrapped.session_token, padding: false)

    assert {:ok, folder_bootstrap} =
             Sharing.get_folder_bootstrap(
               landing.root.folder_token,
               session_token,
               workspace_pin_bootstrap_hash()
             )

    assert folder_bootstrap.entries == []
  end

  test "updates folder share exclusions", %{
    conn: conn,
    owner_id: owner_id,
    document: document,
    owner_device: owner_device
  } do
    folder = create_folder(document.workspace_id, owner_id)
    visible_document = create_document(document.workspace_id, owner_id, folder.id)
    target_document = create_document(document.workspace_id, owner_id, folder.id)
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    attrs =
      sign_create_share_payload(folder, owner_id, %{
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
        "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(48), padding: false),
        "nonce" => Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false),
        "share_keys" => [
          encoded_folder_share_key(visible_document),
          encoded_folder_share_key(target_document)
        ]
      })

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post("/api/documents/#{folder.id}/shares", attrs)

    assert %{
             "id" => share_id
           } = json_response(conn, 201)

    conn =
      conn
      |> recycle_owner_rrp_conn(owner_id, owner_device)
      |> patch(
        "/api/documents/#{folder.id}/shares/#{share_id}/exclusions",
        sign_share_exclusion_payload(share_id, %{"add" => [target_document.id]})
      )

    assert json_response(conn, 200) == %{
             "share_id" => share_id,
             "exclusions" => [target_document.id]
           }

    {:ok, landing} = Sharing.get_share_landing(share_slug)

    {:ok, bootstrapped} =
      bootstrap_share_participant(%{share_slug: share_slug, share: landing.share}, "Guest User")

    session_token = Base.url_encode64(bootstrapped.session_token, padding: false)

    assert {:ok, folder_bootstrap} =
             Sharing.get_folder_bootstrap(
               landing.root.folder_token,
               session_token,
               workspace_pin_bootstrap_hash()
             )

    entry_ids = Enum.map(folder_bootstrap.entries, & &1.id)

    assert visible_document.id in entry_ids
    refute target_document.id in entry_ids
  end

  test "adds folder share keys", %{
    conn: conn,
    owner_id: owner_id,
    document: document,
    owner_device: owner_device
  } do
    folder = create_folder(document.workspace_id, owner_id)
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    attrs =
      sign_create_share_payload(folder, owner_id, %{
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
        "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(48), padding: false),
        "nonce" => Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false),
        "share_keys" => []
      })

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post("/api/documents/#{folder.id}/shares", attrs)

    assert %{
             "id" => share_id
           } = json_response(conn, 201)

    new_document = create_document(document.workspace_id, owner_id, folder.id)

    conn =
      conn
      |> recycle_owner_rrp_conn(owner_id, owner_device)
      |> patch(
        "/api/documents/#{folder.id}/shares/#{share_id}/keys",
        sign_share_key_update_payload(share_id, %{
          "add_keys" => [encoded_folder_share_key(new_document)]
        })
      )

    assert json_response(conn, 200) == %{
             "share_id" => share_id,
             "added" => [new_document.id],
             "replaced" => []
           }

    {:ok, landing} = Sharing.get_share_landing(share_slug)

    {:ok, bootstrapped} =
      bootstrap_share_participant(%{share_slug: share_slug, share: landing.share}, "Guest User")

    session_token = Base.url_encode64(bootstrapped.session_token, padding: false)

    assert {:ok, folder_bootstrap} =
             Sharing.get_folder_bootstrap(
               landing.root.folder_token,
               session_token,
               workspace_pin_bootstrap_hash()
             )

    entry = Enum.find(folder_bootstrap.entries, &(&1.id == new_document.id))

    assert is_binary(entry.document_token)
    assert is_binary(entry.encrypted_dek)
    assert byte_size(entry.nonce) == 24
  end

  test "replaces folder share keys", %{
    conn: conn,
    owner_id: owner_id,
    document: document,
    owner_device: owner_device
  } do
    folder = create_folder(document.workspace_id, owner_id)
    shared_document = create_document(document.workspace_id, owner_id, folder.id)
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    attrs =
      sign_create_share_payload(folder, owner_id, %{
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
        "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(48), padding: false),
        "nonce" => Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false),
        "share_keys" => [encoded_folder_share_key(shared_document)]
      })

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post("/api/documents/#{folder.id}/shares", attrs)

    assert %{
             "id" => share_id
           } = json_response(conn, 201)

    child_share = Repo.get_by!(Share, parent_share_id: share_id, document_id: shared_document.id)

    conn =
      conn
      |> recycle_owner_rrp_conn(owner_id, owner_device)
      |> patch(
        "/api/documents/#{folder.id}/shares/#{share_id}/keys",
        sign_share_key_update_payload(share_id, %{
          "replace_keys" => [
            %{
              "share_id" => child_share.id,
              "document_id" => shared_document.id,
              "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(48), padding: false),
              "nonce" => Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)
            }
          ]
        })
      )

    assert json_response(conn, 200) == %{
             "share_id" => share_id,
             "added" => [],
             "replaced" => [shared_document.id]
           }

    assert %ShareKey{nonce: nonce} = Repo.get!(ShareKey, child_share.id)
    assert byte_size(nonce) == 24
  end

  test "rejects folder share key updates for an unknown share", %{
    conn: conn,
    owner_id: owner_id,
    document: document,
    owner_device: owner_device
  } do
    folder = create_folder(document.workspace_id, owner_id)

    {conn, %{"id" => existing_share_id}, _share_slug} =
      create_folder_share_response(conn, owner_id, owner_device, folder, [])

    new_document = create_document(document.workspace_id, owner_id, folder.id)

    unknown_share_id = Ecto.UUID.generate()

    conn =
      conn
      |> recycle_owner_rrp_conn(owner_id, owner_device)
      |> patch(
        "/api/documents/#{folder.id}/shares/#{unknown_share_id}/keys",
        sign_share_key_update_payload(existing_share_id, %{
          "add_keys" => [encoded_folder_share_key(new_document)]
        })
      )

    assert json_response(conn, 404) == %{"error" => "not_found"}
  end

  test "rejects folder share key updates with invalid encoded key material", %{
    conn: conn,
    owner_id: owner_id,
    document: document,
    owner_device: owner_device
  } do
    folder = create_folder(document.workspace_id, owner_id)

    {conn, %{"id" => share_id}, _share_slug} =
      create_folder_share_response(conn, owner_id, owner_device, folder, [])

    new_document = create_document(document.workspace_id, owner_id, folder.id)

    conn =
      conn
      |> recycle_owner_rrp_conn(owner_id, owner_device)
      |> patch("/api/documents/#{folder.id}/shares/#{share_id}/keys", %{
        "add_keys" => [
          %{
            "share_id" => Ecto.UUID.generate(),
            "document_id" => new_document.id,
            "encrypted_dek" => "not-base64url",
            "nonce" => Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)
          }
        ]
      })

    assert json_response(conn, 400) == %{
             "error" => "invalid_format",
             "field" => "add_keys.encrypted_dek"
           }
  end

  test "rejects folder share key updates with null key arrays", %{
    conn: conn,
    owner_id: owner_id,
    document: document,
    owner_device: owner_device
  } do
    folder = create_folder(document.workspace_id, owner_id)

    {conn, %{"id" => share_id}, _share_slug} =
      create_folder_share_response(conn, owner_id, owner_device, folder, [])

    conn =
      conn
      |> recycle_owner_rrp_conn(owner_id, owner_device)
      |> patch("/api/documents/#{folder.id}/shares/#{share_id}/keys", %{
        "add_keys" => nil
      })

    assert %{"error" => "invalid_strict_json"} = json_response(conn, 422)
  end

  test "rejects folder share key updates for invalid scope and targets", %{
    conn: conn,
    owner_id: owner_id,
    document: document,
    owner_device: owner_device
  } do
    {:ok, document_share} = create_share(document, owner_id)

    conn =
      conn
      |> patch(
        "/api/documents/#{document.id}/shares/#{document_share.share.id}/keys",
        sign_share_key_update_payload(document_share.share.id, %{
          "add_keys" => [encoded_folder_share_key(document)]
        })
      )

    assert json_response(conn, 422) == %{"error" => "invalid_value", "field" => "scope"}

    folder = create_folder(document.workspace_id, owner_id)
    duplicate_document = create_document(document.workspace_id, owner_id, folder.id)

    {conn, %{"id" => share_id}, _share_slug} =
      create_folder_share_response(
        recycle(conn),
        owner_id,
        owner_device,
        folder,
        [encoded_folder_share_key(duplicate_document)]
      )

    conn =
      conn
      |> recycle_owner_rrp_conn(owner_id, owner_device)
      |> patch(
        "/api/documents/#{folder.id}/shares/#{share_id}/keys",
        sign_share_key_update_payload(share_id, %{
          "add_keys" => [encoded_folder_share_key(duplicate_document)]
        })
      )

    assert json_response(conn, 422) == %{"error" => "invalid_value", "field" => "add_keys"}

    excluded_document = create_document(document.workspace_id, owner_id, folder.id)

    assert {:ok, %{exclusions: [excluded_document_id]}} =
             Sharing.update_share_exclusions(
               folder.id,
               share_id,
               sign_share_exclusion_payload(share_id, %{"add" => [excluded_document.id]})
             )

    assert excluded_document_id == excluded_document.id

    conn =
      conn
      |> recycle_owner_rrp_conn(owner_id, owner_device)
      |> patch(
        "/api/documents/#{folder.id}/shares/#{share_id}/keys",
        sign_share_key_update_payload(share_id, %{
          "add_keys" => [encoded_folder_share_key(excluded_document)]
        })
      )

    assert json_response(conn, 422) == %{"error" => "invalid_value", "field" => "add_keys"}
  end

  test "rejects folder share key replacements with mismatched child share", %{
    conn: conn,
    owner_id: owner_id,
    document: document,
    owner_device: owner_device
  } do
    folder = create_folder(document.workspace_id, owner_id)
    shared_document = create_document(document.workspace_id, owner_id, folder.id)

    {conn, %{"id" => share_id}, _share_slug} =
      create_folder_share_response(
        conn,
        owner_id,
        owner_device,
        folder,
        [encoded_folder_share_key(shared_document)]
      )

    conn =
      conn
      |> recycle_owner_rrp_conn(owner_id, owner_device)
      |> patch(
        "/api/documents/#{folder.id}/shares/#{share_id}/keys",
        sign_share_key_update_payload(share_id, %{
          "replace_keys" => [
            %{
              "share_id" => Ecto.UUID.generate(),
              "document_id" => shared_document.id,
              "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(48), padding: false),
              "nonce" => Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)
            }
          ]
        })
      )

    assert json_response(conn, 422) == %{
             "error" => "invalid_value",
             "field" => "replace_keys"
           }
  end

  test "updates share settings", %{
    conn: conn,
    owner_id: owner_id,
    document: document
  } do
    {:ok, created} = create_share(document, owner_id)

    expires_event_sequence = 1_000_000

    conn =
      conn
      |> patch(
        "/api/documents/#{document.id}/shares/#{created.share.id}",
        sign_share_settings_payload(created.share.id, %{
          "expires_event_sequence" => expires_event_sequence,
          "max_views" => 25
        })
      )

    assert %{
             "id" => share_id,
             "expires_event_sequence" => updated_expires_event_sequence,
             "max_views" => 25,
             "view_count" => 0
           } = json_response(conn, 200)

    assert share_id == created.share.id

    assert updated_expires_event_sequence == expires_event_sequence

    shares = Sharing.list_document_shares(document, owner_id, %{base_role: "owner"})
    assert Enum.any?(shares, &(&1.id == created.share.id and &1.max_views == 25))
  end

  test "updates max_views settings on edit shares", %{
    conn: conn,
    owner_id: owner_id,
    document: document
  } do
    {:ok, created} = create_share(document, owner_id, permission: "edit")

    conn =
      conn
      |> patch(
        "/api/documents/#{document.id}/shares/#{created.share.id}",
        sign_share_settings_payload(created.share.id, %{"max_views" => 10})
      )

    assert %{"id" => share_id, "max_views" => 10} = json_response(conn, 200)
    assert share_id == created.share.id
  end

  test "share management token routes use generic not found for missing documents", %{
    conn: conn,
    owner_id: owner_id,
    document: document
  } do
    {:ok, created} = create_share(document, owner_id)

    missing_document_id = Ecto.UUID.generate()

    conn =
      conn
      |> patch(
        "/api/documents/#{missing_document_id}/shares/#{created.share.id}",
        sign_share_settings_payload(created.share.id, %{"max_views" => 10})
      )

    assert json_response(conn, 404) == %{"error" => "not_found"}
  end

  test "updating a share to expired revokes existing participant sessions", %{
    conn: conn,
    owner_id: owner_id,
    document: document
  } do
    {:ok, created} = create_share(document, owner_id)

    participant = share_participant_attrs("Guest User")

    {:ok, bootstrapped} = bootstrap_share_participant(created, participant)
    session_token = Base.url_encode64(bootstrapped.session_token, padding: false)
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    assert {:ok, _canonical} =
             Sharing.get_document_bootstrap(
               landing.root.document_token,
               session_token,
               workspace_pin_bootstrap_hash()
             )

    Phoenix.PubSub.subscribe(
      RefMD.PubSub,
      "share_device_revocation:#{bootstrapped.participant.device_id}"
    )

    Phoenix.PubSub.subscribe(
      RefMD.PubSub,
      "share_socket:#{bootstrapped.participant.principal_id}"
    )

    expires_event_sequence = 1

    conn =
      conn
      |> patch(
        "/api/documents/#{document.id}/shares/#{created.share.id}",
        sign_share_settings_payload(created.share.id, %{
          "expires_event_sequence" => expires_event_sequence
        })
      )

    assert %{
             "id" => share_id,
             "expires_event_sequence" => updated_expires_event_sequence,
             "max_views" => 9_007_199_254_740_991,
             "view_count" => 1
           } = json_response(conn, 200)

    assert share_id == created.share.id

    assert updated_expires_event_sequence == expires_event_sequence

    assert {:error, :not_found} =
             Sharing.get_document_bootstrap(
               landing.root.document_token,
               session_token,
               workspace_pin_bootstrap_hash()
             )
  end

  test "updating max_views below the current view_count keeps existing participant sessions",
       %{
         conn: conn,
         owner_id: owner_id,
         document: document
       } do
    {:ok, created} = create_share(document, owner_id)

    participant = share_participant_attrs("Guest User")

    {:ok, bootstrapped} = bootstrap_share_participant(created, participant)
    session_token = Base.url_encode64(bootstrapped.session_token, padding: false)
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    assert {:ok, _canonical} =
             Sharing.get_document_bootstrap(
               landing.root.document_token,
               session_token,
               workspace_pin_bootstrap_hash()
             )

    Phoenix.PubSub.subscribe(RefMD.PubSub, "share:#{created.share.id}:revoked")

    Phoenix.PubSub.subscribe(
      RefMD.PubSub,
      "share_device_revocation:#{bootstrapped.participant.device_id}"
    )

    Phoenix.PubSub.subscribe(
      RefMD.PubSub,
      "share_socket:#{bootstrapped.participant.principal_id}"
    )

    conn =
      conn
      |> patch(
        "/api/documents/#{document.id}/shares/#{created.share.id}",
        sign_share_settings_payload(created.share.id, %{"max_views" => 1})
      )

    assert json_response(conn, 200) == %{
             "id" => created.share.id,
             "expires_event_sequence" => 9_007_199_254_740_991,
             "max_views" => 1,
             "view_count" => 1
           }

    assert {:ok, canonical} =
             Sharing.get_document_bootstrap(
               landing.root.document_token,
               session_token,
               workspace_pin_bootstrap_hash()
             )

    assert canonical.document_id == document.id

    refute_receive {:share_revoked, _share_id}, 50
    refute_receive {:device_revoked, _device_id}, 50
    refute_receive %Phoenix.Socket.Broadcast{event: "disconnect"}, 50

    second_participant = share_participant_attrs("Second Guest")
    assert {:error, :not_found} = bootstrap_share_participant(created, second_participant)
  end

  test "deletes a share", %{
    conn: conn,
    owner_id: owner_id,
    document: document
  } do
    {:ok, created} = create_share(document, owner_id)

    participant = share_participant_attrs("Guest User")

    {:ok, bootstrapped} = bootstrap_share_participant(created, participant)

    Phoenix.PubSub.subscribe(
      RefMD.PubSub,
      "share_device_revocation:#{bootstrapped.participant.device_id}"
    )

    Phoenix.PubSub.subscribe(
      RefMD.PubSub,
      "share_socket:#{bootstrapped.participant.principal_id}"
    )

    conn =
      conn
      |> delete(
        "/api/documents/#{document.id}/shares/#{created.share.id}",
        sign_share_delete_payload(created.share.id)
      )

    assert response(conn, 204) == ""
    assert_receive {:device_revoked, device_id}
    assert device_id == bootstrapped.participant.device_id

    assert_receive %Phoenix.Socket.Broadcast{event: "disconnect", topic: topic}
    assert topic == "share_socket:#{bootstrapped.participant.principal_id}"

    assert {:error, :not_found} = Sharing.get_share_landing(created.share_slug)
  end

  test "share settings update returns unified not_found for unknown share", %{
    conn: conn,
    owner_id: owner_id,
    document: document
  } do
    assert {:ok, created} = create_share(document, owner_id)

    conn =
      conn
      |> patch(
        "/api/documents/#{document.id}/shares/#{Ecto.UUID.generate()}",
        sign_share_settings_payload(created.share.id, %{"max_views" => 10})
      )

    assert json_response(conn, 404) == %{"error" => "not_found"}
  end

  test "share settings update returns unified not_found for a missing share", %{
    conn: conn,
    owner_id: owner_id,
    document: document
  } do
    assert {:ok, created} = create_share(document, owner_id)

    conn =
      conn
      |> patch(
        "/api/documents/#{document.id}/shares/#{Ecto.UUID.generate()}",
        sign_share_settings_payload(created.share.id, %{"max_views" => 10})
      )

    assert json_response(conn, 404) == %{"error" => "not_found"}
  end

  test "share settings update returns unified not_found for malformed share id", %{
    conn: conn,
    owner_id: owner_id,
    document: document
  } do
    assert {:ok, _created} = create_share(document, owner_id)

    conn =
      conn
      |> patch("/api/documents/#{document.id}/shares/not-a-uuid", %{
        "max_views" => 10
      })

    assert json_response(conn, 404) == %{"error" => "not_found"}
  end

  test "share settings update rejects requests without update fields", %{
    conn: conn,
    owner_id: owner_id,
    document: document
  } do
    {:ok, created} = create_share(document, owner_id)

    conn =
      conn
      |> patch("/api/documents/#{document.id}/shares/#{created.share.id}", %{})

    assert json_response(conn, 400) == %{"error" => "missing_update_fields"}
  end

  test "share settings update rejects invalid expires_event_sequence", %{
    conn: conn,
    owner_id: owner_id,
    document: document
  } do
    {:ok, created} = create_share(document, owner_id)

    conn =
      conn
      |> patch("/api/documents/#{document.id}/shares/#{created.share.id}", %{
        "expires_event_sequence" => "not-a-sequence"
      })

    assert %{"error" => "invalid_request_schema"} = json_response(conn, 422)
  end

  test "share settings update rejects invalid max_views type", %{
    conn: conn,
    owner_id: owner_id,
    document: document
  } do
    {:ok, created} = create_share(document, owner_id)

    conn =
      conn
      |> patch("/api/documents/#{document.id}/shares/#{created.share.id}", %{
        "max_views" => "ten"
      })

    assert %{"error" => "invalid_request_schema"} = json_response(conn, 422)
  end

  test "share settings update rejects max_views zero", %{
    conn: conn,
    owner_id: owner_id,
    document: document
  } do
    {:ok, created} = create_share(document, owner_id)

    conn =
      conn
      |> patch("/api/documents/#{document.id}/shares/#{created.share.id}", %{
        "max_views" => 0
      })

    assert %{"error" => "invalid_request_schema"} = json_response(conn, 422)
    assert {:ok, _landing} = Sharing.get_share_landing(created.share_slug)
  end

  test "share deletion returns unified not_found for unknown share", %{
    conn: conn,
    owner_id: owner_id,
    document: document
  } do
    assert {:ok, created} = create_share(document, owner_id)

    conn =
      conn
      |> delete(
        "/api/documents/#{document.id}/shares/#{Ecto.UUID.generate()}",
        sign_share_delete_payload(created.share.id)
      )

    assert json_response(conn, 404) == %{"error" => "not_found"}
  end

  test "share deletion returns unified not_found for a missing share", %{
    conn: conn,
    owner_id: owner_id,
    document: document
  } do
    assert {:ok, created} = create_share(document, owner_id)

    conn =
      conn
      |> delete(
        "/api/documents/#{document.id}/shares/#{Ecto.UUID.generate()}",
        sign_share_delete_payload(created.share.id)
      )

    assert json_response(conn, 404) == %{"error" => "not_found"}
  end

  test "admin share deletion requires authenticated owner on the admin route", %{
    conn: conn,
    owner_id: owner_id,
    document: document,
    owner_device: owner_device
  } do
    {:ok, created} = create_share(document, owner_id)

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> delete(
        "/api/documents/#{document.id}/shares/#{created.share.id}/admin",
        sign_share_delete_payload(created.share.id)
      )

    assert response(conn, 204) == ""
    assert {:error, :not_found} = Sharing.get_share_landing(created.share_slug)
  end
end
