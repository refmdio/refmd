defmodule RefMDWeb.DocumentShareControllerTest do
  use RefMDWeb.ConnCase, async: true

  import Ecto.Query

  alias RefMD.Auth
  alias RefMD.Documents
  alias RefMD.Repo
  alias RefMD.Sharing
  alias RefMD.Sharing.{Share, ShareKey}
  alias RefMD.Users.User
  alias RefMD.Workspaces
  alias RefMD.Workspaces.WorkspaceMember

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

  defp create_share(document, owner_id, opts \\ []) do
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    attrs = %{
      "id" => Ecto.UUID.generate(),
      "scope" => "document",
      "share_slug" => share_slug,
      "token_prefix" => String.slice(share_slug, 0, 4),
      "permission" => Keyword.get(opts, :permission, "view"),
      "password_protected" => false,
      "encrypted_dek" => :crypto.strong_rand_bytes(32),
      "nonce" => nil,
      "expires_at" => Keyword.get(opts, :expires_at),
      "access_limit" => Keyword.get(opts, :access_limit)
    }

    Sharing.create_share(document, owner_id, attrs)
  end

  defp create_folder_share_response(conn, owner_id, owner_device, folder, share_keys) do
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post("/api/documents/#{folder.id}/shares", %{
        "id" => Ecto.UUID.generate(),
        "scope" => "folder",
        "share_slug" => share_slug,
        "token_prefix" => String.slice(share_slug, 0, 4),
        "permission" => "view",
        "password_protected" => false,
        "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
        "nonce" => nil,
        "share_keys" => share_keys
      })

    {conn, json_response(conn, 201), share_slug}
  end

  defp encoded_folder_share_key(document) do
    %{
      "share_id" => Ecto.UUID.generate(),
      "document_id" => document.id,
      "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
      "nonce" => nil
    }
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
    owner_id = create_user("owner-document-share@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Document Share Workspace")
    document = create_document(workspace.id, owner_id)
    owner_device = create_device(owner_id)

    %{
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

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post("/api/documents/#{document.id}/shares", %{
        "id" => Ecto.UUID.generate(),
        "scope" => "document",
        "share_slug" => share_slug,
        "token_prefix" => String.slice(share_slug, 0, 4),
        "permission" => "view",
        "password_protected" => true,
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
        "auth_key" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
      })

    assert %{
             "id" => share_id,
             "share_slug" => ^share_slug,
             "share_manage_token" => share_manage_token
           } = json_response(conn, 201)

    assert Ecto.UUID.cast(share_id) == {:ok, share_id}
    assert is_binary(share_manage_token)
  end

  test "creates a share with access_limit zero", %{
    conn: conn,
    owner_id: owner_id,
    document: document,
    owner_device: owner_device
  } do
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post("/api/documents/#{document.id}/shares", %{
        "id" => Ecto.UUID.generate(),
        "scope" => "document",
        "share_slug" => share_slug,
        "token_prefix" => String.slice(share_slug, 0, 4),
        "permission" => "view",
        "password_protected" => false,
        "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
        "nonce" => nil,
        "access_limit" => 0
      })

    assert %{"id" => share_id} = json_response(conn, 201)
    assert {:error, :not_found} = Sharing.get_share_landing(share_slug)

    shares = Sharing.list_document_shares(document, owner_id, %{base_role: "owner"})

    assert Enum.any?(
             shares,
             &(&1.id == share_id and &1.access_limit == 0 and &1.share_slug == share_slug)
           )
  end

  test "rejects guest users from share management APIs", %{conn: conn, document: document} do
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
      |> with_pop_headers(guest_id, guest_device.device, guest_device.signing_private_key)
      |> get("/api/documents/#{document.id}/shares")

    assert json_response(list_conn, 403) == %{"error" => "forbidden"}

    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    create_conn =
      build_conn()
      |> authed_conn(guest_id, guest_device.device)
      |> with_pop_headers(guest_id, guest_device.device, guest_device.signing_private_key)
      |> post("/api/documents/#{document.id}/shares", %{
        "id" => Ecto.UUID.generate(),
        "scope" => "document",
        "share_slug" => share_slug,
        "token_prefix" => String.slice(share_slug, 0, 4),
        "permission" => "view",
        "password_protected" => false,
        "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
        "nonce" => nil
      })

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

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post("/api/documents/#{folder.id}/shares", %{
        "id" => Ecto.UUID.generate(),
        "scope" => "folder",
        "share_slug" => share_slug,
        "token_prefix" => String.slice(share_slug, 0, 4),
        "permission" => "view",
        "password_protected" => false,
        "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
        "nonce" => nil,
        "share_keys" => [
          %{
            "share_id" => Ecto.UUID.generate(),
            "document_id" => shared_document.id,
            "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
            "nonce" => nil
          },
          %{
            "share_id" => Ecto.UUID.generate(),
            "document_id" => child_folder.id,
            "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
            "nonce" => nil
          }
        ]
      })

    assert %{"id" => share_id, "share_slug" => ^share_slug} = json_response(conn, 201)

    {:ok, landing} = Sharing.get_share_landing(share_slug)
    assert landing.share.id == share_id
    assert landing.share.scope == "folder"
    assert landing.root.kind == "folder"

    {:ok, bootstrapped} =
      Sharing.bootstrap_participant(share_slug, %{
        "display_name" => "Guest User",
        "device_signing_pub_key" => valid_signing_public_key(),
        "device_encryption_pub_key" => valid_encryption_public_key()
      })

    session_token = Base.url_encode64(bootstrapped.session_token, padding: false)

    assert {:ok, folder_bootstrap} =
             Sharing.get_folder_bootstrap(landing.root.folder_token, session_token)

    shared_entry = Enum.find(folder_bootstrap.entries, &(&1.id == shared_document.id))
    assert is_binary(shared_entry.share_id)
    refute shared_entry.share_id == share_id
    assert is_binary(shared_entry.document_token)
    assert is_binary(shared_entry.encrypted_dek)
    assert is_nil(shared_entry.nonce)

    child_folder_entry = Enum.find(folder_bootstrap.entries, &(&1.id == child_folder.id))
    assert is_binary(child_folder_entry.share_id)
    refute child_folder_entry.share_id == share_id
    assert is_binary(child_folder_entry.folder_token)
    assert is_binary(child_folder_entry.encrypted_dek)
    assert is_nil(child_folder_entry.nonce)
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

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post("/api/documents/#{folder.id}/shares", %{
        "id" => Ecto.UUID.generate(),
        "scope" => "folder",
        "share_slug" => share_slug,
        "token_prefix" => String.slice(share_slug, 0, 4),
        "permission" => "view",
        "password_protected" => false,
        "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
        "nonce" => nil,
        "share_keys" => [
          %{
            "share_id" => Ecto.UUID.generate(),
            "document_id" => shared_document.id,
            "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
            "nonce" => nil
          }
        ]
      })

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

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post("/api/documents/#{folder.id}/shares", %{
        "id" => Ecto.UUID.generate(),
        "scope" => "folder",
        "share_slug" => share_slug,
        "token_prefix" => String.slice(share_slug, 0, 4),
        "permission" => "view",
        "password_protected" => false,
        "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
        "nonce" => nil
      })

    assert json_response(conn, 400) == %{"error" => "missing_field", "field" => "share_keys"}
  end

  test "creates an empty folder share when share_keys is empty", %{
    conn: conn,
    owner_id: owner_id,
    document: document,
    owner_device: owner_device
  } do
    folder = create_folder(document.workspace_id, owner_id)
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post("/api/documents/#{folder.id}/shares", %{
        "id" => Ecto.UUID.generate(),
        "scope" => "folder",
        "share_slug" => share_slug,
        "token_prefix" => String.slice(share_slug, 0, 4),
        "permission" => "view",
        "password_protected" => false,
        "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
        "nonce" => nil,
        "share_keys" => []
      })

    assert %{"id" => share_id, "share_slug" => ^share_slug} = json_response(conn, 201)

    {:ok, landing} = Sharing.get_share_landing(share_slug)
    assert landing.share.id == share_id

    {:ok, bootstrapped} =
      Sharing.bootstrap_participant(share_slug, %{
        "display_name" => "Guest User",
        "device_signing_pub_key" => valid_signing_public_key(),
        "device_encryption_pub_key" => valid_encryption_public_key()
      })

    session_token = Base.url_encode64(bootstrapped.session_token, padding: false)

    assert {:ok, folder_bootstrap} =
             Sharing.get_folder_bootstrap(landing.root.folder_token, session_token)

    assert folder_bootstrap.entries == []
  end

  test "updates folder share exclusions with share_manage_token", %{
    conn: conn,
    owner_id: owner_id,
    document: document,
    owner_device: owner_device
  } do
    folder = create_folder(document.workspace_id, owner_id)
    visible_document = create_document(document.workspace_id, owner_id, folder.id)
    target_document = create_document(document.workspace_id, owner_id, folder.id)
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post("/api/documents/#{folder.id}/shares", %{
        "id" => Ecto.UUID.generate(),
        "scope" => "folder",
        "share_slug" => share_slug,
        "token_prefix" => String.slice(share_slug, 0, 4),
        "permission" => "view",
        "password_protected" => false,
        "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
        "nonce" => nil,
        "share_keys" => [
          encoded_folder_share_key(visible_document),
          encoded_folder_share_key(target_document)
        ]
      })

    assert %{
             "id" => share_id,
             "share_manage_token" => share_manage_token
           } = json_response(conn, 201)

    conn =
      conn
      |> recycle()
      |> put_req_header("authorization", share_manage_token)
      |> patch("/api/documents/#{folder.id}/shares/#{share_id}/exclusions", %{
        "add" => [target_document.id]
      })

    assert json_response(conn, 200) == %{
             "share_id" => share_id,
             "exclusions" => [target_document.id]
           }

    {:ok, landing} = Sharing.get_share_landing(share_slug)

    {:ok, bootstrapped} =
      Sharing.bootstrap_participant(share_slug, %{
        "display_name" => "Guest User",
        "device_signing_pub_key" => valid_signing_public_key(),
        "device_encryption_pub_key" => valid_encryption_public_key()
      })

    session_token = Base.url_encode64(bootstrapped.session_token, padding: false)

    assert {:ok, folder_bootstrap} =
             Sharing.get_folder_bootstrap(landing.root.folder_token, session_token)

    entry_ids = Enum.map(folder_bootstrap.entries, & &1.id)

    assert visible_document.id in entry_ids
    refute target_document.id in entry_ids
  end

  test "adds folder share keys with share_manage_token", %{
    conn: conn,
    owner_id: owner_id,
    document: document,
    owner_device: owner_device
  } do
    folder = create_folder(document.workspace_id, owner_id)
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post("/api/documents/#{folder.id}/shares", %{
        "id" => Ecto.UUID.generate(),
        "scope" => "folder",
        "share_slug" => share_slug,
        "token_prefix" => String.slice(share_slug, 0, 4),
        "permission" => "view",
        "password_protected" => false,
        "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
        "nonce" => nil,
        "share_keys" => []
      })

    assert %{
             "id" => share_id,
             "share_manage_token" => share_manage_token
           } = json_response(conn, 201)

    new_document = create_document(document.workspace_id, owner_id, folder.id)

    conn =
      conn
      |> recycle()
      |> put_req_header("authorization", share_manage_token)
      |> patch("/api/documents/#{folder.id}/shares/#{share_id}/keys", %{
        "add_keys" => [encoded_folder_share_key(new_document)]
      })

    assert json_response(conn, 200) == %{
             "share_id" => share_id,
             "added" => [new_document.id],
             "replaced" => []
           }

    {:ok, landing} = Sharing.get_share_landing(share_slug)

    {:ok, bootstrapped} =
      Sharing.bootstrap_participant(share_slug, %{
        "display_name" => "Guest User",
        "device_signing_pub_key" => valid_signing_public_key(),
        "device_encryption_pub_key" => valid_encryption_public_key()
      })

    session_token = Base.url_encode64(bootstrapped.session_token, padding: false)

    assert {:ok, folder_bootstrap} =
             Sharing.get_folder_bootstrap(landing.root.folder_token, session_token)

    entry = Enum.find(folder_bootstrap.entries, &(&1.id == new_document.id))

    assert is_binary(entry.document_token)
    assert is_binary(entry.encrypted_dek)
    assert is_nil(entry.nonce)
  end

  test "replaces folder share keys with share_manage_token", %{
    conn: conn,
    owner_id: owner_id,
    document: document,
    owner_device: owner_device
  } do
    folder = create_folder(document.workspace_id, owner_id)
    shared_document = create_document(document.workspace_id, owner_id, folder.id)
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post("/api/documents/#{folder.id}/shares", %{
        "id" => Ecto.UUID.generate(),
        "scope" => "folder",
        "share_slug" => share_slug,
        "token_prefix" => String.slice(share_slug, 0, 4),
        "permission" => "view",
        "password_protected" => false,
        "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
        "nonce" => nil,
        "share_keys" => [encoded_folder_share_key(shared_document)]
      })

    assert %{
             "id" => share_id,
             "share_manage_token" => share_manage_token
           } = json_response(conn, 201)

    child_share = Repo.get_by!(Share, parent_share_id: share_id, document_id: shared_document.id)

    conn =
      conn
      |> recycle()
      |> put_req_header("authorization", share_manage_token)
      |> patch("/api/documents/#{folder.id}/shares/#{share_id}/keys", %{
        "replace_keys" => [
          %{
            "share_id" => child_share.id,
            "document_id" => shared_document.id,
            "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
            "nonce" => nil
          }
        ]
      })

    assert json_response(conn, 200) == %{
             "share_id" => share_id,
             "added" => [],
             "replaced" => [shared_document.id]
           }

    assert %ShareKey{nonce: nil} = Repo.get!(ShareKey, child_share.id)
  end

  test "rejects folder share key updates without a valid manage token", %{
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
      |> recycle()
      |> patch("/api/documents/#{folder.id}/shares/#{share_id}/keys", %{
        "add_keys" => [encoded_folder_share_key(new_document)]
      })

    assert json_response(conn, 404) == %{"error" => "not_found"}
  end

  test "rejects folder share key updates with invalid encoded key material", %{
    conn: conn,
    owner_id: owner_id,
    document: document,
    owner_device: owner_device
  } do
    folder = create_folder(document.workspace_id, owner_id)

    {conn, %{"id" => share_id, "share_manage_token" => share_manage_token}, _share_slug} =
      create_folder_share_response(conn, owner_id, owner_device, folder, [])

    new_document = create_document(document.workspace_id, owner_id, folder.id)

    conn =
      conn
      |> recycle()
      |> put_req_header("authorization", share_manage_token)
      |> patch("/api/documents/#{folder.id}/shares/#{share_id}/keys", %{
        "add_keys" => [
          %{
            "share_id" => Ecto.UUID.generate(),
            "document_id" => new_document.id,
            "encrypted_dek" => "not-base64url",
            "nonce" => nil
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

    {conn, %{"id" => share_id, "share_manage_token" => share_manage_token}, _share_slug} =
      create_folder_share_response(conn, owner_id, owner_device, folder, [])

    conn =
      conn
      |> recycle()
      |> put_req_header("authorization", share_manage_token)
      |> patch("/api/documents/#{folder.id}/shares/#{share_id}/keys", %{
        "add_keys" => nil
      })

    assert json_response(conn, 400) == %{
             "error" => "invalid_format",
             "field" => "add_keys"
           }
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
      |> put_req_header("authorization", document_share.share_manage_token)
      |> patch("/api/documents/#{document.id}/shares/#{document_share.share.id}/keys", %{
        "add_keys" => [encoded_folder_share_key(document)]
      })

    assert json_response(conn, 422) == %{"error" => "invalid_value", "field" => "scope"}

    folder = create_folder(document.workspace_id, owner_id)
    duplicate_document = create_document(document.workspace_id, owner_id, folder.id)

    {conn, %{"id" => share_id, "share_manage_token" => share_manage_token}, _share_slug} =
      create_folder_share_response(
        recycle(conn),
        owner_id,
        owner_device,
        folder,
        [encoded_folder_share_key(duplicate_document)]
      )

    conn =
      conn
      |> recycle()
      |> put_req_header("authorization", share_manage_token)
      |> patch("/api/documents/#{folder.id}/shares/#{share_id}/keys", %{
        "add_keys" => [encoded_folder_share_key(duplicate_document)]
      })

    assert json_response(conn, 422) == %{"error" => "invalid_value", "field" => "add_keys"}

    excluded_document = create_document(document.workspace_id, owner_id, folder.id)

    assert {:ok, %{exclusions: [excluded_document_id]}} =
             Sharing.update_share_exclusions(
               folder.id,
               share_id,
               share_manage_token,
               %{"add" => [excluded_document.id]}
             )

    assert excluded_document_id == excluded_document.id

    conn =
      conn
      |> recycle()
      |> put_req_header("authorization", share_manage_token)
      |> patch("/api/documents/#{folder.id}/shares/#{share_id}/keys", %{
        "add_keys" => [encoded_folder_share_key(excluded_document)]
      })

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

    {conn, %{"id" => share_id, "share_manage_token" => share_manage_token}, _share_slug} =
      create_folder_share_response(
        conn,
        owner_id,
        owner_device,
        folder,
        [encoded_folder_share_key(shared_document)]
      )

    conn =
      conn
      |> recycle()
      |> put_req_header("authorization", share_manage_token)
      |> patch("/api/documents/#{folder.id}/shares/#{share_id}/keys", %{
        "replace_keys" => [
          %{
            "share_id" => Ecto.UUID.generate(),
            "document_id" => shared_document.id,
            "encrypted_dek" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
            "nonce" => nil
          }
        ]
      })

    assert json_response(conn, 422) == %{
             "error" => "invalid_value",
             "field" => "replace_keys"
           }
  end

  test "updates share settings with share_manage_token", %{
    conn: conn,
    owner_id: owner_id,
    document: document
  } do
    {:ok, created} = create_share(document, owner_id)
    expires_at = DateTime.add(DateTime.utc_now(), 3_600, :second) |> DateTime.truncate(:second)

    conn =
      conn
      |> put_req_header("authorization", created.share_manage_token)
      |> patch("/api/documents/#{document.id}/shares/#{created.share.id}", %{
        "expires_at" => DateTime.to_iso8601(expires_at),
        "access_limit" => 25
      })

    assert %{
             "id" => share_id,
             "expires_at" => updated_expires_at,
             "access_limit" => 25,
             "access_count" => 0
           } = json_response(conn, 200)

    assert share_id == created.share.id

    assert {:ok, parsed_expires_at, 0} = DateTime.from_iso8601(updated_expires_at)
    assert DateTime.truncate(parsed_expires_at, :second) == expires_at

    shares = Sharing.list_document_shares(document, owner_id, %{base_role: "owner"})
    assert Enum.any?(shares, &(&1.id == created.share.id and &1.access_limit == 25))
  end

  test "updates access_limit settings on edit shares", %{
    conn: conn,
    owner_id: owner_id,
    document: document
  } do
    {:ok, created} = create_share(document, owner_id, permission: "edit")

    conn =
      conn
      |> put_req_header("authorization", created.share_manage_token)
      |> patch("/api/documents/#{document.id}/shares/#{created.share.id}", %{
        "access_limit" => 10
      })

    assert %{"id" => share_id, "access_limit" => 10} = json_response(conn, 200)
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
      |> put_req_header("authorization", created.share_manage_token)
      |> patch("/api/documents/#{missing_document_id}/shares/#{created.share.id}", %{
        "expires_at" => nil
      })

    assert json_response(conn, 404) == %{"error" => "not_found"}
  end

  test "updating a share to expired revokes existing participant sessions", %{
    conn: conn,
    owner_id: owner_id,
    document: document
  } do
    {:ok, created} = create_share(document, owner_id)

    participant = %{
      "display_name" => "Guest User",
      "device_signing_pub_key" => valid_signing_public_key(),
      "device_encryption_pub_key" => valid_encryption_public_key()
    }

    {:ok, bootstrapped} = Sharing.bootstrap_participant(created.share_slug, participant)
    session_token = Base.url_encode64(bootstrapped.session_token, padding: false)
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    Phoenix.PubSub.subscribe(
      RefMD.PubSub,
      "share_device_revocation:#{bootstrapped.participant.device_id}"
    )

    Phoenix.PubSub.subscribe(
      RefMD.PubSub,
      "share_socket:#{bootstrapped.participant.principal_id}"
    )

    expires_at = DateTime.add(DateTime.utc_now(), -1, :second) |> DateTime.truncate(:second)

    conn =
      conn
      |> put_req_header("authorization", created.share_manage_token)
      |> patch("/api/documents/#{document.id}/shares/#{created.share.id}", %{
        "expires_at" => DateTime.to_iso8601(expires_at)
      })

    assert %{
             "id" => share_id,
             "expires_at" => updated_expires_at,
             "access_limit" => nil,
             "access_count" => 1
           } = json_response(conn, 200)

    assert share_id == created.share.id

    assert {:ok, parsed_expires_at, 0} = DateTime.from_iso8601(updated_expires_at)
    assert DateTime.truncate(parsed_expires_at, :second) == expires_at

    assert_receive {:device_revoked, device_id}
    assert device_id == bootstrapped.participant.device_id

    assert_receive %Phoenix.Socket.Broadcast{event: "disconnect", topic: topic}
    assert topic == "share_socket:#{bootstrapped.participant.principal_id}"

    assert {:error, :not_found} =
             Sharing.get_document_bootstrap(landing.root.document_token, session_token)
  end

  test "updating access_limit below the current access_count revokes existing participant sessions",
       %{
         conn: conn,
         owner_id: owner_id,
         document: document
       } do
    {:ok, created} = create_share(document, owner_id)

    participant = %{
      "display_name" => "Guest User",
      "device_signing_pub_key" => valid_signing_public_key(),
      "device_encryption_pub_key" => valid_encryption_public_key()
    }

    {:ok, bootstrapped} = Sharing.bootstrap_participant(created.share_slug, participant)
    session_token = Base.url_encode64(bootstrapped.session_token, padding: false)
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

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
      |> put_req_header("authorization", created.share_manage_token)
      |> patch("/api/documents/#{document.id}/shares/#{created.share.id}", %{
        "access_limit" => 1
      })

    assert json_response(conn, 200) == %{
             "id" => created.share.id,
             "expires_at" => nil,
             "access_limit" => 1,
             "access_count" => 1
           }

    assert_receive {:device_revoked, device_id}
    assert device_id == bootstrapped.participant.device_id

    assert_receive %Phoenix.Socket.Broadcast{event: "disconnect", topic: topic}
    assert topic == "share_socket:#{bootstrapped.participant.principal_id}"

    assert {:error, :not_found} =
             Sharing.get_document_bootstrap(landing.root.document_token, session_token)
  end

  test "deletes a share with share_manage_token", %{
    conn: conn,
    owner_id: owner_id,
    document: document
  } do
    {:ok, created} = create_share(document, owner_id)

    participant = %{
      "display_name" => "Guest User",
      "device_signing_pub_key" => valid_signing_public_key(),
      "device_encryption_pub_key" => valid_encryption_public_key()
    }

    {:ok, bootstrapped} = Sharing.bootstrap_participant(created.share_slug, participant)

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
      |> put_req_header("authorization", created.share_manage_token)
      |> delete("/api/documents/#{document.id}/shares/#{created.share.id}")

    assert response(conn, 204) == ""
    assert_receive {:device_revoked, device_id}
    assert device_id == bootstrapped.participant.device_id

    assert_receive %Phoenix.Socket.Broadcast{event: "disconnect", topic: topic}
    assert topic == "share_socket:#{bootstrapped.participant.principal_id}"

    assert {:error, :not_found} = Sharing.get_share_landing(created.share_slug)
  end

  test "share settings update returns unified not_found for invalid manage token", %{
    conn: conn,
    owner_id: owner_id,
    document: document
  } do
    {:ok, created} = create_share(document, owner_id)

    conn =
      conn
      |> put_req_header(
        "authorization",
        Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
      )
      |> patch("/api/documents/#{document.id}/shares/#{created.share.id}", %{
        "access_limit" => 10
      })

    assert json_response(conn, 404) == %{"error" => "not_found"}
  end

  test "share settings update returns unified not_found for malformed authorization header", %{
    conn: conn,
    owner_id: owner_id,
    document: document
  } do
    {:ok, created} = create_share(document, owner_id)

    conn =
      conn
      |> put_req_header("authorization", "Token invalid value")
      |> patch("/api/documents/#{document.id}/shares/#{created.share.id}", %{
        "access_limit" => 10
      })

    assert json_response(conn, 404) == %{"error" => "not_found"}
  end

  test "share settings update returns unified not_found for malformed share id", %{
    conn: conn,
    owner_id: owner_id,
    document: document
  } do
    {:ok, created} = create_share(document, owner_id)

    conn =
      conn
      |> put_req_header("authorization", created.share_manage_token)
      |> patch("/api/documents/#{document.id}/shares/not-a-uuid", %{
        "access_limit" => 10
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
      |> put_req_header("authorization", created.share_manage_token)
      |> patch("/api/documents/#{document.id}/shares/#{created.share.id}", %{})

    assert json_response(conn, 400) == %{"error" => "missing_update_fields"}
  end

  test "share settings update rejects invalid expires_at", %{
    conn: conn,
    owner_id: owner_id,
    document: document
  } do
    {:ok, created} = create_share(document, owner_id)

    conn =
      conn
      |> put_req_header("authorization", created.share_manage_token)
      |> patch("/api/documents/#{document.id}/shares/#{created.share.id}", %{
        "expires_at" => "not-a-datetime"
      })

    assert json_response(conn, 400) == %{"error" => "invalid_datetime", "field" => "expires_at"}
  end

  test "share settings update rejects invalid access_limit type", %{
    conn: conn,
    owner_id: owner_id,
    document: document
  } do
    {:ok, created} = create_share(document, owner_id)

    conn =
      conn
      |> put_req_header("authorization", created.share_manage_token)
      |> patch("/api/documents/#{document.id}/shares/#{created.share.id}", %{
        "access_limit" => "ten"
      })

    assert json_response(conn, 400) == %{"error" => "invalid_integer", "field" => "access_limit"}
  end

  test "share settings update accepts access_limit zero", %{
    conn: conn,
    owner_id: owner_id,
    document: document
  } do
    {:ok, created} = create_share(document, owner_id)

    conn =
      conn
      |> put_req_header("authorization", created.share_manage_token)
      |> patch("/api/documents/#{document.id}/shares/#{created.share.id}", %{
        "access_limit" => 0
      })

    assert json_response(conn, 200) == %{
             "id" => created.share.id,
             "expires_at" => nil,
             "access_limit" => 0,
             "access_count" => 0
           }

    assert {:error, :not_found} = Sharing.get_share_landing(created.share_slug)
  end

  test "share deletion returns unified not_found for invalid manage token", %{
    conn: conn,
    owner_id: owner_id,
    document: document
  } do
    {:ok, created} = create_share(document, owner_id)

    conn =
      conn
      |> put_req_header(
        "authorization",
        Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
      )
      |> delete("/api/documents/#{document.id}/shares/#{created.share.id}")

    assert json_response(conn, 404) == %{"error" => "not_found"}
  end

  test "share deletion returns unified not_found for malformed authorization header", %{
    conn: conn,
    owner_id: owner_id,
    document: document
  } do
    {:ok, created} = create_share(document, owner_id)

    conn =
      conn
      |> put_req_header("authorization", "Token invalid value")
      |> delete("/api/documents/#{document.id}/shares/#{created.share.id}")

    assert json_response(conn, 404) == %{"error" => "not_found"}
  end

  test "share deletion without manage token returns not_found", %{
    conn: conn,
    owner_id: owner_id,
    document: document
  } do
    {:ok, created} = create_share(document, owner_id)

    conn = delete(conn, "/api/documents/#{document.id}/shares/#{created.share.id}")

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
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> delete("/api/documents/#{document.id}/shares/#{created.share.id}/admin")

    assert response(conn, 204) == ""
    assert {:error, :not_found} = Sharing.get_share_landing(created.share_slug)
  end
end
