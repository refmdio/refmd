defmodule RefMDWeb.ShareMountControllerTest do
  use RefMDWeb.ConnCase, async: true

  import Ecto.Query

  alias RefMD.Auth
  alias RefMD.Documents
  alias RefMD.Documents.TreeOrdering
  alias RefMD.Repo
  alias RefMD.Sharing
  alias RefMD.Sharing.Share
  alias RefMD.Sharing.SharedFolderToken
  alias RefMD.Sharing.ShareMount
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
    {signing_public_key, signing_private_key} = :crypto.generate_key(:eddsa, :ed25519)
    {ecdh_public_key, _ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)

    {:ok, device} =
      RefMD.Devices.create_device(%{
        user_id: user_id,
        name: "Browser",
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
        "encrypted_dek" => :crypto.strong_rand_bytes(if(password_protected, do: 48, else: 32)),
        "nonce" => if(password_protected, do: :crypto.strong_rand_bytes(24), else: nil)
      }
      |> maybe_put_password_fields(opts)

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
        "encrypted_dek" => :crypto.strong_rand_bytes(if(password_protected, do: 48, else: 32)),
        "nonce" => if(password_protected, do: :crypto.strong_rand_bytes(24), else: nil),
        "share_keys" =>
          Enum.map(shared_nodes, fn document ->
            %{
              "share_id" => Ecto.UUID.generate(),
              "document_id" => document.id,
              "encrypted_dek" =>
                :crypto.strong_rand_bytes(if(password_protected, do: 48, else: 32)),
              "nonce" => if(password_protected, do: :crypto.strong_rand_bytes(24), else: nil)
            }
          end)
      }
      |> maybe_put_password_fields(opts)

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
    {created, _auth_key} = create_document_share(document, owner_id)
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    conn =
      conn
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> post("/api/mounts", %{
        "workspace_id" => mount_workspace.id,
        "share_slug" => created.share_slug,
        "target_kind" => "document",
        "target_token" => landing.root.document_token
      })

    assert %{
             "id" => mount_id,
             "workspace_id" => workspace_id,
             "share_id" => share_id,
             "target_kind" => "document",
             "status" => "active",
             "target" => %{"document_id" => document_id}
           } = json_response(conn, 201)

    assert workspace_id == mount_workspace.id
    assert share_id == created.share.id
    assert document_id == document.id
    assert Ecto.UUID.cast(mount_id) != :error
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
        "target_token" => landing.root.document_token
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
        "target_token" => landing.root.document_token
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
        "target_token" => landing.root.document_token
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
        "target_token" => landing.root.document_token
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
        "target_token" => landing.root.document_token
      })

    %{"id" => mount_id} = json_response(create_conn, 201)

    from(m in ShareMount, where: m.id == ^mount_id)
    |> Repo.update_all(set: [position: local_document.position])

    assert :ok = TreeOrdering.normalize_combined_siblings!(mount_workspace.id, nil)

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
               "target_token" => landing.root.document_token
             }),
             201
           )

    duplicate_conn =
      post(authed, "/api/mounts", %{
        "workspace_id" => mount_workspace.id,
        "share_slug" => created.share_slug,
        "target_kind" => "document",
        "target_token" => landing.root.document_token
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

  test "GET /api/shares/:share_slug/mounts lists saved targets for the current user", %{
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
        "target_token" => landing.root.document_token
      })

    conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> get("/api/shares/#{created.share_slug}/mounts")

    assert %{"mounts" => [%{"workspace_id" => workspace_id, "target_token" => target_token}]} =
             json_response(conn, 200)

    assert workspace_id == mount_workspace.id
    assert target_token == landing.root.document_token
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
        "target_token" => landing.root.document_token
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

  test "GET /api/mounts/:mount_id returns document admission for active mounts", %{
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
        "target_token" => landing.root.document_token
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
      |> get("/api/mounts/#{mount_id}")

    assert %{
             "mount" => %{"id" => ^mount_id},
             "admission" => %{
               "document_id" => document_id,
               "share_id" => share_id,
               "encrypted_dek" => encrypted_dek
             }
           } = json_response(conn, 200)

    assert document_id == document.id
    assert share_id == created.share.id
    assert is_binary(encrypted_dek)
  end

  test "GET /api/mounts/:mount_id/folders/:folder_token returns folder subtree", %{
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
        "target_token" => landing.root.folder_token
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
      |> get("/api/mounts/#{mount_id}/folders/#{landing.root.folder_token}")

    assert %{
             "mount" => %{"id" => ^mount_id},
             "folder" => %{"id" => folder_id},
             "entries" => entries
           } = json_response(conn, 200)

    assert folder_id == folder.id
    assert Enum.any?(entries, &(&1["id"] == child_folder.id))
    assert Enum.any?(entries, &(&1["id"] == child_document.id))
    refute Enum.any?(entries, &(&1["id"] == nested_document.id))

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
      |> get("/api/mounts/#{mount_id}/folders/#{child_folder_entry["folder_token"]}")

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
        "target_token" => child_folder_token
      })

    assert %{
             "id" => mount_id,
             "target_kind" => "folder",
             "target_token" => target_token,
             "target" => %{"document_id" => target_document_id}
           } = json_response(create_conn, 201)

    assert target_token == child_folder_token
    assert target_document_id == child_folder.id

    detail_conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> get("/api/mounts/#{mount_id}")

    assert %{
             "mount" => %{"id" => ^mount_id, "target_kind" => "folder"},
             "folder_tree" => %{
               "folder" => %{"id" => mounted_folder_id},
               "entries" => mounted_entries
             }
           } = json_response(detail_conn, 200)

    assert mounted_folder_id == child_folder.id
    assert Enum.any?(mounted_entries, &(&1["id"] == nested_document.id))
    refute Enum.any?(mounted_entries, &(&1["id"] == sibling_document.id))
  end

  test "GET /api/mounts/:mount_id with document_id returns admission for mounted folder child", %{
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
        "target_token" => landing.root.folder_token
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
      |> get("/api/mounts/#{mount_id}?document_id=#{child_document.id}")

    assert %{
             "mount" => %{"id" => ^mount_id, "target_kind" => "folder"},
             "admission" => %{
               "document_id" => document_id,
               "share_id" => share_id,
               "encrypted_dek" => encrypted_dek
             },
             "folder_tree" => nil,
             "child_shares" => nil
           } = json_response(conn, 200)

    assert document_id == child_document.id
    assert share_id != created.share.id
    assert is_binary(encrypted_dek)
  end

  test "GET /api/mounts/:mount_id with share query returns admission for mounted folder child", %{
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
        "target_token" => landing.root.folder_token
      })

    %{"id" => mount_id} = json_response(create_conn, 201)

    child_share =
      Repo.one!(
        from s in Share,
          where: s.parent_share_id == ^created.share.id,
          where: s.document_id == ^child_document.id
      )

    conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> get("/api/mounts/#{mount_id}?share=#{child_share.id}")

    assert %{
             "mount" => %{"id" => ^mount_id, "target_kind" => "folder"},
             "admission" => %{
               "document_id" => document_id,
               "share_id" => share_id,
               "encrypted_dek" => encrypted_dek
             },
             "folder_tree" => nil,
             "child_shares" => nil
           } = json_response(conn, 200)

    assert document_id == child_document.id
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
        "target_token" => landing.root.document_token
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
        "target_token" => landing.root.document_token
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

  test "password-protected mounts require challenge before returning admission", %{
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
        "target_token" => landing.root.document_token
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
      |> get("/api/mounts/#{mount_id}")

    assert %{"admission" => nil, "mount" => %{"password_protected" => true}} =
             json_response(show_conn, 200)

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

    respond_conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> post("/api/mounts/#{mount_id}/challenge", %{"response" => response})

    assert %{"admission" => %{"document_id" => document_id}} = json_response(respond_conn, 200)
    assert document_id == document.id
  end

  test "password-protected folder mounts can return child document admission after challenge", %{
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
        "target_token" => landing.root.folder_token
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
      |> get("/api/mounts/#{mount_id}")

    assert %{"folder_tree" => nil, "mount" => %{"password_protected" => true}} =
             json_response(show_conn, 200)

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
      |> post("/api/mounts/#{mount_id}/challenge", %{"response" => response})

    assert %{"folder_tree" => %{"entries" => root_entries}} =
             json_response(root_respond_conn, 200)

    assert Enum.any?(root_entries, &(&1["id"] == child_folder.id))
    assert Enum.any?(root_entries, &(&1["id"] == child_document.id))
    refute Enum.any?(root_entries, &(&1["id"] == nested_document.id))

    child_folder_entry = Enum.find(root_entries, &(&1["id"] == child_folder.id))
    assert is_binary(child_folder_entry["folder_token"])

    nested_conn =
      build_conn()
      |> authed_conn(mount_user_id, mount_user_device.device)
      |> with_pop_headers(
        mount_user_id,
        mount_user_device.device,
        mount_user_device.signing_private_key
      )
      |> get("/api/mounts/#{mount_id}/folders/#{child_folder_entry["folder_token"]}")

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

    child_share =
      Repo.one!(
        from s in Share,
          where: s.parent_share_id == ^created.share.id,
          where: s.document_id == ^child_document.id
      )

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
        "share_id" => child_share.id
      })

    assert %{"admission" => %{"document_id" => document_id, "password_protected" => true}} =
             json_response(respond_conn, 200)

    assert document_id == child_document.id
  end
end
