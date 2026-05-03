defmodule RefMD.SharingTest do
  use RefMD.DataCase, async: true

  alias RefMD.Crypto.Blake3
  alias RefMD.Documents
  alias RefMD.Repo
  alias RefMD.Sharing

  alias RefMD.Sharing.{ServerEnvelope, Share, ShareExclusion, ShareKey, SharePasswordChallenge}

  alias RefMD.Users.User
  alias RefMD.Workspaces
  alias RefMD.Workspaces.{WorkspaceMember, WorkspaceRole}

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

  defp create_share_attrs(opts \\ []) do
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    %{
      "id" => Ecto.UUID.generate(),
      "scope" => "document",
      "share_slug" => share_slug,
      "token_prefix" => String.slice(share_slug, 0, 4),
      "permission" => Keyword.get(opts, :permission, "view"),
      "password_protected" => false,
      "encrypted_dek" => :crypto.strong_rand_bytes(32),
      "nonce" => nil,
      "access_limit" => Keyword.get(opts, :access_limit),
      "expires_at" => Keyword.get(opts, :expires_at)
    }
  end

  defp create_password_protected_share_attrs(opts) do
    auth_key = Keyword.get(opts, :auth_key, :crypto.strong_rand_bytes(32))

    create_share_attrs(opts)
    |> Map.merge(%{
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
  end

  defp valid_signing_public_key do
    key = :crypto.strong_rand_bytes(32)
    if RefMD.Crypto.valid_ed25519_public_key?(key), do: key, else: valid_signing_public_key()
  end

  defp valid_encryption_public_key do
    key = :crypto.strong_rand_bytes(32)
    if RefMD.Crypto.valid_x25519_public_key?(key), do: key, else: valid_encryption_public_key()
  end

  defp create_device(user_id) do
    {signing_public_key, _signing_private_key} = :crypto.generate_key(:eddsa, :ed25519)
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

    device
  end

  defp insert_document_signer!(attrs) do
    now = DateTime.utc_now()

    Repo.insert_all(RefMD.Documents.DocumentSignerKey, [
      %{
        document_id: attrs.document_id,
        signer_kind: attrs.signer_kind,
        share_id: Map.get(attrs, :share_id),
        principal_id: Map.get(attrs, :principal_id),
        user_id: Map.get(attrs, :user_id),
        device_id: attrs.device_id,
        context_key:
          [
            attrs.signer_kind,
            Map.get(attrs, :share_id) || "-",
            Map.get(attrs, :principal_id) || "-",
            Map.get(attrs, :user_id) || "-",
            attrs.device_id
          ]
          |> Enum.join(":"),
        signing_public_key: attrs.signing_public_key,
        encryption_public_key: attrs.encryption_public_key,
        first_seen_at: now,
        last_seen_at: now
      }
    ])
  end

  defp create_folder_share_attrs(nodes, opts \\ []) do
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    password_protected = Keyword.get(opts, :password_protected, false)

    %{
      "id" => Ecto.UUID.generate(),
      "scope" => "folder",
      "share_slug" => share_slug,
      "token_prefix" => String.slice(share_slug, 0, 4),
      "permission" => Keyword.get(opts, :permission, "view"),
      "password_protected" => password_protected,
      "encrypted_dek" => :crypto.strong_rand_bytes(if(password_protected, do: 48, else: 32)),
      "nonce" => if(password_protected, do: :crypto.strong_rand_bytes(24), else: nil),
      "share_keys" => Enum.map(nodes, &folder_share_key_attrs(&1, password_protected)),
      "salt" => Keyword.get(opts, :salt),
      "kdf_params" => Keyword.get(opts, :kdf_params),
      "auth_key" => Keyword.get(opts, :auth_key),
      "exclusions" => Keyword.get(opts, :exclusions)
    }
  end

  defp folder_share_key_attrs(document, password_protected \\ false) do
    %{
      "share_id" => Ecto.UUID.generate(),
      "document_id" => document.id,
      "encrypted_dek" => :crypto.strong_rand_bytes(if(password_protected, do: 48, else: 32)),
      "nonce" => if(password_protected, do: :crypto.strong_rand_bytes(24), else: nil)
    }
  end

  defp legacy_server_wrap(plaintext, purpose, share_id, document_id \\ nil) do
    aad =
      %{protocol: "refmd", version: 1}
      |> Map.merge(%{purpose: purpose, share_id: share_id})
      |> maybe_put_document_id(document_id)
      |> Jason.encode!()

    nonce = :crypto.strong_rand_bytes(12)
    key = :binary.copy(<<1>>, 32)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, key, nonce, plaintext, aad, 16, true)

    %{ciphertext: ciphertext <> tag, nonce: nonce, key_id: "test-share-key"}
  end

  defp maybe_put_document_id(aad, nil), do: aad
  defp maybe_put_document_id(aad, document_id), do: Map.put(aad, :document_id, document_id)

  defp insert_child_share_without_key!(root_share, document, owner_id, opts \\ []) do
    token = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

    Repo.insert!(
      Share.changeset(%Share{}, %{
        id: Ecto.UUID.generate(),
        document_id: document.id,
        parent_share_id: root_share.id,
        scope: Keyword.get(opts, :scope, "document"),
        token_hash: token,
        token_prefix: String.slice(token, 0, 4),
        slug_ciphertext: :crypto.strong_rand_bytes(32),
        slug_nonce: :crypto.strong_rand_bytes(12),
        slug_key_id: "test",
        permission: "view",
        password_protected: false,
        access_count: 0,
        created_by: owner_id
      })
    )
  end

  setup do
    owner_id = create_user("owner@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Test Workspace")
    document = create_document(workspace.id, owner_id)
    folder = create_folder(workspace.id, owner_id)
    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)

    %{
      owner_id: owner_id,
      workspace: workspace,
      document: document,
      folder: folder,
      owner_role: role
    }
  end

  test "create_share/3 creates a landing share and canonical token", %{
    document: document,
    owner_id: owner_id
  } do
    attrs = create_share_attrs()

    assert {:ok, result} = Sharing.create_share(document, owner_id, attrs)
    assert result.share.document_id == document.id
    assert result.share.permission == attrs["permission"]
    assert result.share_slug == attrs["share_slug"]
    assert is_binary(result.share_manage_token)

    assert {:ok, landing} = Sharing.get_share_landing(attrs["share_slug"])
    assert landing.share.id == result.share.id
    assert landing.root.kind == "document"
    assert is_binary(landing.root.document_token)
  end

  test "create_share/3 rejects archived root documents", %{document: document, owner_id: owner_id} do
    assert {:ok, archived_document} = Documents.archive_document(document)

    assert {:error, {:invalid_value, :document_id}} =
             Sharing.create_share(archived_document, owner_id, create_share_attrs())
  end

  test "create_share/3 rejects archived root folders", %{folder: folder, owner_id: owner_id} do
    assert {:ok, archived_folder} = Documents.archive_document(folder)

    assert {:error, {:invalid_value, :document_id}} =
             Sharing.create_share(archived_folder, owner_id, create_folder_share_attrs([]))
  end

  test "create_share/3 accepts access_limit on edit shares", %{
    document: document,
    owner_id: owner_id
  } do
    assert {:ok, result} =
             Sharing.create_share(
               document,
               owner_id,
               create_share_attrs(permission: "edit", access_limit: 1)
             )

    assert result.share.permission == "edit"
    assert result.share.access_limit == 1
  end

  test "create_share/3 rejects password material on open shares", %{
    document: document,
    owner_id: owner_id
  } do
    attrs =
      create_share_attrs()
      |> Map.merge(%{
        "salt" => :crypto.strong_rand_bytes(16),
        "kdf_params" => %{"algorithm" => "argon2id"},
        "auth_key" => :crypto.strong_rand_bytes(32)
      })

    assert {:error, {:invalid_value, :password_protected}} =
             Sharing.create_share(document, owner_id, attrs)
  end

  test "create_share/3 rejects nonce on open shares", %{document: document, owner_id: owner_id} do
    attrs = Map.put(create_share_attrs(), "nonce", :crypto.strong_rand_bytes(24))

    assert {:error, :invalid_nonce} = Sharing.create_share(document, owner_id, attrs)
  end

  test "server envelope decrypts legacy AAD rows" do
    share_id = Ecto.UUID.generate()
    document_id = Ecto.UUID.generate()
    slug = :crypto.strong_rand_bytes(16)
    dek = :crypto.strong_rand_bytes(32)
    auth_key = :crypto.strong_rand_bytes(32)

    wrapped_slug = legacy_server_wrap(slug, "share_slug_server_wrap", share_id)
    wrapped_dek = legacy_server_wrap(dek, "share_dek_server_wrap", share_id, document_id)
    wrapped_auth_key = legacy_server_wrap(auth_key, "share_auth_key_server_wrap", share_id)

    assert {:ok, ^slug} =
             ServerEnvelope.decrypt_share_slug(
               wrapped_slug.ciphertext,
               wrapped_slug.nonce,
               wrapped_slug.key_id,
               share_id
             )

    assert {:ok, ^dek} =
             ServerEnvelope.decrypt_share_dek(
               wrapped_dek.ciphertext,
               wrapped_dek.nonce,
               wrapped_dek.key_id,
               share_id,
               document_id
             )

    assert {:ok, ^auth_key} =
             ServerEnvelope.decrypt_share_auth_key(
               wrapped_auth_key.ciphertext,
               wrapped_auth_key.nonce,
               wrapped_auth_key.key_id,
               share_id
             )
  end

  test "bootstrap_participant/2 issues a share session and canonical bootstrap", %{
    document: document,
    owner_id: owner_id
  } do
    attrs = create_share_attrs(permission: "edit")
    assert {:ok, created} = Sharing.create_share(document, owner_id, attrs)
    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    participant = %{
      "display_name" => "Guest User",
      "device_signing_pub_key" => valid_signing_public_key(),
      "device_encryption_pub_key" => valid_encryption_public_key()
    }

    assert {:ok, bootstrapped} = Sharing.bootstrap_participant(created.share_slug, participant)
    assert bootstrapped.root.document_token == landing.root.document_token
    assert bootstrapped.participant.grant == "edit"
    assert bootstrapped.session.grant == "edit"

    session_token_base64 = Base.url_encode64(bootstrapped.session_token, padding: false)

    created.share
    |> Ecto.Changeset.change(permission: "view")
    |> Repo.update!()

    assert {:ok, canonical} =
             Sharing.get_document_bootstrap(landing.root.document_token, session_token_base64)

    assert canonical.share_id == created.share.id
    assert canonical.document_id == document.id
    assert canonical.permission == "edit"
    assert canonical.share_slug == created.share_slug
    assert is_binary(canonical.encrypted_dek)
    assert is_nil(canonical.nonce)
  end

  test "document share participant verification directory exposes edit participant devices only",
       %{
         document: document,
         owner_id: owner_id
       } do
    assert {:ok, view_share} =
             Sharing.create_share(document, owner_id, create_share_attrs(permission: "view"))

    view_signing_key = valid_signing_public_key()

    assert {:ok, _view_bootstrap} =
             Sharing.bootstrap_participant(view_share.share_slug, %{
               "display_name" => "View Guest",
               "device_signing_pub_key" => view_signing_key,
               "device_encryption_pub_key" => valid_encryption_public_key()
             })

    assert {:ok, edit_share} =
             Sharing.create_share(document, owner_id, create_share_attrs(permission: "edit"))

    edit_signing_key = valid_signing_public_key()

    assert {:ok, edit_bootstrap} =
             Sharing.bootstrap_participant(edit_share.share_slug, %{
               "display_name" => "Edit Guest",
               "device_signing_pub_key" => edit_signing_key,
               "device_encryption_pub_key" => valid_encryption_public_key()
             })

    directory = Sharing.document_share_participant_verification_directory(document.id)

    assert Enum.any?(
             directory.share_participant_devices,
             &(&1.device_id == edit_bootstrap.participant.device_id and
                 &1.share_id == edit_share.share.id)
           )

    refute Enum.any?(
             directory.share_participant_devices,
             &(&1.signing_public_key == Base.url_encode64(view_signing_key, padding: false))
           )
  end

  test "document share participant verification directory includes folder share participants",
       %{
         folder: folder,
         owner_id: owner_id
       } do
    child_document = create_document(folder.workspace_id, owner_id, folder.id)

    assert {:ok, created} =
             Sharing.create_share(
               folder,
               owner_id,
               create_folder_share_attrs([child_document], permission: "edit")
             )

    assert {:ok, bootstrapped} =
             Sharing.bootstrap_participant(created.share_slug, %{
               "display_name" => "Folder Guest",
               "device_signing_pub_key" => valid_signing_public_key(),
               "device_encryption_pub_key" => valid_encryption_public_key()
             })

    directory = Sharing.document_share_participant_verification_directory(child_document.id)

    assert Enum.any?(
             directory.share_participant_devices,
             &(&1.device_id == bootstrapped.participant.device_id and
                 &1.share_id == created.share.id)
           )
  end

  test "verification directories include devices from users who saved a share mount", %{
    document: document,
    owner_id: owner_id
  } do
    mount_user_id = create_user("mounted-reader@example.com")

    {:ok, mount_workspace} =
      Workspaces.create_default_workspace(mount_user_id, "Mounted Workspace")

    mount_device = create_device(mount_user_id)

    assert {:ok, created} =
             Sharing.create_share(document, owner_id, create_share_attrs(permission: "edit"))

    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    assert {:ok, _mount} =
             Sharing.create_share_mount(mount_user_id, %{
               "workspace_id" => mount_workspace.id,
               "share_slug" => created.share_slug,
               "target_kind" => "document",
               "target_token" => landing.root.document_token
             })

    directory = Sharing.verification_directory(created.share.id, document.id)

    assert Enum.any?(
             directory.share_participant_devices,
             &(&1.share_id == created.share.id and &1.principal_id == mount_user_id and
                 &1.device_id == mount_device.id)
           )

    document_directory = Sharing.document_share_participant_verification_directory(document.id)

    assert Enum.any?(
             document_directory.share_participant_devices,
             &(&1.share_id == created.share.id and &1.principal_id == mount_user_id and
                 &1.device_id == mount_device.id)
           )
  end

  test "verification directories keep historical share signer keys after share deletion", %{
    document: document,
    owner_id: owner_id
  } do
    signing_key = valid_signing_public_key()
    encryption_key = valid_encryption_public_key()

    assert {:ok, created} =
             Sharing.create_share(document, owner_id, create_share_attrs(permission: "edit"))

    assert {:ok, bootstrapped} =
             Sharing.bootstrap_participant(created.share_slug, %{
               "display_name" => "Former Guest",
               "device_signing_pub_key" => signing_key,
               "device_encryption_pub_key" => encryption_key
             })

    insert_document_signer!(%{
      document_id: document.id,
      signer_kind: "share_participant",
      share_id: created.share.id,
      principal_id: bootstrapped.participant.principal_id,
      device_id: bootstrapped.participant.device_id,
      signing_public_key: signing_key,
      encryption_public_key: encryption_key
    })

    assert :ok = Sharing.delete_share(document.id, created.share.id, created.share_manage_token)

    directory = Sharing.document_share_participant_verification_directory(document.id)
    encoded_signing_key = Base.url_encode64(signing_key, padding: false)

    assert Enum.any?(
             directory.share_participant_devices,
             &(&1.signing_public_key == encoded_signing_key and
                 &1.device_id == bootstrapped.participant.device_id and
                 &1.historical == true and
                 is_nil(&1.display_name))
           )
  end

  test "verification directories keep historical workspace signer keys after device deletion", %{
    document: document,
    owner_id: owner_id
  } do
    device = create_device(owner_id)

    assert {:ok, created} =
             Sharing.create_share(document, owner_id, create_share_attrs(permission: "edit"))

    insert_document_signer!(%{
      document_id: document.id,
      signer_kind: "workspace",
      user_id: owner_id,
      device_id: device.id,
      signing_public_key: device.signing_public_key,
      encryption_public_key: device.ecdh_public_key
    })

    Repo.delete!(device)

    directory = Sharing.verification_directory(created.share.id, document.id)
    encoded_signing_key = Base.url_encode64(device.signing_public_key, padding: false)

    assert Enum.any?(
             directory.workspace_devices,
             &(&1.signing_public_key == encoded_signing_key and &1.device_id == device.id and
                 &1.historical == true)
           )
  end

  test "canonical bootstrap requires re-entry when share session is missing", %{
    document: document,
    owner_id: owner_id
  } do
    attrs = create_share_attrs()
    assert {:ok, created} = Sharing.create_share(document, owner_id, attrs)
    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    assert {:ok, response} = Sharing.get_document_bootstrap(landing.root.document_token, nil)
    assert response.bootstrap_required == true
    assert response.share_slug == created.share_slug
  end

  test "password-protected share requires challenge flow before issuing a participant session", %{
    document: document,
    owner_id: owner_id
  } do
    auth_key = :crypto.strong_rand_bytes(32)
    attrs = create_password_protected_share_attrs(auth_key: auth_key)

    assert {:ok, created} = Sharing.create_share(document, owner_id, attrs)
    assert created.share.password_protected

    share_key = Repo.get!(ShareKey, created.share.id)
    assert share_key.salt == attrs["salt"]
    assert share_key.kdf_params == attrs["kdf_params"]
    assert is_binary(share_key.encrypted_auth_key)
    assert is_binary(share_key.auth_key_nonce)

    participant = %{
      "display_name" => "Guest User",
      "device_signing_pub_key" => valid_signing_public_key(),
      "device_encryption_pub_key" => valid_encryption_public_key()
    }

    assert {:error, :password_required} =
             Sharing.bootstrap_participant(created.share_slug, participant)

    assert {:ok, challenge} = Sharing.get_password_challenge(created.share_slug)
    assert challenge.salt == attrs["salt"]
    assert challenge.kdf_params == attrs["kdf_params"]

    response = :crypto.mac(:hmac, :sha256, auth_key, challenge.challenge)

    assert {:ok, bootstrapped} =
             Sharing.respond_password_challenge(
               created.share_slug,
               Map.put(participant, "response", response)
             )

    session_token_base64 = Base.url_encode64(bootstrapped.session_token, padding: false)
    {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    assert {:ok, canonical} =
             Sharing.get_document_bootstrap(landing.root.document_token, session_token_base64)

    assert canonical.password_protected == true
    assert canonical.share_id == created.share.id
    assert canonical.nonce == attrs["nonce"]
  end

  test "password challenge returns dummy salt for a non-existent share slug" do
    slug = "not-a-real-share-slug"

    assert {:ok, first} = Sharing.get_password_challenge(slug)
    assert {:ok, second} = Sharing.get_password_challenge(slug)

    assert byte_size(first.challenge) == 32
    assert first.salt == second.salt
    assert first.kdf_params == second.kdf_params
  end

  test "non-existent share slugs use separate dummy password challenge rows" do
    slug_one = "not-a-real-share-slug"
    slug_two = "also-not-a-real-share-slug"

    assert {:ok, first} = Sharing.get_password_challenge(slug_one)
    assert {:ok, second} = Sharing.get_password_challenge(slug_two)

    stored =
      Repo.all(from(c in SharePasswordChallenge, where: is_nil(c.share_id)))

    assert first.challenge != second.challenge
    assert length(stored) == 2
  end

  test "get_password_challenge/1 reuses the active challenge for a share", %{
    document: document,
    owner_id: owner_id
  } do
    attrs = create_password_protected_share_attrs(auth_key: :crypto.strong_rand_bytes(32))
    assert {:ok, created} = Sharing.create_share(document, owner_id, attrs)

    assert {:ok, first} = Sharing.get_password_challenge(created.share_slug)
    assert {:ok, second} = Sharing.get_password_challenge(created.share_slug)
    assert first.challenge == second.challenge

    token_hash =
      created.share_slug
      |> Base.url_decode64!(padding: false)
      |> Blake3.hash_base64url()

    stored =
      Repo.all(from(c in SharePasswordChallenge, where: c.token_hash == ^token_hash))

    assert length(stored) == 1
    assert hd(stored).challenge == first.challenge
  end

  test "delete_expired_password_challenges/0 removes expired rows only" do
    now = DateTime.utc_now()

    expired =
      Repo.insert!(%SharePasswordChallenge{
        token_hash: Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
        challenge: :crypto.strong_rand_bytes(32),
        expires_at: DateTime.add(now, -60, :second),
        created_at: now
      })

    active =
      Repo.insert!(%SharePasswordChallenge{
        token_hash: Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
        challenge: :crypto.strong_rand_bytes(32),
        expires_at: DateTime.add(now, 60, :second),
        created_at: now
      })

    assert {1, nil} = Sharing.delete_expired_password_challenges()
    refute Repo.get(SharePasswordChallenge, expired.id)
    assert Repo.get(SharePasswordChallenge, active.id)
  end

  test "folder canonical bootstrap requires re-entry after participant device is revoked", %{
    folder: folder,
    owner_id: owner_id
  } do
    child_document = create_document(folder.workspace_id, owner_id, folder.id)

    assert {:ok, created} =
             Sharing.create_share(folder, owner_id, create_folder_share_attrs([child_document]))

    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    participant = %{
      "display_name" => "Guest User",
      "device_signing_pub_key" => valid_signing_public_key(),
      "device_encryption_pub_key" => valid_encryption_public_key()
    }

    assert {:ok, bootstrapped} = Sharing.bootstrap_participant(created.share_slug, participant)

    session_token_base64 = Base.url_encode64(bootstrapped.session_token, padding: false)

    Repo.delete!(
      Repo.get!(RefMD.Sharing.ShareParticipantDevice, bootstrapped.participant.device_id)
    )

    assert {:ok, response} =
             Sharing.get_folder_bootstrap(landing.root.folder_token, session_token_base64)

    assert response.bootstrap_required == true
    assert response.share_slug == created.share_slug
  end

  test "folder shares expose descendant documents and folders", %{
    folder: folder,
    owner_id: owner_id
  } do
    visible_document = create_document(folder.workspace_id, owner_id, folder.id)
    child_folder = create_folder(folder.workspace_id, owner_id, folder.id)
    nested_document = create_document(folder.workspace_id, owner_id, child_folder.id)

    attrs =
      create_folder_share_attrs([visible_document, child_folder, nested_document],
        permission: "edit"
      )

    assert {:ok, created} = Sharing.create_share(folder, owner_id, attrs)
    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    participant = %{
      "display_name" => "Guest User",
      "device_signing_pub_key" => valid_signing_public_key(),
      "device_encryption_pub_key" => valid_encryption_public_key()
    }

    assert {:ok, bootstrapped} = Sharing.bootstrap_participant(created.share_slug, participant)
    session_token_base64 = Base.url_encode64(bootstrapped.session_token, padding: false)

    assert {:ok, folder_bootstrap} =
             Sharing.get_folder_bootstrap(landing.root.folder_token, session_token_base64)

    assert folder_bootstrap.share_id == created.share.id
    assert folder_bootstrap.password_protected == false
    assert folder_bootstrap.folder.parent_id == nil
    assert folder_bootstrap.folder.share_id == created.share.id

    child_folder_entry = Enum.find(folder_bootstrap.entries, &(&1.id == child_folder.id))
    assert is_binary(child_folder_entry.share_id)
    refute child_folder_entry.share_id == created.share.id
    assert is_binary(child_folder_entry.folder_token)
    assert is_binary(child_folder_entry.encrypted_dek)
    assert is_nil(child_folder_entry.nonce)

    visible_entry = Enum.find(folder_bootstrap.entries, &(&1.id == visible_document.id))
    assert is_binary(visible_entry.share_id)
    refute visible_entry.share_id == created.share.id
    assert is_binary(visible_entry.document_token)
    assert visible_entry.encrypted_title == visible_document.encrypted_title
    assert visible_entry.encrypted_title_nonce == visible_document.encrypted_title_nonce
    assert is_binary(visible_entry.encrypted_dek)
    assert is_nil(visible_entry.nonce)

    refute Enum.any?(folder_bootstrap.entries, &(&1.id == nested_document.id))

    assert {:ok, nested_folder_bootstrap} =
             Sharing.get_folder_bootstrap(child_folder_entry.folder_token, session_token_base64)

    assert nested_folder_bootstrap.folder.parent_id == nil
    assert nested_folder_bootstrap.folder.share_id == child_folder_entry.share_id

    nested_folder_entry =
      Enum.find(nested_folder_bootstrap.entries, &(&1.id == nested_document.id))

    assert is_binary(nested_folder_entry.document_token)
    assert nested_folder_entry.parent_id == child_folder.id
    assert is_binary(nested_folder_entry.share_id)
    assert is_binary(nested_folder_entry.encrypted_dek)
    assert is_nil(nested_folder_entry.nonce)

    assert {:ok, canonical} =
             Sharing.get_document_bootstrap(visible_entry.document_token, session_token_base64)

    assert canonical.share_id == visible_entry.share_id
    assert canonical.document_id == visible_document.id
    assert canonical.permission == "edit"
    assert canonical.share_slug == created.share_slug

    assert {:ok, {nil, []}} =
             Documents.get_initial_document_data_for_share(visible_document.id, created.share.id)

    assert {:ok, {nil, []}} =
             Documents.get_initial_document_data_for_share(
               visible_document.id,
               visible_entry.share_id
             )

    assert Sharing.can_read_document?(visible_entry.share_id, visible_document.id)

    assert Sharing.can_join_document_session?(
             visible_entry.share_id,
             visible_document.id,
             bootstrapped.session.id
           )

    refute Sharing.can_read_document?(visible_entry.share_id, nested_document.id)
    refute Sharing.can_continue_document_session?(visible_entry.share_id, nested_document.id)

    refute Sharing.can_join_document_session?(
             visible_entry.share_id,
             nested_document.id,
             bootstrapped.session.id
           )

    assert {:error, :unauthorized} =
             Documents.get_initial_document_data_for_share(
               nested_document.id,
               visible_entry.share_id
             )

    child_share = Repo.get!(Share, visible_entry.share_id)

    assert {:ok, child_slug_bytes} =
             ServerEnvelope.decrypt_share_slug(
               child_share.slug_ciphertext,
               child_share.slug_nonce,
               child_share.slug_key_id,
               child_share.id
             )

    child_share_slug = Base.url_encode64(child_slug_bytes, padding: false)
    assert {:error, :not_found} = Sharing.get_share_landing(child_share_slug)
    assert {:error, :not_found} = Sharing.bootstrap_participant(child_share_slug, participant)

    assert {:ok, _moved_document} =
             Documents.update_document(visible_document, %{"parent_id" => nil})

    refute Sharing.can_read_document?(created.share.id, visible_document.id)
    refute Sharing.can_read_document?(visible_entry.share_id, visible_document.id)
    refute Sharing.can_continue_document_session?(visible_entry.share_id, visible_document.id)

    assert {:error, :unauthorized} =
             Documents.get_initial_document_data_for_share(visible_document.id, created.share.id)

    assert {:error, :unauthorized} =
             Documents.get_initial_document_data_for_share(
               visible_document.id,
               visible_entry.share_id
             )

    assert {:error, :not_found} =
             Sharing.get_document_bootstrap(visible_entry.document_token, session_token_base64)

    assert {:error, :not_found} =
             Sharing.get_document_bootstrap(visible_entry.document_token, nil)

    assert {:ok, _moved_folder} = Documents.update_document(child_folder, %{"parent_id" => nil})

    assert {:error, :not_found} =
             Sharing.get_folder_bootstrap(child_folder_entry.folder_token, session_token_base64)
  end

  test "folder share creation skips excluded descendants", %{
    folder: folder,
    owner_id: owner_id
  } do
    visible_document = create_document(folder.workspace_id, owner_id, folder.id)
    excluded_document = create_document(folder.workspace_id, owner_id, folder.id)
    excluded_folder = create_folder(folder.workspace_id, owner_id, folder.id)
    nested_document = create_document(folder.workspace_id, owner_id, excluded_folder.id)

    attrs =
      create_folder_share_attrs([visible_document],
        exclusions: [excluded_document.id, excluded_folder.id]
      )

    assert {:ok, created} = Sharing.create_share(folder, owner_id, attrs)

    assert Repo.get_by(ShareExclusion,
             share_id: created.share.id,
             document_id: excluded_document.id
           )

    assert Repo.get_by(ShareExclusion,
             share_id: created.share.id,
             document_id: excluded_folder.id
           )

    refute Repo.get_by(Share,
             parent_share_id: created.share.id,
             document_id: excluded_document.id
           )

    refute Repo.get_by(Share, parent_share_id: created.share.id, document_id: excluded_folder.id)
    refute Repo.get_by(Share, parent_share_id: created.share.id, document_id: nested_document.id)

    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    assert {:ok, bootstrapped} =
             Sharing.bootstrap_participant(created.share_slug, %{
               "display_name" => "Guest User",
               "device_signing_pub_key" => valid_signing_public_key(),
               "device_encryption_pub_key" => valid_encryption_public_key()
             })

    session_token = Base.url_encode64(bootstrapped.session_token, padding: false)

    assert {:ok, folder_bootstrap} =
             Sharing.get_folder_bootstrap(landing.root.folder_token, session_token)

    entry_ids = Enum.map(folder_bootstrap.entries, & &1.id)

    assert visible_document.id in entry_ids
    refute excluded_document.id in entry_ids
    refute excluded_folder.id in entry_ids
    refute nested_document.id in entry_ids

    assert Sharing.can_read_document?(created.share.id, visible_document.id)
    refute Sharing.can_read_document?(created.share.id, excluded_document.id)
    refute Sharing.can_read_document?(created.share.id, nested_document.id)
  end

  test "folder share exclusions can be added and removed without recreating child shares", %{
    folder: folder,
    owner_id: owner_id
  } do
    visible_document = create_document(folder.workspace_id, owner_id, folder.id)
    target_document = create_document(folder.workspace_id, owner_id, folder.id)
    child_folder = create_folder(folder.workspace_id, owner_id, folder.id)
    nested_document = create_document(folder.workspace_id, owner_id, child_folder.id)

    attrs =
      create_folder_share_attrs([
        visible_document,
        target_document,
        child_folder,
        nested_document
      ])

    assert {:ok, created} = Sharing.create_share(folder, owner_id, attrs)
    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    assert {:ok, bootstrapped} =
             Sharing.bootstrap_participant(created.share_slug, %{
               "display_name" => "Guest User",
               "device_signing_pub_key" => valid_signing_public_key(),
               "device_encryption_pub_key" => valid_encryption_public_key()
             })

    session_token = Base.url_encode64(bootstrapped.session_token, padding: false)
    share_id = created.share.id
    visible_document_id = visible_document.id

    assert {:ok, initial_bootstrap} =
             Sharing.get_folder_bootstrap(landing.root.folder_token, session_token)

    target_entry = Enum.find(initial_bootstrap.entries, &(&1.id == target_document.id))
    child_folder_entry = Enum.find(initial_bootstrap.entries, &(&1.id == child_folder.id))

    assert {:ok, nested_bootstrap} =
             Sharing.get_folder_bootstrap(child_folder_entry.folder_token, session_token)

    nested_entry = Enum.find(nested_bootstrap.entries, &(&1.id == nested_document.id))

    Phoenix.PubSub.subscribe(
      RefMD.PubSub,
      "share_document_revocation:#{share_id}:#{visible_document.id}"
    )

    Phoenix.PubSub.subscribe(
      RefMD.PubSub,
      "share_document_revocation:#{share_id}:#{target_document.id}"
    )

    Phoenix.PubSub.subscribe(
      RefMD.PubSub,
      "share_document_revocation:#{share_id}:#{child_folder.id}"
    )

    Phoenix.PubSub.subscribe(
      RefMD.PubSub,
      "share_document_revocation:#{share_id}:#{nested_document.id}"
    )

    Phoenix.PubSub.subscribe(
      RefMD.PubSub,
      "share_device_revocation:#{bootstrapped.participant.device_id}"
    )

    Phoenix.PubSub.subscribe(
      RefMD.PubSub,
      "share_socket:#{bootstrapped.participant.principal_id}"
    )

    assert {:ok, result} =
             Sharing.update_share_exclusions(
               folder.id,
               created.share.id,
               created.share_manage_token,
               %{"add" => [target_document.id, child_folder.id]}
             )

    assert result.share_id == created.share.id
    assert MapSet.new(result.exclusions) == MapSet.new([target_document.id, child_folder.id])

    revoked_ids =
      Enum.map(1..3, fn _ ->
        assert_receive {:share_document_revoked, ^share_id, document_id}
        document_id
      end)

    assert MapSet.new(revoked_ids) ==
             MapSet.new([target_document.id, child_folder.id, nested_document.id])

    refute_receive {:share_document_revoked, _share_id, ^visible_document_id}, 50
    refute_receive {:device_revoked, _device_id}, 50
    refute_receive %Phoenix.Socket.Broadcast{event: "disconnect"}, 50

    assert {:ok, updated_bootstrap} =
             Sharing.get_folder_bootstrap(landing.root.folder_token, session_token)

    updated_entry_ids = Enum.map(updated_bootstrap.entries, & &1.id)

    assert visible_document.id in updated_entry_ids
    refute target_document.id in updated_entry_ids
    refute child_folder.id in updated_entry_ids

    assert {:error, :not_found} =
             Sharing.get_document_bootstrap(target_entry.document_token, session_token)

    assert {:error, :not_found} =
             Sharing.get_folder_bootstrap(child_folder_entry.folder_token, session_token)

    assert {:error, :not_found} =
             Sharing.get_document_bootstrap(nested_entry.document_token, session_token)

    refute Sharing.can_read_document?(created.share.id, target_document.id)
    refute Sharing.can_read_document?(created.share.id, nested_document.id)

    assert {:ok, result} =
             Sharing.update_share_exclusions(
               folder.id,
               created.share.id,
               created.share_manage_token,
               %{"remove" => [child_folder.id]}
             )

    assert result.exclusions == [target_document.id]

    assert {:ok, final_bootstrap} =
             Sharing.get_folder_bootstrap(landing.root.folder_token, session_token)

    final_entry_ids = Enum.map(final_bootstrap.entries, & &1.id)

    assert visible_document.id in final_entry_ids
    refute child_folder.id in final_entry_ids
    refute target_document.id in final_entry_ids
  end

  test "folder share exclusion removal does not disconnect active visitors", %{
    folder: folder,
    owner_id: owner_id
  } do
    target_document = create_document(folder.workspace_id, owner_id, folder.id)

    assert {:ok, created} =
             Sharing.create_share(
               folder,
               owner_id,
               create_folder_share_attrs([], exclusions: [target_document.id])
             )

    assert {:ok, bootstrapped} =
             Sharing.bootstrap_participant(created.share_slug, %{
               "display_name" => "Guest User",
               "device_signing_pub_key" => valid_signing_public_key(),
               "device_encryption_pub_key" => valid_encryption_public_key()
             })

    Phoenix.PubSub.subscribe(
      RefMD.PubSub,
      "share_device_revocation:#{bootstrapped.participant.device_id}"
    )

    Phoenix.PubSub.subscribe(
      RefMD.PubSub,
      "share_socket:#{bootstrapped.participant.principal_id}"
    )

    assert {:ok, %{exclusions: []}} =
             Sharing.update_share_exclusions(
               folder.id,
               created.share.id,
               created.share_manage_token,
               %{"remove" => [target_document.id]}
             )

    refute_receive {:device_revoked, _device_id}, 50
    refute_receive %Phoenix.Socket.Broadcast{event: "disconnect"}, 50
  end

  test "folder share keys can be added for newly created descendants", %{
    folder: folder,
    owner_id: owner_id
  } do
    assert {:ok, created} =
             Sharing.create_share(folder, owner_id, create_folder_share_attrs([]))

    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    assert {:ok, bootstrapped} =
             Sharing.bootstrap_participant(created.share_slug, %{
               "display_name" => "Guest User",
               "device_signing_pub_key" => valid_signing_public_key(),
               "device_encryption_pub_key" => valid_encryption_public_key()
             })

    session_token = Base.url_encode64(bootstrapped.session_token, padding: false)

    assert {:ok, initial_bootstrap} =
             Sharing.get_folder_bootstrap(landing.root.folder_token, session_token)

    assert initial_bootstrap.entries == []

    new_document = create_document(folder.workspace_id, owner_id, folder.id)
    new_folder = create_folder(folder.workspace_id, owner_id, folder.id)
    nested_document = create_document(folder.workspace_id, owner_id, new_folder.id)

    assert {:ok, result} =
             Sharing.update_share_keys(
               folder.id,
               created.share.id,
               created.share_manage_token,
               %{
                 "add_keys" => [
                   folder_share_key_attrs(new_document),
                   folder_share_key_attrs(new_folder),
                   folder_share_key_attrs(nested_document)
                 ]
               }
             )

    assert result.share_id == created.share.id
    assert result.added == [new_document.id, new_folder.id, nested_document.id]
    assert result.replaced == []

    assert Repo.get_by(Share, parent_share_id: created.share.id, document_id: new_document.id)
    assert Repo.get_by(Share, parent_share_id: created.share.id, document_id: new_folder.id)
    assert Repo.get_by(Share, parent_share_id: created.share.id, document_id: nested_document.id)

    assert {:ok, updated_bootstrap} =
             Sharing.get_folder_bootstrap(landing.root.folder_token, session_token)

    document_entry = Enum.find(updated_bootstrap.entries, &(&1.id == new_document.id))
    folder_entry = Enum.find(updated_bootstrap.entries, &(&1.id == new_folder.id))

    assert is_binary(document_entry.document_token)
    assert is_binary(folder_entry.folder_token)

    assert {:ok, nested_bootstrap} =
             Sharing.get_folder_bootstrap(folder_entry.folder_token, session_token)

    assert Enum.any?(nested_bootstrap.entries, &(&1.id == nested_document.id))
    assert Sharing.can_read_document?(created.share.id, new_document.id)
    assert Sharing.can_read_document?(created.share.id, nested_document.id)
  end

  test "folder share keys can be replaced for existing child shares", %{
    folder: folder,
    owner_id: owner_id
  } do
    target_document = create_document(folder.workspace_id, owner_id, folder.id)

    assert {:ok, created} =
             Sharing.create_share(
               folder,
               owner_id,
               create_folder_share_attrs([target_document])
             )

    child_share =
      Repo.get_by!(Share, parent_share_id: created.share.id, document_id: target_document.id)

    original_share_key = Repo.get!(ShareKey, child_share.id)
    replacement_encrypted_dek = :crypto.strong_rand_bytes(32)

    assert {:ok, result} =
             Sharing.update_share_keys(
               folder.id,
               created.share.id,
               created.share_manage_token,
               %{
                 "replace_keys" => [
                   %{
                     "share_id" => child_share.id,
                     "document_id" => target_document.id,
                     "encrypted_dek" => replacement_encrypted_dek,
                     "nonce" => nil
                   }
                 ]
               }
             )

    assert result.share_id == created.share.id
    assert result.added == []
    assert result.replaced == [target_document.id]

    updated_share_key = Repo.get!(ShareKey, child_share.id)
    assert is_nil(updated_share_key.nonce)
    refute updated_share_key.encrypted_dek == original_share_key.encrypted_dek

    assert {:ok, ^replacement_encrypted_dek} =
             ServerEnvelope.decrypt_share_dek(
               updated_share_key.encrypted_dek,
               updated_share_key.dek_server_nonce,
               updated_share_key.server_key_id,
               child_share.id,
               target_document.id
             )
  end

  test "password-protected folder share keys can be added and replaced", %{
    folder: folder,
    owner_id: owner_id
  } do
    auth_key = :crypto.strong_rand_bytes(32)

    assert {:ok, created} =
             Sharing.create_share(
               folder,
               owner_id,
               create_folder_share_attrs([],
                 password_protected: true,
                 salt: :crypto.strong_rand_bytes(16),
                 kdf_params: %{
                   "algorithm" => "argon2id",
                   "memory" => 65_536,
                   "iterations" => 3,
                   "parallelism" => 4,
                   "hash_length" => 32
                 },
                 auth_key: auth_key
               )
             )

    added_document = create_document(folder.workspace_id, owner_id, folder.id)

    assert {:ok, %{added: [added_document_id], replaced: []}} =
             Sharing.update_share_keys(
               folder.id,
               created.share.id,
               created.share_manage_token,
               %{"add_keys" => [folder_share_key_attrs(added_document, true)]}
             )

    assert added_document_id == added_document.id

    child_share =
      Repo.get_by!(Share, parent_share_id: created.share.id, document_id: added_document.id)

    replacement_nonce = :crypto.strong_rand_bytes(24)

    assert {:ok, %{added: [], replaced: [replaced_document_id]}} =
             Sharing.update_share_keys(
               folder.id,
               created.share.id,
               created.share_manage_token,
               %{
                 "replace_keys" => [
                   %{
                     "share_id" => child_share.id,
                     "document_id" => added_document.id,
                     "encrypted_dek" => :crypto.strong_rand_bytes(48),
                     "nonce" => replacement_nonce
                   }
                 ]
               }
             )

    assert replaced_document_id == added_document.id
    assert {:ok, challenge} = Sharing.get_password_challenge(created.share_slug)

    assert {:ok, bootstrapped} =
             Sharing.respond_password_challenge(created.share_slug, %{
               "display_name" => "Guest User",
               "device_signing_pub_key" => valid_signing_public_key(),
               "device_encryption_pub_key" => valid_encryption_public_key(),
               "response" => :crypto.mac(:hmac, :sha256, auth_key, challenge.challenge)
             })

    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)
    session_token = Base.url_encode64(bootstrapped.session_token, padding: false)

    assert {:ok, folder_bootstrap} =
             Sharing.get_folder_bootstrap(landing.root.folder_token, session_token)

    entry = Enum.find(folder_bootstrap.entries, &(&1.id == added_document.id))

    assert entry.nonce == replacement_nonce
  end

  test "folder share key update rejects nonce on open shares", %{
    folder: folder,
    owner_id: owner_id
  } do
    target_document = create_document(folder.workspace_id, owner_id, folder.id)

    assert {:ok, created} =
             Sharing.create_share(folder, owner_id, create_folder_share_attrs([target_document]))

    child_share =
      Repo.get_by!(Share, parent_share_id: created.share.id, document_id: target_document.id)

    assert {:error, {:invalid_value, :add_keys}} =
             Sharing.update_share_keys(
               folder.id,
               created.share.id,
               created.share_manage_token,
               %{
                 "add_keys" => [
                   %{
                     "share_id" => Ecto.UUID.generate(),
                     "document_id" =>
                       create_document(folder.workspace_id, owner_id, folder.id).id,
                     "encrypted_dek" => :crypto.strong_rand_bytes(32),
                     "nonce" => :crypto.strong_rand_bytes(24)
                   }
                 ]
               }
             )

    assert {:error, {:invalid_value, :replace_keys}} =
             Sharing.update_share_keys(
               folder.id,
               created.share.id,
               created.share_manage_token,
               %{
                 "replace_keys" => [
                   %{
                     "share_id" => child_share.id,
                     "document_id" => target_document.id,
                     "encrypted_dek" => :crypto.strong_rand_bytes(32),
                     "nonce" => :crypto.strong_rand_bytes(24)
                   }
                 ]
               }
             )
  end

  test "moved documents under unshared folders are inaccessible to folder shares", %{
    folder: folder,
    owner_id: owner_id
  } do
    target_document = create_document(folder.workspace_id, owner_id, folder.id)

    assert {:ok, created} =
             Sharing.create_share(
               folder,
               owner_id,
               create_folder_share_attrs([target_document])
             )

    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    assert {:ok, bootstrapped} =
             Sharing.bootstrap_participant(created.share_slug, %{
               "display_name" => "Guest User",
               "device_signing_pub_key" => valid_signing_public_key(),
               "device_encryption_pub_key" => valid_encryption_public_key()
             })

    session_token = Base.url_encode64(bootstrapped.session_token, padding: false)

    assert {:ok, folder_bootstrap} =
             Sharing.get_folder_bootstrap(landing.root.folder_token, session_token)

    target_entry = Enum.find(folder_bootstrap.entries, &(&1.id == target_document.id))
    unshared_folder = create_folder(folder.workspace_id, owner_id, folder.id)

    assert {:ok, moved_document} =
             Documents.update_document(target_document, %{"parent_id" => unshared_folder.id})

    refute Sharing.can_read_document?(created.share.id, moved_document.id)

    assert {:error, :not_found} =
             Sharing.get_document_bootstrap(target_entry.document_token, session_token)

    child_share =
      Repo.get_by!(Share, parent_share_id: created.share.id, document_id: moved_document.id)

    assert {:error, {:invalid_value, :replace_keys}} =
             Sharing.update_share_keys(
               folder.id,
               created.share.id,
               created.share_manage_token,
               %{
                 "replace_keys" => [
                   %{
                     "share_id" => child_share.id,
                     "document_id" => moved_document.id,
                     "encrypted_dek" => :crypto.strong_rand_bytes(32),
                     "nonce" => nil
                   }
                 ]
               }
             )
  end

  test "moved folders under unshared folders cannot be bootstrapped", %{
    folder: folder,
    owner_id: owner_id
  } do
    child_folder = create_folder(folder.workspace_id, owner_id, folder.id)
    nested_document = create_document(folder.workspace_id, owner_id, child_folder.id)

    assert {:ok, created} =
             Sharing.create_share(
               folder,
               owner_id,
               create_folder_share_attrs([child_folder, nested_document])
             )

    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    assert {:ok, bootstrapped} =
             Sharing.bootstrap_participant(created.share_slug, %{
               "display_name" => "Guest User",
               "device_signing_pub_key" => valid_signing_public_key(),
               "device_encryption_pub_key" => valid_encryption_public_key()
             })

    session_token = Base.url_encode64(bootstrapped.session_token, padding: false)

    assert {:ok, folder_bootstrap} =
             Sharing.get_folder_bootstrap(landing.root.folder_token, session_token)

    child_folder_entry = Enum.find(folder_bootstrap.entries, &(&1.id == child_folder.id))
    unshared_folder = create_folder(folder.workspace_id, owner_id, folder.id)

    assert {:ok, moved_folder} =
             Documents.update_document(child_folder, %{"parent_id" => unshared_folder.id})

    assert {:error, :not_found} =
             Sharing.get_folder_bootstrap(child_folder_entry.folder_token, session_token)

    refute Sharing.can_read_document?(created.share.id, moved_folder.id)
    refute Sharing.can_read_document?(created.share.id, nested_document.id)
  end

  test "folder share key replacement rejects mismatched child shares", %{
    folder: folder,
    owner_id: owner_id
  } do
    target_document = create_document(folder.workspace_id, owner_id, folder.id)

    assert {:ok, created} =
             Sharing.create_share(
               folder,
               owner_id,
               create_folder_share_attrs([target_document])
             )

    assert {:error, {:invalid_value, :replace_keys}} =
             Sharing.update_share_keys(
               folder.id,
               created.share.id,
               created.share_manage_token,
               %{
                 "replace_keys" => [
                   %{
                     "share_id" => Ecto.UUID.generate(),
                     "document_id" => target_document.id,
                     "encrypted_dek" => :crypto.strong_rand_bytes(32),
                     "nonce" => nil
                   }
                 ]
               }
             )
  end

  test "folder share key update rolls back added children when replacement fails", %{
    folder: folder,
    owner_id: owner_id
  } do
    assert {:ok, created} =
             Sharing.create_share(folder, owner_id, create_folder_share_attrs([]))

    added_document = create_document(folder.workspace_id, owner_id, folder.id)
    replace_document = create_document(folder.workspace_id, owner_id, folder.id)

    child_share_without_key =
      insert_child_share_without_key!(created.share, replace_document, owner_id)

    assert {:error, {:invalid_value, :replace_keys}} =
             Sharing.update_share_keys(
               folder.id,
               created.share.id,
               created.share_manage_token,
               %{
                 "add_keys" => [folder_share_key_attrs(added_document)],
                 "replace_keys" => [
                   %{
                     "share_id" => child_share_without_key.id,
                     "document_id" => replace_document.id,
                     "encrypted_dek" => :crypto.strong_rand_bytes(32),
                     "nonce" => nil
                   }
                 ]
               }
             )

    refute Repo.get_by(Share, parent_share_id: created.share.id, document_id: added_document.id)
  end

  test "folder share key update rejects unreachable nested additions", %{
    folder: folder,
    owner_id: owner_id
  } do
    assert {:ok, created} =
             Sharing.create_share(folder, owner_id, create_folder_share_attrs([]))

    child_folder = create_folder(folder.workspace_id, owner_id, folder.id)
    nested_document = create_document(folder.workspace_id, owner_id, child_folder.id)

    assert {:error, {:invalid_value, :add_keys}} =
             Sharing.update_share_keys(
               folder.id,
               created.share.id,
               created.share_manage_token,
               %{"add_keys" => [folder_share_key_attrs(nested_document)]}
             )

    refute Repo.get_by(Share, parent_share_id: created.share.id, document_id: nested_document.id)
  end

  test "folder share key update rejects paths through mismatched child share scopes", %{
    folder: folder,
    owner_id: owner_id
  } do
    assert {:ok, created} =
             Sharing.create_share(folder, owner_id, create_folder_share_attrs([]))

    child_folder = create_folder(folder.workspace_id, owner_id, folder.id)
    nested_document = create_document(folder.workspace_id, owner_id, child_folder.id)

    insert_child_share_without_key!(created.share, child_folder, owner_id, scope: "document")

    assert {:error, {:invalid_value, :add_keys}} =
             Sharing.update_share_keys(
               folder.id,
               created.share.id,
               created.share_manage_token,
               %{"add_keys" => [folder_share_key_attrs(nested_document)]}
             )
  end

  test "folder share key update rejects paths through incomplete child shares", %{
    folder: folder,
    owner_id: owner_id
  } do
    assert {:ok, created} =
             Sharing.create_share(folder, owner_id, create_folder_share_attrs([]))

    child_folder = create_folder(folder.workspace_id, owner_id, folder.id)
    nested_document = create_document(folder.workspace_id, owner_id, child_folder.id)

    insert_child_share_without_key!(created.share, child_folder, owner_id, scope: "folder")

    assert {:error, {:invalid_value, :add_keys}} =
             Sharing.update_share_keys(
               folder.id,
               created.share.id,
               created.share_manage_token,
               %{"add_keys" => [folder_share_key_attrs(nested_document)]}
             )
  end

  test "folder share key update rejects add and replace collisions", %{
    folder: folder,
    owner_id: owner_id
  } do
    existing_document = create_document(folder.workspace_id, owner_id, folder.id)

    assert {:ok, created} =
             Sharing.create_share(
               folder,
               owner_id,
               create_folder_share_attrs([existing_document])
             )

    child_share =
      Repo.get_by!(Share, parent_share_id: created.share.id, document_id: existing_document.id)

    new_document = create_document(folder.workspace_id, owner_id, folder.id)

    assert {:error, {:invalid_value, :add_keys}} =
             Sharing.update_share_keys(
               folder.id,
               created.share.id,
               created.share_manage_token,
               %{
                 "add_keys" => [
                   %{
                     "share_id" => child_share.id,
                     "document_id" => new_document.id,
                     "encrypted_dek" => :crypto.strong_rand_bytes(32),
                     "nonce" => nil
                   }
                 ]
               }
             )

    assert {:error, {:invalid_value, :add_keys}} =
             Sharing.update_share_keys(
               folder.id,
               created.share.id,
               created.share_manage_token,
               %{
                 "add_keys" => [
                   %{
                     "share_id" => child_share.id,
                     "document_id" => new_document.id,
                     "encrypted_dek" => :crypto.strong_rand_bytes(32),
                     "nonce" => nil
                   }
                 ],
                 "replace_keys" => [
                   %{
                     "share_id" => child_share.id,
                     "document_id" => existing_document.id,
                     "encrypted_dek" => :crypto.strong_rand_bytes(32),
                     "nonce" => nil
                   }
                 ]
               }
             )
  end

  test "folder share key update accepts empty update arrays", %{
    folder: folder,
    owner_id: owner_id
  } do
    assert {:ok, created} =
             Sharing.create_share(folder, owner_id, create_folder_share_attrs([]))

    assert {:ok, %{added: [], replaced: []}} =
             Sharing.update_share_keys(
               folder.id,
               created.share.id,
               created.share_manage_token,
               %{"add_keys" => [], "replace_keys" => []}
             )
  end

  test "folder share key update rejects excluded targets", %{
    folder: folder,
    owner_id: owner_id
  } do
    target_document = create_document(folder.workspace_id, owner_id, folder.id)

    assert {:ok, created} =
             Sharing.create_share(
               folder,
               owner_id,
               create_folder_share_attrs([], exclusions: [target_document.id])
             )

    assert {:error, {:invalid_value, :add_keys}} =
             Sharing.update_share_keys(
               folder.id,
               created.share.id,
               created.share_manage_token,
               %{"add_keys" => [folder_share_key_attrs(target_document)]}
             )

    refute Repo.get_by(Share, parent_share_id: created.share.id, document_id: target_document.id)
  end

  test "folder share access ignores stale child shares for excluded documents", %{
    folder: folder,
    owner_id: owner_id
  } do
    target_document = create_document(folder.workspace_id, owner_id, folder.id)

    assert {:ok, created} =
             Sharing.create_share(
               folder,
               owner_id,
               create_folder_share_attrs([target_document])
             )

    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    assert {:ok, bootstrapped} =
             Sharing.bootstrap_participant(created.share_slug, %{
               "display_name" => "Guest User",
               "device_signing_pub_key" => valid_signing_public_key(),
               "device_encryption_pub_key" => valid_encryption_public_key()
             })

    session_token = Base.url_encode64(bootstrapped.session_token, padding: false)

    assert {:ok, folder_bootstrap} =
             Sharing.get_folder_bootstrap(landing.root.folder_token, session_token)

    target_entry = Enum.find(folder_bootstrap.entries, &(&1.id == target_document.id))
    assert is_binary(target_entry.document_token)

    Repo.insert!(
      ShareExclusion.changeset(%ShareExclusion{}, %{
        share_id: created.share.id,
        document_id: target_document.id
      })
    )

    refute Sharing.can_read_document?(created.share.id, target_document.id)

    assert {:error, :not_found} =
             Sharing.get_document_bootstrap(target_entry.document_token, session_token)

    assert {:ok, updated_bootstrap} =
             Sharing.get_folder_bootstrap(landing.root.folder_token, session_token)

    refute Enum.any?(updated_bootstrap.entries, &(&1.id == target_document.id))
  end

  test "folder share key update rejects existing child shares", %{
    folder: folder,
    owner_id: owner_id
  } do
    target_document = create_document(folder.workspace_id, owner_id, folder.id)

    assert {:ok, created} =
             Sharing.create_share(
               folder,
               owner_id,
               create_folder_share_attrs([target_document])
             )

    assert {:error, {:invalid_value, :add_keys}} =
             Sharing.update_share_keys(
               folder.id,
               created.share.id,
               created.share_manage_token,
               %{"add_keys" => [folder_share_key_attrs(target_document)]}
             )
  end

  test "child share uniqueness is enforced by the database", %{
    folder: folder,
    owner_id: owner_id
  } do
    target_document = create_document(folder.workspace_id, owner_id, folder.id)

    assert {:ok, created} =
             Sharing.create_share(
               folder,
               owner_id,
               create_folder_share_attrs([target_document])
             )

    assert {:error, changeset} =
             %Share{}
             |> Share.changeset(%{
               id: Ecto.UUID.generate(),
               document_id: target_document.id,
               parent_share_id: created.share.id,
               scope: "document",
               token_hash: Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
               token_prefix: "test",
               slug_ciphertext: :crypto.strong_rand_bytes(32),
               slug_nonce: :crypto.strong_rand_bytes(12),
               slug_key_id: "test",
               permission: "view",
               password_protected: false,
               access_count: 0,
               created_by: owner_id
             })
             |> Repo.insert()

    assert {"has already been taken", _meta} = changeset.errors[:parent_share_id]
  end

  test "folder share key update rejects document shares", %{
    document: document,
    owner_id: owner_id
  } do
    assert {:ok, created} = Sharing.create_share(document, owner_id, create_share_attrs())

    assert {:error, {:invalid_value, :scope}} =
             Sharing.update_share_keys(
               document.id,
               created.share.id,
               created.share_manage_token,
               %{"add_keys" => [folder_share_key_attrs(document)]}
             )
  end

  test "folder share exclusion update accepts combined add and remove", %{
    folder: folder,
    owner_id: owner_id
  } do
    target_document = create_document(folder.workspace_id, owner_id, folder.id)
    restored_document = create_document(folder.workspace_id, owner_id, folder.id)

    assert {:ok, created} =
             Sharing.create_share(
               folder,
               owner_id,
               create_folder_share_attrs([target_document], exclusions: [restored_document.id])
             )

    assert {:ok, result} =
             Sharing.update_share_exclusions(
               folder.id,
               created.share.id,
               created.share_manage_token,
               %{"add" => [target_document.id], "remove" => [restored_document.id]}
             )

    assert result.exclusions == [target_document.id]
  end

  test "folder share exclusion update rejects document shares", %{
    document: document,
    owner_id: owner_id
  } do
    assert {:ok, created} = Sharing.create_share(document, owner_id, create_share_attrs())

    assert {:error, {:invalid_value, :scope}} =
             Sharing.update_share_exclusions(
               document.id,
               created.share.id,
               created.share_manage_token,
               %{"add" => [document.id]}
             )
  end

  test "folder share exclusion update rejects non-descendant targets", %{
    folder: folder,
    owner_id: owner_id
  } do
    child_document = create_document(folder.workspace_id, owner_id, folder.id)
    outside_document = create_document(folder.workspace_id, owner_id)

    assert {:ok, created} =
             Sharing.create_share(folder, owner_id, create_folder_share_attrs([child_document]))

    assert {:error, {:invalid_value, :exclusions}} =
             Sharing.update_share_exclusions(
               folder.id,
               created.share.id,
               created.share_manage_token,
               %{"add" => [outside_document.id]}
             )
  end

  test "folder share creation rejects incomplete descendant keys", %{
    folder: folder,
    owner_id: owner_id
  } do
    shared_document = create_document(folder.workspace_id, owner_id, folder.id)
    omitted_document = create_document(folder.workspace_id, owner_id, folder.id)

    attrs = create_folder_share_attrs([shared_document])

    assert {:error, {:invalid_value, :share_keys}} =
             Sharing.create_share(folder, owner_id, attrs)

    assert is_binary(omitted_document.id)
  end

  test "password-protected folder shares create child shares and complete challenge flow", %{
    folder: folder,
    owner_id: owner_id
  } do
    child_document = create_document(folder.workspace_id, owner_id, folder.id)
    auth_key = :crypto.strong_rand_bytes(32)

    attrs =
      create_folder_share_attrs([child_document],
        password_protected: true,
        salt: :crypto.strong_rand_bytes(16),
        kdf_params: %{
          "algorithm" => "argon2id",
          "memory" => 65_536,
          "iterations" => 3,
          "parallelism" => 4,
          "hash_length" => 32
        },
        auth_key: auth_key
      )

    assert {:ok, created} = Sharing.create_share(folder, owner_id, attrs)
    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    assert {:ok, challenge} = Sharing.get_password_challenge(created.share_slug)

    participant = %{
      "display_name" => "Guest User",
      "device_signing_pub_key" => valid_signing_public_key(),
      "device_encryption_pub_key" => valid_encryption_public_key()
    }

    response = :crypto.mac(:hmac, :sha256, auth_key, challenge.challenge)

    assert {:ok, bootstrapped} =
             Sharing.respond_password_challenge(
               created.share_slug,
               Map.put(participant, "response", response)
             )

    session_token_base64 = Base.url_encode64(bootstrapped.session_token, padding: false)

    assert {:ok, folder_bootstrap} =
             Sharing.get_folder_bootstrap(landing.root.folder_token, session_token_base64)

    assert folder_bootstrap.password_protected == true

    child_entry = Enum.find(folder_bootstrap.entries, &(&1.id == child_document.id))
    assert is_binary(child_entry.share_id)
    assert is_binary(child_entry.document_token)

    assert {:ok, canonical} =
             Sharing.get_document_bootstrap(child_entry.document_token, session_token_base64)

    assert canonical.password_protected == true
    assert canonical.document_id == child_document.id
    assert canonical.share_id == child_entry.share_id
  end

  test "access_limit share keeps the admitted session alive but blocks new admissions", %{
    document: document,
    owner_id: owner_id
  } do
    attrs = create_share_attrs(access_limit: 1)
    assert {:ok, created} = Sharing.create_share(document, owner_id, attrs)
    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    participant = %{
      "display_name" => "Guest User",
      "device_signing_pub_key" => valid_signing_public_key(),
      "device_encryption_pub_key" => valid_encryption_public_key()
    }

    assert {:ok, bootstrapped} = Sharing.bootstrap_participant(created.share_slug, participant)

    session_token_base64 = Base.url_encode64(bootstrapped.session_token, padding: false)

    assert {:ok, canonical} =
             Sharing.get_document_bootstrap(landing.root.document_token, session_token_base64)

    assert canonical.document_id == document.id
    assert Sharing.can_read_document?(created.share.id, document.id)

    assert Sharing.can_join_document_session?(
             created.share.id,
             document.id,
             bootstrapped.session.id
           )

    assert Sharing.can_continue_document_session?(created.share.id, document.id)

    Sharing.touch_participant_session(bootstrapped.session.id)

    assert Sharing.can_join_document_session?(
             created.share.id,
             document.id,
             bootstrapped.session.id
           )

    assert Sharing.can_continue_document_session?(created.share.id, document.id)
    assert {:error, :not_found} = Sharing.bootstrap_participant(created.share_slug, participant)
    assert {:error, :not_found} = Sharing.get_share_landing(created.share_slug)
  end

  test "list_document_shares/3 filters non-admin users to their own shares", %{
    workspace: workspace,
    document: document,
    owner_id: owner_id,
    owner_role: owner_role
  } do
    editor_id = create_user("editor@example.com")

    editor_role =
      Repo.one!(
        from(r in WorkspaceRole,
          where: r.workspace_id == ^workspace.id and r.base_role == "editor"
        )
      )

    Repo.insert!(%WorkspaceMember{
      workspace_id: workspace.id,
      user_id: editor_id,
      role_id: editor_role.id,
      joined_at: DateTime.utc_now()
    })

    {:ok, owner_share} = Sharing.create_share(document, owner_id, create_share_attrs())
    {:ok, editor_share} = Sharing.create_share(document, editor_id, create_share_attrs())

    owner_visible = Sharing.list_document_shares(document, owner_id, owner_role)
    editor_visible = Sharing.list_document_shares(document, editor_id, editor_role)

    assert Enum.any?(owner_visible, &(&1.id == owner_share.share.id))
    assert Enum.any?(owner_visible, &(&1.id == editor_share.share.id))
    assert Enum.any?(editor_visible, &(&1.id == editor_share.share.id))
    refute Enum.any?(editor_visible, &(&1.id == owner_share.share.id))
  end

  test "list_document_shares/3 includes restorable share slugs", %{
    document: document,
    owner_id: owner_id,
    owner_role: owner_role
  } do
    {:ok, created} = Sharing.create_share(document, owner_id, create_share_attrs())

    shares = Sharing.list_document_shares(document, owner_id, owner_role)

    assert Enum.any?(shares, &(&1.id == created.share.id and &1.share_slug == created.share_slug))
  end
end
