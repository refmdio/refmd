defmodule RefMD.Sharing.SharingTest do
  use RefMD.DataCase, async: true

  alias RefMD.Crypto.{Blake3, JCS, Signature}
  alias RefMD.Documents
  alias RefMD.Documents.{Document, DocumentSnapshot, DocumentUpdate}
  alias RefMD.Repo
  alias RefMD.Sharing

  alias RefMD.Sharing.{Share, ShareExclusion, ShareKey, SharePasswordChallenge}

  alias RefMD.Users.User
  alias RefMD.Workspaces

  alias RefMD.Workspaces.{WorkspaceMember, WorkspaceRole}

  defp workspace_pin_bootstrap_hash,
    do: Process.get(:workspace_pin_bootstrap_hash, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

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

  defp test_hybrid_signature do
    %{
      "protocol" => "refmd.hybrid-signature",
      "suite_id" => "refmd-test-suite",
      "suite_rank" => 1000,
      "version" => 1,
      "signing_key_id" => "test-signing-key",
      "transcript_hash" => Blake3.hash_base64url("test-transcript"),
      "ed25519" => Blake3.hash_base64url("test-ed25519"),
      "mldsa65" => Blake3.hash_base64url("test-mldsa65")
    }
  end

  defp insert_active_snapshot_with_updates!(document, updates) do
    now = DateTime.utc_now()
    snapshot_id = Ecto.UUID.generate()
    key_checkpoint_hash = Blake3.hash_base64url("test-checkpoint")
    authority_context_key = "test-authority-context"
    signing_key_id = "test-signing-key"
    clock_key = "#{authority_context_key}:#{signing_key_id}"

    snapshot =
      Repo.insert!(%DocumentSnapshot{
        id: snapshot_id,
        document_id: document.id,
        latest_version: length(updates),
        data: <<1, 2, 3>>,
        nonce: :crypto.strong_rand_bytes(24),
        key_version: 1,
        hybrid_signature: test_hybrid_signature(),
        ciphertext_hash: Blake3.hash_base64url("snapshot-ciphertext:#{snapshot_id}"),
        snapshot_signature_hash: Blake3.hash_base64url("snapshot-signature:#{snapshot_id}"),
        snapshot_admission_event_hash: Blake3.hash_base64url("snapshot-admission:#{snapshot_id}"),
        proof_chain_hash: Blake3.hash_base64url("snapshot-proof:#{snapshot_id}"),
        clocks: %{clock_key => max_update_clock(updates)},
        parent_snapshot_update_clocks: %{},
        parent_proof_hash: "GENESIS",
        created_by_signing_key_id: signing_key_id,
        owner_kind: "device",
        owner_id: "test-device",
        authority_kind: "workspace_device",
        authority_id: document.workspace_id,
        authority_context_key: authority_context_key,
        authority_scope_id: document.workspace_id,
        authority_permission_version: 1,
        key_checkpoint_sequence: 1,
        key_checkpoint_hash: key_checkpoint_hash,
        created_at: now
      })

    inserted_updates =
      updates
      |> Enum.with_index(1)
      |> Enum.map(fn {clock, version} ->
        Repo.insert!(%DocumentUpdate{
          document_id: document.id,
          snapshot_id: snapshot.id,
          clock: clock,
          version: version,
          signing_key_id: signing_key_id,
          update_data: <<version>>,
          nonce: :crypto.strong_rand_bytes(24),
          key_version: 1,
          update_hash: Blake3.hash_base64url("update:#{snapshot.id}:#{version}"),
          hybrid_signature: test_hybrid_signature(),
          owner_kind: "device",
          owner_id: "test-device",
          authority_kind: "workspace_device",
          authority_id: document.workspace_id,
          authority_context_key: authority_context_key,
          authority_scope_id: document.workspace_id,
          authority_permission_version: 1,
          key_checkpoint_sequence: 1,
          key_checkpoint_hash: key_checkpoint_hash,
          admission_event_hash:
            Blake3.hash_base64url("update-admission:#{snapshot.id}:#{version}"),
          write_session_counter: version,
          timestamp: DateTime.to_unix(now, :millisecond),
          created_at: now
        })
      end)

    Repo.update_all(
      from(d in Document, where: d.id == ^document.id),
      set: [active_snapshot_id: snapshot.id]
    )

    {snapshot, inserted_updates, clock_key}
  end

  defp max_update_clock([]), do: -1
  defp max_update_clock(updates), do: Enum.max(updates)

  defp create_share_attrs(opts \\ []) do
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    %{
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
      "max_views" => Keyword.get(opts, :max_views),
      "expires_event_sequence" => Keyword.get(opts, :expires_event_sequence)
    }
  end

  defp create_password_protected_share_attrs(opts) do
    auth_key = Keyword.get(opts, :auth_key, :crypto.strong_rand_bytes(32))
    attrs = create_share_attrs(opts)

    attrs
    |> Map.merge(%{
      "password_protected" => true,
      "authorization_public_key_material" =>
        share_capability_public_key_material_for_slug(auth_key, attrs["share_slug"]),
      "auth_key" => auth_key,
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
    })
  end

  defp create_share(document, owner_id, attrs) do
    Sharing.create_share(
      document,
      owner_id,
      with_test_share_security_artifacts(document, owner_id, attrs)
    )
  end

  defp delete_share(document_id, share_id) do
    share = Repo.get!(Share, share_id)

    Sharing.delete_share(
      document_id,
      share_id,
      with_test_share_management_append(share, "share_revoked")
    )
  end

  defp update_share_exclusions(document_id, share_id, attrs) do
    share = Repo.get!(Share, share_id)

    Sharing.update_share_exclusions(
      document_id,
      share_id,
      with_test_share_management_append(share, "share_exclusion_changed", attrs)
    )
  end

  defp update_share_keys(document_id, share_id, attrs) do
    share = Repo.get!(Share, share_id)

    Sharing.update_share_keys(
      document_id,
      share_id,
      with_test_share_scope_key_directory_append(share, attrs)
    )
  end

  defp valid_encryption_public_key do
    key = :crypto.strong_rand_bytes(32)
    if RefMD.Crypto.valid_x25519_public_key?(key), do: key, else: valid_encryption_public_key()
  end

  defp valid_share_participant_device_attrs(attrs) do
    device_id = Ecto.UUID.generate()
    private = hybrid_signing_private_key_material("share_participant_device", device_id)
    public = hybrid_signing_public_key_material(private)
    encryption_public_key = valid_encryption_public_key()

    encryption =
      hybrid_encryption_public_key_material(
        "share_participant_device",
        device_id,
        encryption_public_key
      )

    Map.merge(
      %{
        "share_participant_principal_id" => Ecto.UUID.generate(),
        "share_participant_device_id" => device_id,
        "share_participant_session_id" => Ecto.UUID.generate(),
        "__share_participant_private_material" => private,
        "hybrid_signing_public_key_material" => public,
        "hybrid_encryption_public_key_material" => encryption.public
      },
      attrs
    )
  end

  defp respond_share_password_challenge(created, attrs, authorization_secret) do
    attrs = attach_share_participant_device_authorization(attrs, created, authorization_secret)

    case Sharing.respond_password_challenge(created.share_slug, attrs) do
      {:ok, bootstrapped} ->
        {:ok, bootstrapped}

      other ->
        other
    end
  end

  defp share_password_challenge_response(auth_key, %{challenge: challenge}) do
    :crypto.mac(:hmac, :sha256, auth_key, challenge)
  end

  defp password_challenge_hash(share_slug) do
    share_slug
    |> Base.url_decode64!(padding: false)
    |> Blake3.hash_base64url()
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

    device
  end

  defp insert_document_signer!(attrs) do
    now = DateTime.utc_now()
    document = Documents.get_document(attrs.document_id)
    authority = document_signer_authority(attrs, document)

    Repo.insert_all(RefMD.Documents.DocumentSignerKey, [
      %{
        document_id: attrs.document_id,
        authority_kind: authority.kind,
        authority_id: authority.id,
        authority_context_key: authority.context_key,
        authority_scope_id: authority.scope_id,
        authority_permission_version: 1,
        key_checkpoint_sequence: 1,
        key_checkpoint_hash: Blake3.hash_base64url("test-key-checkpoint"),
        owner_kind: document_signer_owner_kind(attrs),
        owner_id: attrs.device_id,
        hybrid_signing_public_key_material: attrs.hybrid_signing_public_key_material,
        signing_key_id:
          Signature.compute_signing_key_id!(attrs.hybrid_signing_public_key_material),
        first_seen_at: now,
        last_seen_at: now
      }
    ])
  end

  defp document_signer_authority(%{signer_kind: "workspace"} = attrs, document) do
    %{
      kind: "workspace_device",
      id: document.workspace_id,
      context_key: attrs.device_id,
      scope_id: document.workspace_id
    }
  end

  defp document_signer_authority(%{signer_kind: "share_participant"} = attrs, document) do
    %{
      kind: "share_participant_device",
      id: attrs.share_id,
      context_key: "#{attrs.share_id}:#{attrs.principal_id}",
      scope_id: document.id
    }
  end

  defp document_signer_owner_kind(%{signer_kind: "share_participant"}),
    do: "share_participant_device"

  defp document_signer_owner_kind(_attrs), do: "device"

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
      "authorization_public_key_material" =>
        share_capability_public_key_material_for_slug(
          Keyword.get(opts, :auth_key, open_admission_key()),
          share_slug
        ),
      "share_capability_secret_commitment" => open_share_capability_secret_commitment(),
      "authenticated_workspace_pin_bootstrap_hash" => workspace_pin_bootstrap_hash(),
      "encrypted_dek" => :crypto.strong_rand_bytes(48),
      "nonce" => :crypto.strong_rand_bytes(24),
      "share_keys" => Enum.map(nodes, &folder_share_key_attrs(&1, password_protected)),
      "salt" => Keyword.get(opts, :salt),
      "auth_key" => Keyword.get(opts, :auth_key),
      "kdf_params" => Keyword.get(opts, :kdf_params),
      "exclusions" => Keyword.get(opts, :exclusions)
    }
  end

  defp folder_share_key_attrs(document, _password_protected \\ false) do
    %{
      "share_id" => Ecto.UUID.generate(),
      "document_id" => document.id,
      "encrypted_dek" => :crypto.strong_rand_bytes(48),
      "nonce" => :crypto.strong_rand_bytes(24)
    }
  end

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
        permission: "view",
        password_protected: false,
        authorization_public_key_material: nil,
        share_capability_secret_commitment: root_share.share_capability_secret_commitment,
        password_capability_secret_commitment: root_share.password_capability_secret_commitment,
        capability_context_hash: root_share.capability_context_hash,
        created_event_hash: root_share.created_event_hash,
        authenticated_workspace_pin_bootstrap_hash:
          root_share.authenticated_workspace_pin_bootstrap_hash,
        authenticated_workspace_pin_bootstrap_checkpoint:
          root_share.authenticated_workspace_pin_bootstrap_checkpoint,
        max_views: root_share.max_views,
        expires_event_sequence: root_share.expires_event_sequence,
        view_count: 0,
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
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)
    Process.put(:workspace_pin_bootstrap_hash, test_workspace_pin_bootstrap_hash!(workspace.id))
    signer = Process.get({:test_workspace_signer_material, workspace.id})

    %{
      owner_id: owner_id,
      workspace: workspace,
      document: document,
      folder: folder,
      owner_role: role,
      signer: signer
    }
  end

  defp archive_for_test(document, owner_id, signer) do
    append =
      document_write_state_key_directory_append(
        document.workspace_id,
        owner_id,
        signer.device_id,
        signer.signing_private,
        [
          %{document_id: document.id, previous_write_state: "writable", write_state: "archived"}
        ],
        "archive"
      )

    {:ok, admission} = Documents.WriteStateAdmission.parse_append(append)
    Documents.archive_document(document, admission)
  end

  test "create_share/3 creates a landing share and canonical token", %{
    document: document,
    owner_id: owner_id
  } do
    attrs = create_share_attrs()

    assert {:ok, result} = create_share(document, owner_id, attrs)
    assert result.share.document_id == document.id
    assert result.share.permission == attrs["permission"]
    assert result.share_slug == attrs["share_slug"]

    assert {:ok, landing} = Sharing.get_share_landing(attrs["share_slug"])
    assert landing.share.id == result.share.id
    assert landing.root.kind == "document"
    assert is_binary(landing.root.document_token)
  end

  test "create_share/3 rejects share capability material with the wrong owner id", %{
    document: document,
    owner_id: owner_id
  } do
    attrs = create_share_attrs()

    invalid_material =
      attrs["authorization_public_key_material"]
      |> Map.put("owner_id", Blake3.hash_base64url("wrong-share-token"))

    assert {:error, {:invalid_public_key, :authorization_public_key_material}} =
             create_share(
               document,
               owner_id,
               Map.put(attrs, "authorization_public_key_material", invalid_material)
             )
  end

  test "root share changeset rejects authorization material that does not match token_hash", %{
    document: document,
    owner_id: owner_id
  } do
    token_hash = Blake3.hash_base64url("root-share-token")
    material = share_capability_public_key_material(open_admission_key(), token_hash)

    assert %{valid?: true} =
             Share.changeset(%Share{}, %{
               id: Ecto.UUID.generate(),
               document_id: document.id,
               scope: "document",
               token_hash: token_hash,
               token_prefix: "abcd",
               permission: "view",
               password_protected: false,
               authorization_public_key_material: material,
               share_capability_secret_commitment: open_share_capability_secret_commitment(),
               password_capability_secret_commitment: "none",
               capability_context_hash: Blake3.hash_base64url("capability-context"),
               created_event_hash: Blake3.hash_base64url("created-event"),
               authenticated_workspace_pin_bootstrap_hash: workspace_pin_bootstrap_hash(),
               authenticated_workspace_pin_bootstrap_checkpoint: %{},
               max_views: 9_007_199_254_740_991,
               expires_event_sequence: 9_007_199_254_740_991,
               view_count: 0,
               created_by: owner_id
             })

    invalid_material = Map.put(material, "owner_id", Blake3.hash_base64url("other-share-token"))

    assert %{valid?: false, errors: errors} =
             Share.changeset(%Share{}, %{
               id: Ecto.UUID.generate(),
               document_id: document.id,
               scope: "document",
               token_hash: token_hash,
               token_prefix: "abcd",
               permission: "view",
               password_protected: false,
               authorization_public_key_material: invalid_material,
               share_capability_secret_commitment: open_share_capability_secret_commitment(),
               password_capability_secret_commitment: "none",
               capability_context_hash: Blake3.hash_base64url("capability-context"),
               created_event_hash: Blake3.hash_base64url("created-event"),
               authenticated_workspace_pin_bootstrap_hash: workspace_pin_bootstrap_hash(),
               authenticated_workspace_pin_bootstrap_checkpoint: %{},
               max_views: 9_007_199_254_740_991,
               expires_event_sequence: 9_007_199_254_740_991,
               view_count: 0,
               created_by: owner_id
             })

    assert {"is invalid", _meta} = errors[:authorization_public_key_material]
  end

  test "child share changeset rejects root share capability public material", %{
    document: document,
    folder: folder,
    owner_id: owner_id
  } do
    assert {:ok, created} =
             create_share(
               folder,
               owner_id,
               create_folder_share_attrs([])
             )

    child_token_hash = Blake3.hash_base64url("child-share-token")

    assert %{valid?: true} =
             Share.changeset(%Share{}, %{
               id: Ecto.UUID.generate(),
               document_id: document.id,
               parent_share_id: created.share.id,
               scope: "document",
               token_hash: child_token_hash,
               token_prefix: "abcd",
               permission: "view",
               password_protected: false,
               authorization_public_key_material: nil,
               share_capability_secret_commitment:
                 created.share.share_capability_secret_commitment,
               password_capability_secret_commitment:
                 created.share.password_capability_secret_commitment,
               capability_context_hash: created.share.capability_context_hash,
               created_event_hash: created.share.created_event_hash,
               authenticated_workspace_pin_bootstrap_hash:
                 created.share.authenticated_workspace_pin_bootstrap_hash,
               authenticated_workspace_pin_bootstrap_checkpoint:
                 created.share.authenticated_workspace_pin_bootstrap_checkpoint,
               max_views: created.share.max_views,
               expires_event_sequence: created.share.expires_event_sequence,
               view_count: 0,
               created_by: owner_id
             })

    assert %{valid?: false, errors: errors} =
             Share.changeset(%Share{}, %{
               id: Ecto.UUID.generate(),
               document_id: document.id,
               parent_share_id: created.share.id,
               scope: "document",
               token_hash: child_token_hash,
               token_prefix: "abcd",
               permission: "view",
               password_protected: false,
               authorization_public_key_material: created.share.authorization_public_key_material,
               share_capability_secret_commitment:
                 created.share.share_capability_secret_commitment,
               password_capability_secret_commitment:
                 created.share.password_capability_secret_commitment,
               capability_context_hash: created.share.capability_context_hash,
               created_event_hash: created.share.created_event_hash,
               authenticated_workspace_pin_bootstrap_hash:
                 created.share.authenticated_workspace_pin_bootstrap_hash,
               authenticated_workspace_pin_bootstrap_checkpoint:
                 created.share.authenticated_workspace_pin_bootstrap_checkpoint,
               max_views: created.share.max_views,
               expires_event_sequence: created.share.expires_event_sequence,
               view_count: 0,
               created_by: owner_id
             })

    assert {"is invalid", _meta} = errors[:authorization_public_key_material]
  end

  test "share_created key directory body rejects non share-capability authorization material" do
    material =
      share_capability_public_key_material(open_admission_key(), Blake3.hash_base64url("share"))
      |> Map.put("owner_kind", "device")
      |> Map.put("owner_id", Ecto.UUID.generate())

    body = %{
      "workspace_id" => Ecto.UUID.generate(),
      "share_id" => Ecto.UUID.generate(),
      "scope_kind" => "document",
      "scope_id" => Ecto.UUID.generate(),
      "permission" => "view",
      "share_key_version" => 1,
      "password_protected" => false,
      "authorization_public_key_material" => material,
      "authorization_public_key_material_hash" =>
        Blake3.hash_base64url(JCS.canonical_bytes!(material)),
      "share_capability_secret_commitment" => Blake3.hash_base64url("share-capability"),
      "password_capability_secret_commitment" => "none",
      "password_auth_metadata_hash" => "none",
      "max_views" => 9_007_199_254_740_991,
      "expires_event_sequence" => 9_007_199_254_740_991,
      "redeem_authority_policy" => "capability_url",
      "capability_context_hash" => Blake3.hash_base64url("capability-context")
    }

    assert_raise ArgumentError, "authorization_public_key_material_owner_kind_invalid", fn ->
      RefMD.Encryption.KeyDirectory.Share.assert!("share_created", body)
    end
  end

  test "create_share/3 rejects archived root documents", %{
    document: document,
    owner_id: owner_id,
    signer: signer
  } do
    assert {:ok, archived_document} = archive_for_test(document, owner_id, signer)

    assert {:error, {:invalid_value, :document_id}} =
             create_share(archived_document, owner_id, create_share_attrs())
  end

  test "create_share/3 rejects archived root folders", %{
    folder: folder,
    owner_id: owner_id,
    signer: signer
  } do
    assert {:ok, archived_folder} = archive_for_test(folder, owner_id, signer)

    assert {:error, {:invalid_value, :document_id}} =
             create_share(archived_folder, owner_id, create_folder_share_attrs([]))
  end

  test "create_share/3 accepts max_views on edit shares", %{
    document: document,
    owner_id: owner_id
  } do
    assert {:ok, result} =
             create_share(
               document,
               owner_id,
               create_share_attrs(permission: "edit", max_views: 1)
             )

    assert result.share.permission == "edit"
    assert result.share.max_views == 1
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
             create_share(document, owner_id, attrs)
  end

  test "create_share/3 rejects missing nonce on shares", %{document: document, owner_id: owner_id} do
    attrs = Map.put(create_share_attrs(), "nonce", nil)

    assert {:error, :invalid_nonce} = create_share(document, owner_id, attrs)
  end

  test "bootstrap_participant/2 issues a share session and canonical bootstrap", %{
    document: document,
    owner_id: owner_id
  } do
    attrs = create_share_attrs(permission: "edit")
    assert {:ok, created} = create_share(document, owner_id, attrs)

    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    participant = valid_share_participant_device_attrs(%{"display_name" => "Guest User"})

    assert {:ok, bootstrapped} = bootstrap_share_participant(created, participant)
    assert bootstrapped.root.document_token == landing.root.document_token
    assert bootstrapped.participant.grant == "edit"
    assert bootstrapped.session.grant == "edit"
    assert bootstrapped.root_document_bootstrap.share_id == created.share.id
    assert bootstrapped.root_document_bootstrap.document_id == document.id
    assert bootstrapped.root_document_bootstrap.permission == "edit"
    assert bootstrapped.root_document_bootstrap.share_token_hash == created.share.token_hash

    session_token_base64 = Base.url_encode64(bootstrapped.session_token, padding: false)

    created.share
    |> Ecto.Changeset.change(permission: "view")
    |> Repo.update!()

    assert {:ok, canonical} =
             Sharing.get_document_bootstrap(
               landing.root.document_token,
               session_token_base64,
               workspace_pin_bootstrap_hash()
             )

    assert canonical.share_id == created.share.id
    assert canonical.document_id == document.id
    assert canonical.permission == "edit"
    assert canonical.share_token_hash == created.share.token_hash
    assert is_binary(canonical.encrypted_dek)
    assert byte_size(canonical.nonce) == 24
  end

  test "bootstrap_participant/2 requires share capability authorization", %{
    document: document,
    owner_id: owner_id
  } do
    assert {:ok, created} = create_share(document, owner_id, create_share_attrs())

    attrs =
      %{"display_name" => "Guest User"}
      |> valid_share_participant_device_attrs()
      |> attach_share_participant_device_authorization(created)
      |> Map.delete("share_capability_authorization")

    assert {:error, {:missing_field, :share_capability_authorization}} =
             Sharing.bootstrap_participant(created.share_slug, attrs)
  end

  test "bootstrap_participant/2 rejects capability authorization from wrong secret", %{
    document: document,
    owner_id: owner_id
  } do
    assert {:ok, created} = create_share(document, owner_id, create_share_attrs())

    attrs =
      %{"display_name" => "Guest User"}
      |> valid_share_participant_device_attrs()
      |> attach_share_participant_device_authorization(created)
      |> put_in(
        ["share_capability_authorization", "signature", "ed25519"],
        Base.url_encode64(<<0::512>>, padding: false)
      )

    assert {:error, :invalid_share_capability_authorization} =
             Sharing.bootstrap_participant(created.share_slug, attrs)
  end

  test "bootstrap_participant/2 coalesces root document bootstrap and records the open once", %{
    document: document,
    owner_id: owner_id
  } do
    assert {:ok, created} =
             create_share(document, owner_id, create_share_attrs(max_views: 1))

    participant =
      %{"display_name" => "Guest User"}
      |> valid_share_participant_device_attrs()

    assert {:ok, bootstrapped} = bootstrap_share_participant(created, participant)

    assert bootstrapped.participant.device_id == participant["share_participant_device_id"]
    assert bootstrapped.root_document_bootstrap.document_id == document.id
    assert %{view_count: 1} = Repo.get!(Share, created.share.id)

    session_token_base64 = Base.url_encode64(bootstrapped.session_token, padding: false)

    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug, session_token_base64)

    assert {:ok, _canonical} =
             Sharing.get_document_bootstrap(
               landing.root.document_token,
               session_token_base64,
               workspace_pin_bootstrap_hash()
             )

    assert %{view_count: 1} = Repo.get!(Share, created.share.id)
  end

  test "bootstrap_participant/2 rejects share participant device id reuse", %{
    document: document,
    owner_id: owner_id
  } do
    assert {:ok, created} = create_share(document, owner_id, create_share_attrs(max_views: 2))

    participant =
      %{"display_name" => "Guest User"}
      |> valid_share_participant_device_attrs()

    assert {:ok, _bootstrapped} = bootstrap_share_participant(created, participant)

    assert {:error, :participant_device_id_reused} =
             bootstrap_share_participant(created, participant)
  end

  test "max_views root document bootstrap records open and reserves further admission",
       %{
         document: document,
         owner_id: owner_id
       } do
    assert {:ok, created} =
             create_share(document, owner_id, create_share_attrs(max_views: 1))

    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    first_participant = valid_share_participant_device_attrs(%{"display_name" => "First Guest"})
    second_participant = valid_share_participant_device_attrs(%{"display_name" => "Second Guest"})

    assert {:ok, first_bootstrapped} = bootstrap_share_participant(created, first_participant)
    assert first_bootstrapped.root_document_bootstrap.document_id == document.id
    assert %{view_count: 1} = Repo.get!(Share, created.share.id)
    assert {:error, :not_found} = bootstrap_share_participant(created, second_participant)

    assert {:ok, first_canonical} =
             Sharing.get_document_bootstrap(
               landing.root.document_token,
               Base.url_encode64(first_bootstrapped.session_token, padding: false),
               workspace_pin_bootstrap_hash()
             )

    assert first_canonical.document_id == document.id
    assert %{view_count: 1} = Repo.get!(Share, created.share.id)

    assert {:ok, resumed_first_canonical} =
             Sharing.get_document_bootstrap(
               landing.root.document_token,
               Base.url_encode64(first_bootstrapped.session_token, padding: false),
               workspace_pin_bootstrap_hash()
             )

    assert resumed_first_canonical.document_id == document.id
    assert %{view_count: 1} = Repo.get!(Share, created.share.id)

    third_participant =
      %{"display_name" => "Third Guest"}
      |> valid_share_participant_device_attrs()

    assert {:error, :not_found} = bootstrap_share_participant(created, third_participant)
    assert {:error, :not_found} = bootstrap_share_participant(created, first_participant)
  end

  test "document share participant verification directory exposes edit participant devices only",
       %{
         document: document,
         owner_id: owner_id
       } do
    assert {:ok, view_share} =
             create_share(document, owner_id, create_share_attrs(permission: "view"))

    view_participant = valid_share_participant_device_attrs(%{"display_name" => "View Guest"})

    assert {:ok, _view_bootstrap} = bootstrap_share_participant(view_share, view_participant)

    assert {:ok, edit_share} =
             create_share(document, owner_id, create_share_attrs(permission: "edit"))

    assert {:ok, edit_bootstrap} =
             bootstrap_share_participant(
               edit_share,
               valid_share_participant_device_attrs(%{"display_name" => "Edit Guest"})
             )

    directory = Sharing.document_share_participant_verification_directory(document.id)

    assert Enum.any?(
             directory.share_participant_devices,
             &(&1.device_id == edit_bootstrap.participant.device_id and
                 &1.share_id == edit_share.share.id)
           )

    refute Enum.any?(
             directory.share_participant_devices,
             &(&1.signing_key_id ==
                 Signature.compute_signing_key_id!(
                   view_participant["hybrid_signing_public_key_material"]
                 ))
           )
  end

  test "document share participant verification directory includes folder share participants",
       %{
         folder: folder,
         owner_id: owner_id
       } do
    child_document = create_document(folder.workspace_id, owner_id, folder.id)

    assert {:ok, created} =
             create_share(
               folder,
               owner_id,
               create_folder_share_attrs([child_document], permission: "edit")
             )

    assert {:ok, bootstrapped} =
             bootstrap_share_participant(
               created,
               valid_share_participant_device_attrs(%{"display_name" => "Folder Guest"})
             )

    directory = Sharing.document_share_participant_verification_directory(child_document.id)

    assert Enum.any?(
             directory.share_participant_devices,
             &(&1.device_id == bootstrapped.participant.device_id and
                 &1.share_id == created.share.id)
           )
  end

  test "verification directories do not treat saved mount workspace devices as share participants",
       %{
         document: document,
         owner_id: owner_id
       } do
    mount_user_id = create_user("mounted-reader@example.com")

    {:ok, mount_workspace} =
      Workspaces.create_default_workspace(mount_user_id, "Mounted Workspace")

    mount_device = create_device(mount_user_id)

    assert {:ok, created} =
             create_share(document, owner_id, create_share_attrs(permission: "edit"))

    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    assert {:ok, _mount} =
             Sharing.create_share_mount(mount_user_id, %{
               "workspace_id" => mount_workspace.id,
               "share_slug" => created.share_slug,
               "target_kind" => "document",
               "target_token" => landing.root.document_token,
               "authenticated_workspace_pin_bootstrap_hash" =>
                 created.share.authenticated_workspace_pin_bootstrap_hash
             })

    directory = Sharing.verification_directory(created.share.id, document.id)

    refute Enum.any?(
             directory.share_participant_devices,
             &(&1.share_id == created.share.id and &1.principal_id == mount_user_id and
                 &1.device_id == mount_device.id)
           )

    document_directory = Sharing.document_share_participant_verification_directory(document.id)

    refute Enum.any?(
             document_directory.share_participant_devices,
             &(&1.share_id == created.share.id and &1.principal_id == mount_user_id and
                 &1.device_id == mount_device.id)
           )
  end

  test "verification directories keep historical share signer keys after share deletion", %{
    document: document,
    owner_id: owner_id
  } do
    participant = valid_share_participant_device_attrs(%{"display_name" => "Former Guest"})

    assert {:ok, created} =
             create_share(document, owner_id, create_share_attrs(permission: "edit"))

    assert {:ok, bootstrapped} =
             bootstrap_share_participant(created, participant)

    insert_document_signer!(%{
      document_id: document.id,
      signer_kind: "share_participant",
      share_id: created.share.id,
      principal_id: bootstrapped.participant.principal_id,
      device_id: bootstrapped.participant.device_id,
      hybrid_signing_public_key_material: participant["hybrid_signing_public_key_material"]
    })

    assert :ok = delete_share(document.id, created.share.id)

    directory = Sharing.document_share_participant_verification_directory(document.id)

    signing_key_id =
      Signature.compute_signing_key_id!(participant["hybrid_signing_public_key_material"])

    assert Enum.any?(
             directory.share_participant_devices,
             &(&1.signing_key_id == signing_key_id and
                 &1.device_id == bootstrapped.participant.device_id and
                 &1.historical == true and
                 is_nil(&1.display_name))
           )
  end

  test "verification directories keep historical workspace signer keys after device deletion", %{
    document: document,
    owner_id: owner_id
  } do
    assert {:ok, created} =
             create_share(document, owner_id, create_share_attrs(permission: "edit"))

    {%RefMD.Devices.Device{} = device, _private_material} =
      Process.get({:test_share_actor_device, owner_id})

    insert_document_signer!(%{
      document_id: document.id,
      signer_kind: "workspace",
      user_id: owner_id,
      device_id: device.id,
      hybrid_signing_public_key_material: device.hybrid_signing_public_key_material
    })

    Repo.delete!(device)

    directory = Sharing.verification_directory(created.share.id, document.id)
    signing_key_id = Signature.compute_signing_key_id!(device.hybrid_signing_public_key_material)

    assert Enum.any?(
             directory.workspace_devices,
             &(&1.signing_key_id == signing_key_id and &1.device_id == device.id and
                 &1.historical == true)
           )
  end

  test "canonical bootstrap requires re-entry when share session is missing", %{
    document: document,
    owner_id: owner_id
  } do
    attrs = create_share_attrs()
    assert {:ok, created} = create_share(document, owner_id, attrs)
    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    assert {:ok, response} = Sharing.get_document_bootstrap(landing.root.document_token, nil, nil)
    assert response.bootstrap_required == true
    assert response.share_token_hash == created.share.token_hash
  end

  test "password-protected share requires challenge flow before issuing a participant session", %{
    document: document,
    owner_id: owner_id
  } do
    auth_key = :crypto.strong_rand_bytes(32)
    attrs = create_password_protected_share_attrs(auth_key: auth_key)

    assert {:ok, created} = create_share(document, owner_id, attrs)
    assert created.share.password_protected

    share_key = Repo.get!(ShareKey, created.share.id)
    assert share_key.salt == attrs["salt"]
    assert share_key.kdf_params == attrs["kdf_params"]

    participant =
      %{"display_name" => "Guest User"}
      |> valid_share_participant_device_attrs()

    assert {:error, :password_required} =
             bootstrap_share_participant(created, participant, auth_key)

    assert {:ok, challenge} = Sharing.get_password_challenge(created.share_slug)
    assert challenge.salt == attrs["salt"]
    assert challenge.kdf_params == attrs["kdf_params"]

    assert {:ok, bootstrapped} =
             Sharing.respond_password_challenge(
               created.share_slug,
               participant
               |> Map.put("response", share_password_challenge_response(auth_key, challenge))
               |> Map.put("password_challenge_hash", password_challenge_hash(created.share_slug))
               |> attach_share_participant_device_authorization(created, auth_key)
             )

    session_token_base64 = Base.url_encode64(bootstrapped.session_token, padding: false)

    {:ok, landing} = Sharing.get_share_landing(created.share_slug, session_token_base64)

    assert {:ok, canonical} =
             Sharing.get_document_bootstrap(
               landing.root.document_token,
               session_token_base64,
               workspace_pin_bootstrap_hash()
             )

    assert canonical.password_protected == true
    assert canonical.share_id == created.share.id
    assert canonical.nonce == attrs["nonce"]
  end

  test "password challenge returns dummy values after max_views is reached", %{
    document: document,
    owner_id: owner_id
  } do
    auth_key = :crypto.strong_rand_bytes(32)
    attrs = create_password_protected_share_attrs(auth_key: auth_key, max_views: 1)

    assert {:ok, created} = create_share(document, owner_id, attrs)

    participant =
      %{"display_name" => "Guest User"}
      |> valid_share_participant_device_attrs()

    assert {:ok, challenge} = Sharing.get_password_challenge(created.share_slug)

    assert {:ok, bootstrapped} =
             Sharing.respond_password_challenge(
               created.share_slug,
               participant
               |> Map.put("response", share_password_challenge_response(auth_key, challenge))
               |> Map.put("password_challenge_hash", password_challenge_hash(created.share_slug))
               |> attach_share_participant_device_authorization(created, auth_key)
             )

    session_token_base64 = Base.url_encode64(bootstrapped.session_token, padding: false)

    {:ok, landing} = Sharing.get_share_landing(created.share_slug, session_token_base64)

    assert {:ok, _canonical} =
             Sharing.get_document_bootstrap(
               landing.root.document_token,
               session_token_base64,
               workspace_pin_bootstrap_hash()
             )

    assert %{view_count: 1} = Repo.get!(Share, created.share.id)
    assert {:ok, blocked_challenge} = Sharing.get_password_challenge(created.share_slug)
    refute blocked_challenge.salt == attrs["salt"]
    assert blocked_challenge.kdf_params == challenge.kdf_params

    assert {:error, :not_found} =
             Sharing.respond_password_challenge(
               created.share_slug,
               participant
               |> Map.put(
                 "response",
                 share_password_challenge_response(auth_key, blocked_challenge)
               )
               |> Map.put("password_challenge_hash", password_challenge_hash(created.share_slug))
               |> attach_share_participant_device_authorization(created, auth_key)
             )

    assert {:ok, resumed_canonical} =
             Sharing.get_document_bootstrap(
               landing.root.document_token,
               session_token_base64,
               workspace_pin_bootstrap_hash()
             )

    assert resumed_canonical.document_id == document.id
    assert %{view_count: 1} = Repo.get!(Share, created.share.id)
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
    assert {:ok, created} = create_share(document, owner_id, attrs)

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
             create_share(folder, owner_id, create_folder_share_attrs([child_document]))

    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    participant = valid_share_participant_device_attrs(%{"display_name" => "Guest User"})

    assert {:ok, bootstrapped} = bootstrap_share_participant(created, participant)

    session_token_base64 = Base.url_encode64(bootstrapped.session_token, padding: false)

    Repo.delete!(
      Repo.get!(RefMD.Sharing.ShareParticipantDevice, bootstrapped.participant.device_id)
    )

    assert {:ok, response} =
             Sharing.get_folder_bootstrap(
               landing.root.folder_token,
               session_token_base64,
               workspace_pin_bootstrap_hash()
             )

    assert response.bootstrap_required == true
    assert response.share_token_hash == created.share.token_hash
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

    assert {:ok, created} = create_share(folder, owner_id, attrs)
    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    participant = valid_share_participant_device_attrs(%{"display_name" => "Guest User"})

    assert {:ok, bootstrapped} = bootstrap_share_participant(created, participant)
    session_token_base64 = Base.url_encode64(bootstrapped.session_token, padding: false)

    assert {:ok, folder_bootstrap} =
             Sharing.get_folder_bootstrap(
               landing.root.folder_token,
               session_token_base64,
               workspace_pin_bootstrap_hash()
             )

    assert folder_bootstrap.share_id == created.share.id
    assert folder_bootstrap.password_protected == false
    assert folder_bootstrap.folder.parent_id == nil
    assert folder_bootstrap.folder.share_id == created.share.id

    child_folder_entry = Enum.find(folder_bootstrap.entries, &(&1.id == child_folder.id))
    assert is_binary(child_folder_entry.share_id)
    refute child_folder_entry.share_id == created.share.id
    assert is_binary(child_folder_entry.folder_token)
    assert is_binary(child_folder_entry.encrypted_dek)
    assert byte_size(child_folder_entry.nonce) == 24

    visible_entry = Enum.find(folder_bootstrap.entries, &(&1.id == visible_document.id))
    assert is_binary(visible_entry.share_id)
    refute visible_entry.share_id == created.share.id
    assert is_binary(visible_entry.document_token)
    assert visible_entry.encrypted_title == visible_document.encrypted_title
    assert visible_entry.encrypted_title_nonce == visible_document.encrypted_title_nonce
    assert is_binary(visible_entry.encrypted_dek)
    assert byte_size(visible_entry.nonce) == 24

    refute Enum.any?(folder_bootstrap.entries, &(&1.id == nested_document.id))

    assert {:ok, nested_folder_bootstrap} =
             Sharing.get_folder_bootstrap(
               child_folder_entry.folder_token,
               session_token_base64,
               workspace_pin_bootstrap_hash()
             )

    assert nested_folder_bootstrap.folder.parent_id == nil
    assert nested_folder_bootstrap.folder.share_id == child_folder_entry.share_id

    nested_folder_entry =
      Enum.find(nested_folder_bootstrap.entries, &(&1.id == nested_document.id))

    assert is_binary(nested_folder_entry.document_token)
    assert nested_folder_entry.parent_id == child_folder.id
    assert is_binary(nested_folder_entry.share_id)
    assert is_binary(nested_folder_entry.encrypted_dek)
    assert byte_size(nested_folder_entry.nonce) == 24

    assert {:ok, canonical} =
             Sharing.get_document_bootstrap(
               visible_entry.document_token,
               session_token_base64,
               workspace_pin_bootstrap_hash()
             )

    assert canonical.share_id == visible_entry.share_id
    assert canonical.document_id == visible_document.id
    assert canonical.permission == "edit"
    assert canonical.share_token_hash == created.share.token_hash

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

    refute is_nil(child_share.parent_share_id)
    refute child_share.token_hash == created.share.token_hash
    assert child_share.authorization_public_key_material == nil
    assert {:error, :invalid_slug} = Sharing.get_share_landing(child_share.token_hash)

    assert {:error, :invalid_token} =
             Sharing.bootstrap_participant(
               child_share.token_hash,
               participant
             )

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
             Sharing.get_document_bootstrap(
               visible_entry.document_token,
               session_token_base64,
               workspace_pin_bootstrap_hash()
             )

    assert {:error, :not_found} =
             Sharing.get_document_bootstrap(visible_entry.document_token, nil, nil)

    assert {:ok, _moved_folder} = Documents.update_document(child_folder, %{"parent_id" => nil})

    assert {:error, :not_found} =
             Sharing.get_folder_bootstrap(
               child_folder_entry.folder_token,
               session_token_base64,
               workspace_pin_bootstrap_hash()
             )
  end

  test "share initial document data applies delta clock filtering before returning updates", %{
    document: document,
    owner_id: owner_id
  } do
    assert {:ok, created} =
             create_share(document, owner_id, create_share_attrs(permission: "edit"))

    {snapshot, [_old_update, new_update], clock_key} =
      insert_active_snapshot_with_updates!(document, [0, 1])

    params = %{
      "mode" => "delta",
      "knownSnapshotId" => snapshot.id,
      "knownSnapshotUpdateClocks" => %{clock_key => 0}
    }

    assert {:ok, {loaded_snapshot, updates}} =
             Documents.get_initial_document_data_for_share(document.id, created.share.id, params)

    assert loaded_snapshot.id == snapshot.id
    assert Enum.map(updates, & &1.clock) == [1]
    assert Enum.map(updates, & &1.update_hash) == [new_update.update_hash]

    assert {:ok, {_loaded_snapshot, complete_updates}} =
             Documents.get_initial_document_data_for_share(document.id, created.share.id, %{
               "mode" => "complete",
               "knownSnapshotId" => snapshot.id
             })

    assert Enum.map(complete_updates, & &1.clock) == [0, 1]
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

    assert {:ok, created} = create_share(folder, owner_id, attrs)

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
             bootstrap_share_participant(
               created,
               valid_share_participant_device_attrs(%{"display_name" => "Guest User"})
             )

    session_token = Base.url_encode64(bootstrapped.session_token, padding: false)

    assert {:ok, folder_bootstrap} =
             Sharing.get_folder_bootstrap(
               landing.root.folder_token,
               session_token,
               workspace_pin_bootstrap_hash()
             )

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

    assert {:ok, created} = create_share(folder, owner_id, attrs)
    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    assert {:ok, bootstrapped} =
             bootstrap_share_participant(
               created,
               valid_share_participant_device_attrs(%{"display_name" => "Guest User"})
             )

    session_token = Base.url_encode64(bootstrapped.session_token, padding: false)
    share_id = created.share.id
    visible_document_id = visible_document.id

    assert {:ok, initial_bootstrap} =
             Sharing.get_folder_bootstrap(
               landing.root.folder_token,
               session_token,
               workspace_pin_bootstrap_hash()
             )

    target_entry = Enum.find(initial_bootstrap.entries, &(&1.id == target_document.id))
    child_folder_entry = Enum.find(initial_bootstrap.entries, &(&1.id == child_folder.id))

    assert {:ok, nested_bootstrap} =
             Sharing.get_folder_bootstrap(
               child_folder_entry.folder_token,
               session_token,
               workspace_pin_bootstrap_hash()
             )

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
             update_share_exclusions(
               folder.id,
               created.share.id,
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
             Sharing.get_folder_bootstrap(
               landing.root.folder_token,
               session_token,
               workspace_pin_bootstrap_hash()
             )

    updated_entry_ids = Enum.map(updated_bootstrap.entries, & &1.id)

    assert visible_document.id in updated_entry_ids
    refute target_document.id in updated_entry_ids
    refute child_folder.id in updated_entry_ids

    assert {:error, :not_found} =
             Sharing.get_document_bootstrap(
               target_entry.document_token,
               session_token,
               workspace_pin_bootstrap_hash()
             )

    assert {:error, :not_found} =
             Sharing.get_folder_bootstrap(
               child_folder_entry.folder_token,
               session_token,
               workspace_pin_bootstrap_hash()
             )

    assert {:error, :not_found} =
             Sharing.get_document_bootstrap(
               nested_entry.document_token,
               session_token,
               workspace_pin_bootstrap_hash()
             )

    refute Sharing.can_read_document?(created.share.id, target_document.id)
    refute Sharing.can_read_document?(created.share.id, nested_document.id)

    assert {:ok, result} =
             update_share_exclusions(
               folder.id,
               created.share.id,
               %{"remove" => [child_folder.id]}
             )

    assert result.exclusions == [target_document.id]

    assert {:ok, final_bootstrap} =
             Sharing.get_folder_bootstrap(
               landing.root.folder_token,
               session_token,
               workspace_pin_bootstrap_hash()
             )

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
             create_share(
               folder,
               owner_id,
               create_folder_share_attrs([], exclusions: [target_document.id])
             )

    assert {:ok, bootstrapped} =
             bootstrap_share_participant(
               created,
               valid_share_participant_device_attrs(%{"display_name" => "Guest User"})
             )

    Phoenix.PubSub.subscribe(
      RefMD.PubSub,
      "share_device_revocation:#{bootstrapped.participant.device_id}"
    )

    Phoenix.PubSub.subscribe(
      RefMD.PubSub,
      "share_socket:#{bootstrapped.participant.principal_id}"
    )

    assert {:ok, %{exclusions: []}} =
             update_share_exclusions(
               folder.id,
               created.share.id,
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
             create_share(folder, owner_id, create_folder_share_attrs([]))

    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    assert {:ok, bootstrapped} =
             bootstrap_share_participant(
               created,
               valid_share_participant_device_attrs(%{"display_name" => "Guest User"})
             )

    session_token = Base.url_encode64(bootstrapped.session_token, padding: false)

    assert {:ok, initial_bootstrap} =
             Sharing.get_folder_bootstrap(
               landing.root.folder_token,
               session_token,
               workspace_pin_bootstrap_hash()
             )

    assert initial_bootstrap.entries == []

    new_document = create_document(folder.workspace_id, owner_id, folder.id)
    new_folder = create_folder(folder.workspace_id, owner_id, folder.id)
    nested_document = create_document(folder.workspace_id, owner_id, new_folder.id)

    assert {:ok, result} =
             update_share_keys(
               folder.id,
               created.share.id,
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
             Sharing.get_folder_bootstrap(
               landing.root.folder_token,
               session_token,
               workspace_pin_bootstrap_hash()
             )

    document_entry = Enum.find(updated_bootstrap.entries, &(&1.id == new_document.id))
    folder_entry = Enum.find(updated_bootstrap.entries, &(&1.id == new_folder.id))

    assert is_binary(document_entry.document_token)
    assert is_binary(folder_entry.folder_token)

    assert {:ok, nested_bootstrap} =
             Sharing.get_folder_bootstrap(
               folder_entry.folder_token,
               session_token,
               workspace_pin_bootstrap_hash()
             )

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
             create_share(
               folder,
               owner_id,
               create_folder_share_attrs([target_document])
             )

    child_share =
      Repo.get_by!(Share, parent_share_id: created.share.id, document_id: target_document.id)

    original_share_key = Repo.get!(ShareKey, child_share.id)
    replacement_encrypted_dek = :crypto.strong_rand_bytes(48)

    assert {:ok, result} =
             update_share_keys(
               folder.id,
               created.share.id,
               %{
                 "replace_keys" => [
                   %{
                     "share_id" => child_share.id,
                     "document_id" => target_document.id,
                     "encrypted_dek" => replacement_encrypted_dek,
                     "nonce" => :crypto.strong_rand_bytes(24)
                   }
                 ]
               }
             )

    assert result.share_id == created.share.id
    assert result.added == []
    assert result.replaced == [target_document.id]

    updated_share_key = Repo.get!(ShareKey, child_share.id)
    assert byte_size(updated_share_key.nonce) == 24
    assert updated_share_key.encrypted_dek == replacement_encrypted_dek
    refute updated_share_key.encrypted_dek == original_share_key.encrypted_dek
  end

  test "password-protected folder share keys can be added and replaced", %{
    folder: folder,
    owner_id: owner_id
  } do
    auth_key = :crypto.strong_rand_bytes(32)

    assert {:ok, created} =
             create_share(
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
             update_share_keys(
               folder.id,
               created.share.id,
               %{"add_keys" => [folder_share_key_attrs(added_document, true)]}
             )

    assert added_document_id == added_document.id

    child_share =
      Repo.get_by!(Share, parent_share_id: created.share.id, document_id: added_document.id)

    replacement_nonce = :crypto.strong_rand_bytes(24)

    assert {:ok, %{added: [], replaced: [replaced_document_id]}} =
             update_share_keys(
               folder.id,
               created.share.id,
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
             respond_share_password_challenge(
               created,
               valid_share_participant_device_attrs(%{
                 "display_name" => "Guest User",
                 "response" => share_password_challenge_response(auth_key, challenge),
                 "password_challenge_hash" => password_challenge_hash(created.share_slug)
               }),
               auth_key
             )

    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)
    session_token = Base.url_encode64(bootstrapped.session_token, padding: false)

    assert {:ok, folder_bootstrap} =
             Sharing.get_folder_bootstrap(
               landing.root.folder_token,
               session_token,
               workspace_pin_bootstrap_hash()
             )

    entry = Enum.find(folder_bootstrap.entries, &(&1.id == added_document.id))

    assert entry.nonce == replacement_nonce
  end

  test "folder share key update rejects missing nonce", %{
    folder: folder,
    owner_id: owner_id
  } do
    target_document = create_document(folder.workspace_id, owner_id, folder.id)

    assert {:ok, created} =
             create_share(folder, owner_id, create_folder_share_attrs([target_document]))

    child_share =
      Repo.get_by!(Share, parent_share_id: created.share.id, document_id: target_document.id)

    assert {:error, {:invalid_value, :add_keys}} =
             update_share_keys(
               folder.id,
               created.share.id,
               %{
                 "add_keys" => [
                   %{
                     "share_id" => Ecto.UUID.generate(),
                     "document_id" =>
                       create_document(folder.workspace_id, owner_id, folder.id).id,
                     "encrypted_dek" => :crypto.strong_rand_bytes(48),
                     "nonce" => nil
                   }
                 ]
               }
             )

    assert {:error, {:invalid_value, :replace_keys}} =
             update_share_keys(
               folder.id,
               created.share.id,
               %{
                 "replace_keys" => [
                   %{
                     "share_id" => child_share.id,
                     "document_id" => target_document.id,
                     "encrypted_dek" => :crypto.strong_rand_bytes(48),
                     "nonce" => nil
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
             create_share(
               folder,
               owner_id,
               create_folder_share_attrs([target_document])
             )

    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    assert {:ok, bootstrapped} =
             bootstrap_share_participant(
               created,
               valid_share_participant_device_attrs(%{"display_name" => "Guest User"})
             )

    session_token = Base.url_encode64(bootstrapped.session_token, padding: false)

    assert {:ok, folder_bootstrap} =
             Sharing.get_folder_bootstrap(
               landing.root.folder_token,
               session_token,
               workspace_pin_bootstrap_hash()
             )

    target_entry = Enum.find(folder_bootstrap.entries, &(&1.id == target_document.id))
    unshared_folder = create_folder(folder.workspace_id, owner_id, folder.id)

    assert {:ok, moved_document} =
             Documents.update_document(target_document, %{"parent_id" => unshared_folder.id})

    refute Sharing.can_read_document?(created.share.id, moved_document.id)

    assert {:error, :not_found} =
             Sharing.get_document_bootstrap(
               target_entry.document_token,
               session_token,
               workspace_pin_bootstrap_hash()
             )

    child_share =
      Repo.get_by!(Share, parent_share_id: created.share.id, document_id: moved_document.id)

    assert {:error, {:invalid_value, :replace_keys}} =
             update_share_keys(
               folder.id,
               created.share.id,
               %{
                 "replace_keys" => [
                   %{
                     "share_id" => child_share.id,
                     "document_id" => moved_document.id,
                     "encrypted_dek" => :crypto.strong_rand_bytes(48),
                     "nonce" => :crypto.strong_rand_bytes(24)
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
             create_share(
               folder,
               owner_id,
               create_folder_share_attrs([child_folder, nested_document])
             )

    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    assert {:ok, bootstrapped} =
             bootstrap_share_participant(
               created,
               valid_share_participant_device_attrs(%{"display_name" => "Guest User"})
             )

    session_token = Base.url_encode64(bootstrapped.session_token, padding: false)

    assert {:ok, folder_bootstrap} =
             Sharing.get_folder_bootstrap(
               landing.root.folder_token,
               session_token,
               workspace_pin_bootstrap_hash()
             )

    child_folder_entry = Enum.find(folder_bootstrap.entries, &(&1.id == child_folder.id))
    unshared_folder = create_folder(folder.workspace_id, owner_id, folder.id)

    assert {:ok, moved_folder} =
             Documents.update_document(child_folder, %{"parent_id" => unshared_folder.id})

    assert {:error, :not_found} =
             Sharing.get_folder_bootstrap(
               child_folder_entry.folder_token,
               session_token,
               workspace_pin_bootstrap_hash()
             )

    refute Sharing.can_read_document?(created.share.id, moved_folder.id)
    refute Sharing.can_read_document?(created.share.id, nested_document.id)
  end

  test "folder share key replacement rejects mismatched child shares", %{
    folder: folder,
    owner_id: owner_id
  } do
    target_document = create_document(folder.workspace_id, owner_id, folder.id)

    assert {:ok, created} =
             create_share(
               folder,
               owner_id,
               create_folder_share_attrs([target_document])
             )

    assert {:error, {:invalid_value, :replace_keys}} =
             update_share_keys(
               folder.id,
               created.share.id,
               %{
                 "replace_keys" => [
                   %{
                     "share_id" => Ecto.UUID.generate(),
                     "document_id" => target_document.id,
                     "encrypted_dek" => :crypto.strong_rand_bytes(48),
                     "nonce" => :crypto.strong_rand_bytes(24)
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
             create_share(folder, owner_id, create_folder_share_attrs([]))

    added_document = create_document(folder.workspace_id, owner_id, folder.id)
    replace_document = create_document(folder.workspace_id, owner_id, folder.id)

    child_share_without_key =
      insert_child_share_without_key!(created.share, replace_document, owner_id)

    assert {:error, {:invalid_value, :replace_keys}} =
             update_share_keys(
               folder.id,
               created.share.id,
               %{
                 "add_keys" => [folder_share_key_attrs(added_document)],
                 "replace_keys" => [
                   %{
                     "share_id" => child_share_without_key.id,
                     "document_id" => replace_document.id,
                     "encrypted_dek" => :crypto.strong_rand_bytes(48),
                     "nonce" => :crypto.strong_rand_bytes(24)
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
             create_share(folder, owner_id, create_folder_share_attrs([]))

    child_folder = create_folder(folder.workspace_id, owner_id, folder.id)
    nested_document = create_document(folder.workspace_id, owner_id, child_folder.id)

    assert {:error, {:invalid_value, :add_keys}} =
             update_share_keys(
               folder.id,
               created.share.id,
               %{"add_keys" => [folder_share_key_attrs(nested_document)]}
             )

    refute Repo.get_by(Share, parent_share_id: created.share.id, document_id: nested_document.id)
  end

  test "folder share key update rejects paths through mismatched child share scopes", %{
    folder: folder,
    owner_id: owner_id
  } do
    assert {:ok, created} =
             create_share(folder, owner_id, create_folder_share_attrs([]))

    child_folder = create_folder(folder.workspace_id, owner_id, folder.id)
    nested_document = create_document(folder.workspace_id, owner_id, child_folder.id)

    insert_child_share_without_key!(created.share, child_folder, owner_id, scope: "document")

    assert {:error, {:invalid_value, :add_keys}} =
             update_share_keys(
               folder.id,
               created.share.id,
               %{"add_keys" => [folder_share_key_attrs(nested_document)]}
             )
  end

  test "folder share key update rejects paths through incomplete child shares", %{
    folder: folder,
    owner_id: owner_id
  } do
    assert {:ok, created} =
             create_share(folder, owner_id, create_folder_share_attrs([]))

    child_folder = create_folder(folder.workspace_id, owner_id, folder.id)
    nested_document = create_document(folder.workspace_id, owner_id, child_folder.id)

    insert_child_share_without_key!(created.share, child_folder, owner_id, scope: "folder")

    assert {:error, {:invalid_value, :add_keys}} =
             update_share_keys(
               folder.id,
               created.share.id,
               %{"add_keys" => [folder_share_key_attrs(nested_document)]}
             )
  end

  test "folder share key update rejects add and replace collisions", %{
    folder: folder,
    owner_id: owner_id
  } do
    existing_document = create_document(folder.workspace_id, owner_id, folder.id)

    assert {:ok, created} =
             create_share(
               folder,
               owner_id,
               create_folder_share_attrs([existing_document])
             )

    child_share =
      Repo.get_by!(Share, parent_share_id: created.share.id, document_id: existing_document.id)

    new_document = create_document(folder.workspace_id, owner_id, folder.id)

    assert {:error, {:invalid_value, :add_keys}} =
             update_share_keys(
               folder.id,
               created.share.id,
               %{
                 "add_keys" => [
                   %{
                     "share_id" => child_share.id,
                     "document_id" => new_document.id,
                     "encrypted_dek" => :crypto.strong_rand_bytes(48),
                     "nonce" => :crypto.strong_rand_bytes(24)
                   }
                 ]
               }
             )

    assert {:error, {:invalid_value, :add_keys}} =
             update_share_keys(
               folder.id,
               created.share.id,
               %{
                 "add_keys" => [
                   %{
                     "share_id" => child_share.id,
                     "document_id" => new_document.id,
                     "encrypted_dek" => :crypto.strong_rand_bytes(48),
                     "nonce" => :crypto.strong_rand_bytes(24)
                   }
                 ],
                 "replace_keys" => [
                   %{
                     "share_id" => child_share.id,
                     "document_id" => existing_document.id,
                     "encrypted_dek" => :crypto.strong_rand_bytes(48),
                     "nonce" => :crypto.strong_rand_bytes(24)
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
             create_share(folder, owner_id, create_folder_share_attrs([]))

    assert {:ok, %{added: [], replaced: []}} =
             update_share_keys(
               folder.id,
               created.share.id,
               %{"add_keys" => [], "replace_keys" => []}
             )
  end

  test "folder share key update rejects excluded targets", %{
    folder: folder,
    owner_id: owner_id
  } do
    target_document = create_document(folder.workspace_id, owner_id, folder.id)

    assert {:ok, created} =
             create_share(
               folder,
               owner_id,
               create_folder_share_attrs([], exclusions: [target_document.id])
             )

    assert {:error, {:invalid_value, :add_keys}} =
             update_share_keys(
               folder.id,
               created.share.id,
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
             create_share(
               folder,
               owner_id,
               create_folder_share_attrs([target_document])
             )

    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    assert {:ok, bootstrapped} =
             bootstrap_share_participant(
               created,
               valid_share_participant_device_attrs(%{"display_name" => "Guest User"})
             )

    session_token = Base.url_encode64(bootstrapped.session_token, padding: false)

    assert {:ok, folder_bootstrap} =
             Sharing.get_folder_bootstrap(
               landing.root.folder_token,
               session_token,
               workspace_pin_bootstrap_hash()
             )

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
             Sharing.get_document_bootstrap(
               target_entry.document_token,
               session_token,
               workspace_pin_bootstrap_hash()
             )

    assert {:ok, updated_bootstrap} =
             Sharing.get_folder_bootstrap(
               landing.root.folder_token,
               session_token,
               workspace_pin_bootstrap_hash()
             )

    refute Enum.any?(updated_bootstrap.entries, &(&1.id == target_document.id))
  end

  test "folder share key update rejects existing child shares", %{
    folder: folder,
    owner_id: owner_id
  } do
    target_document = create_document(folder.workspace_id, owner_id, folder.id)

    assert {:ok, created} =
             create_share(
               folder,
               owner_id,
               create_folder_share_attrs([target_document])
             )

    assert {:error, {:invalid_value, :add_keys}} =
             update_share_keys(
               folder.id,
               created.share.id,
               %{"add_keys" => [folder_share_key_attrs(target_document)]}
             )
  end

  test "child share uniqueness is enforced by the database", %{
    folder: folder,
    owner_id: owner_id
  } do
    target_document = create_document(folder.workspace_id, owner_id, folder.id)

    assert {:ok, created} =
             create_share(
               folder,
               owner_id,
               create_folder_share_attrs([target_document])
             )

    token_hash = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

    assert {:error, changeset} =
             %Share{}
             |> Share.changeset(%{
               id: Ecto.UUID.generate(),
               document_id: target_document.id,
               parent_share_id: created.share.id,
               scope: "document",
               token_hash: token_hash,
               token_prefix: String.slice(token_hash, 0, 4),
               permission: "view",
               password_protected: false,
               authorization_public_key_material: nil,
               share_capability_secret_commitment:
                 created.share.share_capability_secret_commitment,
               password_capability_secret_commitment:
                 created.share.password_capability_secret_commitment,
               capability_context_hash: created.share.capability_context_hash,
               created_event_hash: created.share.created_event_hash,
               authenticated_workspace_pin_bootstrap_hash:
                 created.share.authenticated_workspace_pin_bootstrap_hash,
               authenticated_workspace_pin_bootstrap_checkpoint:
                 created.share.authenticated_workspace_pin_bootstrap_checkpoint,
               max_views: created.share.max_views,
               expires_event_sequence: created.share.expires_event_sequence,
               view_count: 0,
               created_by: owner_id
             })
             |> Repo.insert()

    assert {"has already been taken", _meta} = changeset.errors[:parent_share_id]
  end

  test "folder share key update rejects document shares", %{
    document: document,
    owner_id: owner_id
  } do
    assert {:ok, created} = create_share(document, owner_id, create_share_attrs())

    assert {:error, {:invalid_value, :scope}} =
             update_share_keys(
               document.id,
               created.share.id,
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
             create_share(
               folder,
               owner_id,
               create_folder_share_attrs([target_document], exclusions: [restored_document.id])
             )

    assert {:ok, result} =
             update_share_exclusions(
               folder.id,
               created.share.id,
               %{"add" => [target_document.id], "remove" => [restored_document.id]}
             )

    assert result.exclusions == [target_document.id]
  end

  test "folder share exclusion update rejects document shares", %{
    document: document,
    owner_id: owner_id
  } do
    assert {:ok, created} = create_share(document, owner_id, create_share_attrs())

    assert {:error, {:invalid_value, :scope}} =
             update_share_exclusions(
               document.id,
               created.share.id,
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
             create_share(folder, owner_id, create_folder_share_attrs([child_document]))

    assert {:error, {:invalid_value, :exclusions}} =
             update_share_exclusions(
               folder.id,
               created.share.id,
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
             create_share(folder, owner_id, attrs)

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

    assert {:ok, created} = create_share(folder, owner_id, attrs)
    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    assert {:ok, challenge} = Sharing.get_password_challenge(created.share_slug)

    participant =
      %{"display_name" => "Guest User"}
      |> valid_share_participant_device_attrs()

    assert {:ok, bootstrapped} =
             Sharing.respond_password_challenge(
               created.share_slug,
               participant
               |> Map.put("response", share_password_challenge_response(auth_key, challenge))
               |> Map.put("password_challenge_hash", password_challenge_hash(created.share_slug))
               |> attach_share_participant_device_authorization(created, auth_key)
             )

    session_token_base64 = Base.url_encode64(bootstrapped.session_token, padding: false)

    assert {:ok, folder_bootstrap} =
             Sharing.get_folder_bootstrap(
               landing.root.folder_token,
               session_token_base64,
               workspace_pin_bootstrap_hash()
             )

    assert folder_bootstrap.password_protected == true

    child_entry = Enum.find(folder_bootstrap.entries, &(&1.id == child_document.id))
    assert is_binary(child_entry.share_id)
    assert is_binary(child_entry.document_token)

    assert {:ok, canonical} =
             Sharing.get_document_bootstrap(
               child_entry.document_token,
               session_token_base64,
               workspace_pin_bootstrap_hash()
             )

    assert canonical.password_protected == true
    assert canonical.document_id == child_document.id
    assert canonical.share_id == child_entry.share_id
  end

  test "max_views blocks new admissions without revoking admitted session", %{
    document: document,
    owner_id: owner_id
  } do
    attrs = create_share_attrs(max_views: 1)
    assert {:ok, created} = create_share(document, owner_id, attrs)
    assert {:ok, landing} = Sharing.get_share_landing(created.share_slug)

    participant = valid_share_participant_device_attrs(%{"display_name" => "Guest User"})

    assert {:ok, bootstrapped} = bootstrap_share_participant(created, participant)

    session_token_base64 = Base.url_encode64(bootstrapped.session_token, padding: false)

    assert {:ok, canonical} =
             Sharing.get_document_bootstrap(
               landing.root.document_token,
               session_token_base64,
               workspace_pin_bootstrap_hash()
             )

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

    second_participant = valid_share_participant_device_attrs(%{"display_name" => "Second Guest"})
    assert {:error, :not_found} = bootstrap_share_participant(created, second_participant)
    assert {:error, :not_found} = Sharing.get_share_landing(created.share_slug)

    assert {:ok, existing_landing} =
             Sharing.get_share_landing(created.share_slug, session_token_base64)

    assert existing_landing.root.document_token == landing.root.document_token
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

    {:ok, owner_share} = create_share(document, owner_id, create_share_attrs())
    {:ok, editor_share} = create_share(document, editor_id, create_share_attrs())

    owner_visible = Sharing.list_document_shares(document, owner_id, owner_role)
    editor_visible = Sharing.list_document_shares(document, editor_id, editor_role)

    assert Enum.any?(owner_visible, &(&1.id == owner_share.share.id))
    assert Enum.any?(owner_visible, &(&1.id == editor_share.share.id))
    assert Enum.any?(editor_visible, &(&1.id == editor_share.share.id))
    refute Enum.any?(editor_visible, &(&1.id == owner_share.share.id))
  end

  test "list_document_shares/3 does not expose restorable share slugs", %{
    document: document,
    owner_id: owner_id,
    owner_role: owner_role
  } do
    {:ok, created} = create_share(document, owner_id, create_share_attrs())

    shares = Sharing.list_document_shares(document, owner_id, owner_role)

    assert Enum.any?(shares, &(&1.id == created.share.id))
    refute Enum.any?(shares, &Map.has_key?(&1, :share_slug))
  end

  test "list_document_shares/3 does not expose workspace pin bootstrap hash", %{
    document: document,
    owner_id: owner_id,
    owner_role: owner_role
  } do
    {:ok, created} = create_share(document, owner_id, create_share_attrs())

    shares = Sharing.list_document_shares(document, owner_id, owner_role)

    listed_share = Enum.find(shares, &(&1.id == created.share.id))

    assert listed_share
    refute Map.has_key?(listed_share, :authenticated_workspace_pin_bootstrap_hash)
  end
end
