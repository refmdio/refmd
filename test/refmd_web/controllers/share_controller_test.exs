defmodule RefMDWeb.ShareControllerTest do
  use RefMDWeb.ConnCase, async: true
  import Ecto.Query

  alias RefMD.Crypto.{Blake3, JCS, Signature}
  alias RefMD.Documents
  alias RefMD.Documents.DocumentSnapshot
  alias RefMD.Encryption.KeyDirectory
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

  defp insert_active_snapshot!(document, owner_id) do
    signer = Process.get({:test_workspace_signer_material, document.workspace_id})
    snapshot_id = Ecto.UUID.generate()
    ciphertext = <<7, 7, 7>>
    nonce = :crypto.strong_rand_bytes(24)
    ciphertext_b64 = Base.url_encode64(ciphertext, padding: false)
    nonce_b64 = Base.url_encode64(nonce, padding: false)
    signing_key_id = Signature.compute_signing_key_id!(signer.signing_public)
    previous_checkpoint = KeyDirectory.current_checkpoint("workspace", document.workspace_id)

    public_data = %{
      "docId" => document.id,
      "signingKeyId" => signing_key_id,
      "snapshotId" => snapshot_id,
      "keyVersion" => 1,
      "parentSnapshotId" => "GENESIS",
      "parentProofHash" => "GENESIS",
      "parentSnapshotUpdateClocks" => %{},
      "ownerKind" => "device",
      "ownerId" => signer.device_id,
      "authorityKind" => "workspace_device",
      "authorityId" => document.workspace_id,
      "authorityContextKey" => signing_key_id,
      "authorityScopeId" => document.workspace_id,
      "authorityPermissionVersion" => 1,
      "keyCheckpointSequence" => previous_checkpoint.sequence,
      "keyCheckpointHash" => previous_checkpoint.checkpoint_hash
    }

    signature =
      sign_document_snapshot(
        signer.signing_private,
        owner_id,
        signer.device_id,
        ciphertext_b64,
        nonce_b64,
        public_data,
        test_authority_boundary(public_data, "document_snapshot_accepted"),
        document.workspace_id
      )

    admission =
      document_operation_admission(%{
        workspace_id: document.workspace_id,
        document_id: document.id,
        user_id: owner_id,
        device_id: signer.device_id,
        private_material: signer.signing_private,
        event_type: "document_snapshot_accepted",
        operation_hash: Blake3.hash_base64url(ciphertext),
        signature: signature,
        key_version: 1,
        min_dek_version: 1
      })

    [snapshot_event] = admission["workspaceKeyDirectoryEvents"]
    snapshot_admission_event_hash = KeyDirectory.event_hash(snapshot_event["payload"])

    KeyDirectory.append_signed_scope!(
      "workspace",
      document.workspace_id,
      admission["workspaceKeyDirectoryEvents"],
      admission["workspaceKeyDirectoryCheckpoint"],
      checkpoint_signer_kind: "device"
    )

    snapshot_signature_hash = Blake3.hash_base64url(JCS.canonical_bytes!(signature))
    ciphertext_hash = Blake3.hash_base64url(ciphertext)

    proof_chain_hash =
      Blake3.hash_base64url(
        JCS.canonical_bytes!(%{
          "protocol" => "refmd.snapshot-proof-link",
          "version" => 1,
          "document_id" => document.id,
          "snapshot_id" => snapshot_id,
          "parent_snapshot_id" => "GENESIS",
          "parent_proof_hash" => "GENESIS",
          "ciphertext_hash" => ciphertext_hash,
          "snapshot_signature_hash" => snapshot_signature_hash,
          "snapshot_admission_event_hash" => snapshot_admission_event_hash
        })
      )

    %DocumentSnapshot{}
    |> DocumentSnapshot.changeset(%{
      id: snapshot_id,
      document_id: document.id,
      parent_snapshot_id: nil,
      device_id: signer.device_id,
      latest_version: 0,
      data: ciphertext,
      nonce: nonce,
      key_version: 1,
      hybrid_signature: signature,
      ciphertext_hash: ciphertext_hash,
      snapshot_signature_hash: snapshot_signature_hash,
      snapshot_admission_event_hash: snapshot_admission_event_hash,
      proof_chain_hash: proof_chain_hash,
      clocks: %{},
      parent_snapshot_update_clocks: %{},
      parent_proof_hash: "GENESIS",
      created_by_signing_key_id: signing_key_id,
      owner_kind: "device",
      owner_id: signer.device_id,
      authority_kind: "workspace_device",
      authority_id: document.workspace_id,
      authority_context_key: signing_key_id,
      authority_scope_id: document.workspace_id,
      authority_permission_version: 1,
      key_checkpoint_sequence: previous_checkpoint.sequence,
      key_checkpoint_hash: previous_checkpoint.checkpoint_hash
    })
    |> Repo.insert!()

    document
    |> Ecto.Changeset.change(active_snapshot_id: snapshot_id)
    |> Repo.update!()

    snapshot_id
  end

  defp test_authority_boundary(public_data, event_type) do
    %{
      "previous_workspace_event_sequence" => public_data["keyCheckpointSequence"],
      "previous_workspace_event_hash" => public_data["keyCheckpointHash"],
      "admission_event_type" => event_type,
      "admission_nonce" => public_data["keyCheckpointHash"],
      "min_dek_version" => public_data["keyVersion"],
      "document_permission_proof_hash" => public_data["keyCheckpointHash"]
    }
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
    insert_active_snapshot!(document, owner_id)

    conn =
      post(
        conn,
        "/api/shares/#{created.share_slug}/bootstrap",
        share_participant_request_attrs("Guest User", created, open_admission_key())
      )

    assert %{"root" => %{"kind" => "document"}, "participant" => %{"grant" => "view"}} =
             json_response(conn, 200)

    response = json_response(conn, 200)
    root_bootstrap = response["root_document_bootstrap"]

    latest_sequence =
      get_in(root_bootstrap, ["workspace_key_directory_latest_checkpoint", "payload", "sequence"])

    snapshot_admission = get_in(root_bootstrap, ["initial_document", "snapshot", "admission"])

    candidate_sequence =
      get_in(snapshot_admission, ["workspaceKeyDirectoryCheckpoint", "payload", "sequence"])

    ancestry_sequences =
      root_bootstrap
      |> get_in([
        "initial_document",
        "snapshot",
        "admission",
        "workspaceKeyDirectoryCheckpointAncestry"
      ])
      |> Enum.map(&get_in(&1, ["payload", "sequence"]))

    assert is_integer(latest_sequence)
    assert latest_sequence > 1
    assert candidate_sequence == latest_sequence
    refute 1 in ancestry_sequences
    refute candidate_sequence in ancestry_sequences

    assert conn.resp_cookies["__Host-refmd-share-session"].path == "/"
  end

  test "POST /api/shares/:share_slug/bootstrap keeps old snapshot admission bounded", %{
    conn: conn,
    document: document,
    owner_id: owner_id
  } do
    insert_active_snapshot!(document, owner_id)
    created = create_share(document, owner_id)

    conn =
      post(
        conn,
        "/api/shares/#{created.share_slug}/bootstrap",
        share_participant_request_attrs("Guest User", created, open_admission_key())
      )

    response = json_response(conn, 200)
    root_bootstrap = response["root_document_bootstrap"]

    latest_sequence =
      get_in(root_bootstrap, ["workspace_key_directory_latest_checkpoint", "payload", "sequence"])

    latest_event_head_sequence =
      get_in(root_bootstrap, [
        "workspace_key_directory_latest_checkpoint",
        "payload",
        "covered_event_head",
        "head_sequence"
      ])

    snapshot_admission = get_in(root_bootstrap, ["initial_document", "snapshot", "admission"])

    candidate_sequence =
      get_in(snapshot_admission, ["workspaceKeyDirectoryCheckpoint", "payload", "sequence"])

    candidate_event_head_sequence =
      get_in(snapshot_admission, [
        "workspaceKeyDirectoryCheckpoint",
        "payload",
        "covered_event_head",
        "head_sequence"
      ])

    checkpoint_ancestry_sequences =
      snapshot_admission
      |> Map.fetch!("workspaceKeyDirectoryCheckpointAncestry")
      |> Enum.map(&get_in(&1, ["payload", "sequence"]))

    event_ancestry_sequences =
      snapshot_admission
      |> Map.fetch!("workspaceKeyDirectoryEventAncestry")
      |> Enum.map(&get_in(&1, ["payload", "sequence"]))

    assert latest_sequence > candidate_sequence
    assert checkpoint_ancestry_sequences == [candidate_sequence - 1]
    refute latest_sequence in checkpoint_ancestry_sequences
    refute candidate_sequence in checkpoint_ancestry_sequences
    assert event_ancestry_sequences == [candidate_event_head_sequence]
    refute latest_event_head_sequence in event_ancestry_sequences
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

    assert respond_conn.resp_cookies["__Host-refmd-share-session"].path == "/"
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
        "__Host-refmd-share-session=#{Base.url_encode64(bootstrapped.session_token, padding: false)}"
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
        "__Host-refmd-share-session=#{share_session_token}"
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
      |> put_req_header("cookie", "__Host-refmd-share-session=#{share_session_token}")
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
