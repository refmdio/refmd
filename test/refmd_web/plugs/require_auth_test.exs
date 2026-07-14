defmodule RefMDWeb.Plugs.RequireAuthTest do
  use RefMDWeb.ConnCase, async: true

  alias RefMD.Auth
  alias RefMD.Crypto.Hash
  alias RefMD.Devices.Device
  alias RefMD.Documents
  alias RefMD.Repo
  alias RefMD.Sharing
  alias RefMD.Users.User
  alias RefMD.Workspaces
  alias RefMDWeb.Plugs.RequireAuth

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
        "parent_id" => nil,
        "title" => "Untitled",
        "encrypted_title" => <<1, 2, 3>>,
        "encrypted_title_nonce" => :crypto.strong_rand_bytes(24),
        "encrypted_title_key_version" => 1,
        "created_by" => created_by
      })

    document
  end

  defp create_share(document, owner_id) do
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
    workspace_pin_bootstrap_hash = Process.get(:workspace_pin_bootstrap_hash)

    attrs =
      with_test_share_security_artifacts(document, owner_id, %{
        "id" => Ecto.UUID.generate(),
        "scope" => "document",
        "share_slug" => share_slug,
        "token_prefix" => String.slice(share_slug, 0, 4),
        "permission" => "view",
        "password_protected" => false,
        "authorization_public_key_material" =>
          share_capability_public_key_material_for_slug(open_admission_key(), share_slug),
        "share_capability_secret_commitment" => open_share_capability_secret_commitment(),
        "authenticated_workspace_pin_bootstrap_hash" => workspace_pin_bootstrap_hash,
        "encrypted_dek" => :crypto.strong_rand_bytes(48),
        "nonce" => :crypto.strong_rand_bytes(24)
      })

    {:ok, created} = Sharing.create_share(document, owner_id, attrs)

    created
  end

  setup do
    owner_id = create_user("owner-require-auth@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "RequireAuth Workspace")
    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)
    Process.put(:workspace_pin_bootstrap_hash, test_workspace_pin_bootstrap_hash!(workspace.id))
    document = create_document(workspace.id, owner_id)
    created = create_share(document, owner_id)

    {:ok, _user_session, user_token} = Auth.create_session(owner_id)

    {:ok, bootstrapped} =
      bootstrap_share_participant(created, "Guest User")

    %{
      user_cookie: Base.url_encode64(user_token, padding: false),
      share_cookie: Base.url_encode64(bootstrapped.session_token, padding: false),
      share_id: created.share.id,
      principal_id: bootstrapped.participant.principal_id
    }
  end

  test "accepts a share participant session from the share session cookie when share scope is requested",
       %{
         conn: conn,
         share_cookie: share_cookie,
         share_id: share_id,
         principal_id: principal_id
       } do
    conn =
      conn
      |> put_req_header("cookie", "__Host-refmd-share-session=#{share_cookie}")
      |> put_req_header("x-refmd-session-scope", "share")
      |> RequireAuth.call(allow_share_participant: true)

    refute conn.halted
    assert conn.assigns.session_kind == :share_participant
    assert conn.assigns.current_share_id == share_id
    assert conn.assigns.share_participant_principal_id == principal_id
  end

  test "rejects a share participant session without the share scope selector", %{
    conn: conn,
    share_cookie: share_cookie
  } do
    conn =
      conn
      |> put_req_header("cookie", "__Host-refmd-share-session=#{share_cookie}")
      |> RequireAuth.call(allow_share_participant: true)

    assert conn.halted
    assert conn.status == 401
  end

  test "rejects a user session whose device requires an identity wipe", %{conn: conn} do
    user_id = create_user("wipe-required-auth@example.com")
    device = insert_device(user_id)
    {:ok, _session, token} = Auth.create_session(user_id, %{device_id: device.id})

    device
    |> Ecto.Changeset.change(identity_wipe_required_at: DateTime.utc_now())
    |> Repo.update!()

    conn =
      conn
      |> put_req_header(
        "cookie",
        "__Host-refmd-session=#{Base.url_encode64(token, padding: false)}"
      )
      |> RequireAuth.call([])

    assert conn.halted
    assert conn.status == 401
  end

  test "rejects identity-recovery-only sessions outside the narrow recovery pipeline", %{
    conn: conn
  } do
    user_id = create_user("identity-recovery-session@example.com")

    {:ok, _session, token} =
      Auth.create_session(user_id, %{identity_recovery_required: true})

    conn =
      conn
      |> put_req_header(
        "cookie",
        "__Host-refmd-session=#{Base.url_encode64(token, padding: false)}"
      )
      |> RequireAuth.call([])

    assert conn.halted
    assert conn.status == 401

    allowed_conn =
      build_conn()
      |> put_req_header(
        "cookie",
        "__Host-refmd-session=#{Base.url_encode64(token, padding: false)}"
      )
      |> RequireAuth.call(allow_identity_recovery: true)

    refute allowed_conn.halted
    refute allowed_conn.assigns.device_verified
  end

  test "prefers the user session when both cookies are present and share scope is not requested",
       %{
         conn: conn,
         user_cookie: user_cookie,
         share_cookie: share_cookie
       } do
    conn =
      conn
      |> put_req_header(
        "cookie",
        "__Host-refmd-session=#{user_cookie}; __Host-refmd-share-session=#{share_cookie}"
      )
      |> RequireAuth.call(allow_share_participant: true)

    refute conn.halted
    assert conn.assigns.session_kind == :user
  end

  defp insert_device(user_id) do
    device_id = Ecto.UUID.generate()
    signing = hybrid_device_material(device_id)
    {x25519_public, _private} = :crypto.generate_key(:ecdh, :x25519)
    encryption = hybrid_encryption_public_key_material("device", device_id, x25519_public)
    checkpoint_hash = Hash.blake3_base64url("auth-device:" <> device_id)
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    Repo.insert!(%Device{
      id: device_id,
      user_id: user_id,
      name: "Wipe-required browser",
      device_type: "browser",
      hybrid_encryption_public_key_material: encryption.public,
      encryption_key_id: encryption.encryption_key_id,
      hybrid_signing_public_key_material: signing.public,
      signing_key_id: signing.signing_key_id,
      approval_signature: %{"fixture" => "wipe-required-auth"},
      approval_signature_surface: "device_approval",
      approval_proof: %{
        "target_key_checkpoint_sequence" => 1,
        "target_key_checkpoint_hash" => checkpoint_hash
      },
      key_checkpoint_sequence: 1,
      key_checkpoint_hash: checkpoint_hash,
      client_nonce: :crypto.strong_rand_bytes(16),
      last_seen_at: now,
      created_at: now
    })
  end
end
