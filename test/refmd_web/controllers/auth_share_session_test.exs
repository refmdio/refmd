defmodule RefMDWeb.AuthShareSessionTest do
  use RefMDWeb.ConnCase, async: true

  alias RefMD.Auth
  alias RefMD.Documents
  alias RefMD.Repo
  alias RefMD.Sharing
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

    {:ok, created} =
      Sharing.create_share(document, owner_id, %{
        "id" => Ecto.UUID.generate(),
        "scope" => "document",
        "share_slug" => share_slug,
        "token_prefix" => String.slice(share_slug, 0, 4),
        "permission" => "view",
        "password_protected" => false,
        "encrypted_dek" => :crypto.strong_rand_bytes(32),
        "nonce" => nil
      })

    created
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
    owner_id = create_user("owner-auth-share@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Auth Share Workspace")
    document = create_document(workspace.id, owner_id)
    created = create_share(document, owner_id)

    {:ok, user_session, user_token} = Auth.create_session(owner_id)

    {:ok, bootstrapped} =
      Sharing.bootstrap_participant(created.share_slug, %{
        "display_name" => "Guest User",
        "device_signing_pub_key" => valid_signing_public_key(),
        "device_encryption_pub_key" => valid_encryption_public_key()
      })

    %{
      user_session: user_session,
      user_cookie: Base.url_encode64(user_token, padding: false),
      share_cookie: Base.url_encode64(bootstrapped.session_token, padding: false),
      share_principal_id: bootstrapped.participant.principal_id,
      share_device_id: bootstrapped.participant.device_id
    }
  end

  test "POST /api/auth/ws-token prefers the user session by default", %{
    conn: conn,
    user_session: user_session,
    user_cookie: user_cookie,
    share_cookie: share_cookie
  } do
    user_id = user_session.user_id

    conn =
      conn
      |> put_req_header(
        "cookie",
        "_refmd_session=#{user_cookie}; _refmd_share_session=#{share_cookie}"
      )
      |> post("/api/auth/ws-token")

    assert %{"token" => token} = json_response(conn, 200)
    assert {:ok, ^user_id, _session} = Auth.verify_ws_token(token)
    assert {:error, _reason} = Sharing.verify_ws_token(token)
  end

  test "POST /api/auth/ws-token selects the share session when the share scope header is set", %{
    conn: conn,
    user_cookie: user_cookie,
    share_cookie: share_cookie
  } do
    conn =
      conn
      |> put_req_header(
        "cookie",
        "_refmd_session=#{user_cookie}; _refmd_share_session=#{share_cookie}"
      )
      |> put_req_header("x-refmd-session-scope", "share")
      |> post("/api/auth/ws-token")

    assert %{"token" => token} = json_response(conn, 200)
    assert {:ok, _share_session_id, _session} = Sharing.verify_ws_token(token)
    assert {:error, _reason} = Auth.verify_ws_token(token)
  end

  test "POST /api/auth/pop-challenge selects the share participant session when the share scope header is set",
       %{
         conn: conn,
         user_cookie: user_cookie,
         share_cookie: share_cookie,
         share_device_id: share_device_id
       } do
    conn =
      conn
      |> put_req_header(
        "cookie",
        "_refmd_session=#{user_cookie}; _refmd_share_session=#{share_cookie}"
      )
      |> put_req_header("x-refmd-session-scope", "share")
      |> put_req_header("x-pop-device-id", share_device_id)
      |> post("/api/auth/pop-challenge")

    assert %{"challenge" => challenge} = json_response(conn, 200)
    assert is_binary(challenge)
    assert byte_size(challenge) > 0
  end

  test "POST /api/auth/pop-challenge keeps using the user session by default", %{
    conn: conn,
    user_cookie: user_cookie,
    share_cookie: share_cookie,
    share_device_id: share_device_id
  } do
    conn =
      conn
      |> put_req_header(
        "cookie",
        "_refmd_session=#{user_cookie}; _refmd_share_session=#{share_cookie}"
      )
      |> put_req_header("x-pop-device-id", share_device_id)
      |> post("/api/auth/pop-challenge")

    assert json_response(conn, 403) == %{"error" => "invalid_device"}
  end

  test "POST /api/auth/logout selects the share session when the share scope header is set", %{
    conn: conn,
    user_session: user_session,
    user_cookie: user_cookie,
    share_cookie: share_cookie,
    share_principal_id: share_principal_id,
    share_device_id: share_device_id
  } do
    Phoenix.PubSub.subscribe(RefMD.PubSub, "share_socket:#{share_principal_id}")
    Phoenix.PubSub.subscribe(RefMD.PubSub, "share_device_revocation:#{share_device_id}")

    conn =
      conn
      |> put_req_header(
        "cookie",
        "_refmd_session=#{user_cookie}; _refmd_share_session=#{share_cookie}"
      )
      |> put_req_header("x-refmd-session-scope", "share")
      |> post("/api/auth/logout")

    assert json_response(conn, 200) == %{"ok" => true}
    assert conn.resp_cookies["_refmd_share_session"].max_age == 0
    assert {:ok, %{id: user_session_id}} = Auth.get_valid_session_by_token_base64(user_cookie)
    assert user_session_id == user_session.id
    assert {:error, _reason} = Sharing.get_valid_participant_session_by_token_base64(share_cookie)
    assert_receive %Phoenix.Socket.Broadcast{event: "disconnect", topic: topic}
    assert topic == "share_socket:#{share_principal_id}"
    assert_receive {:device_revoked, ^share_device_id}
  end
end
