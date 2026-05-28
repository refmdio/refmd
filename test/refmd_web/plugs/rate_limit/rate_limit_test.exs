defmodule RefMDWeb.Plugs.RateLimit.RateLimitTest do
  use RefMDWeb.ConnCase, async: false

  alias RefMD.Crypto.{Blake3, Hash}
  alias RefMD.Documents
  alias RefMD.Repo
  alias RefMD.Sharing.{Share, ShareMount}
  alias RefMD.Users.User
  alias RefMD.Workspaces
  alias RefMDWeb.Plugs.RateLimit

  @user_cookie "_refmd_session"
  @share_cookie "_refmd_share_session"

  setup %{conn: conn} do
    :ets.delete_all_objects(RefMDWeb.Plugs.RateLimit.Storage)
    {:ok, conn: delete_req_header(conn, "x-refmd-e2e-rate-limit-bypass")}
  end

  test "uses the share session cookie for canonical share bootstrap", %{conn: conn} do
    user_token = "user-session-token"
    share_token = "share-session-token"

    conn =
      conn
      |> Map.put(:request_path, "/api/shares/d/document-token")
      |> put_req_header(
        "cookie",
        "#{@user_cookie}=#{user_token}; #{@share_cookie}=#{share_token}"
      )
      |> RateLimit.call([])

    refute conn.halted

    assert_session_counter_present(share_token)
    refute_session_counter_present(user_token)
  end

  test "uses the share session cookie for share admission bootstrap", %{conn: conn} do
    user_token = "user-session-token"
    share_token = "share-session-token"

    conn =
      conn
      |> Map.put(:request_path, "/api/shares/test-share/bootstrap")
      |> put_req_header(
        "cookie",
        "#{@user_cookie}=#{user_token}; #{@share_cookie}=#{share_token}"
      )
      |> RateLimit.call([])

    refute conn.halted

    assert_session_counter_present(share_token)
    refute_session_counter_present(user_token)
  end

  test "uses dedicated transport quota for pop challenge", %{conn: conn} do
    token = "user-session-token"

    conn =
      conn
      |> Map.put(:request_path, "/api/auth/pop-challenge")
      |> put_req_header("cookie", "#{@user_cookie}=#{token}")
      |> RateLimit.call([])

    refute conn.halted

    assert_transport_counter_present(token)
    assert_transport_ip_counter_present()
    refute_general_session_counter_present(token)
    refute_general_ip_counter_present()
  end

  test "bypasses rate limits for local E2E requests with the explicit bypass header", %{
    conn: conn
  } do
    conn =
      conn
      |> Map.put(:request_path, "/api/auth/pop-challenge")
      |> put_req_header("x-refmd-e2e-rate-limit-bypass", "1")
      |> RateLimit.call([])

    refute conn.halted
    assert :ets.tab2list(RefMDWeb.Plugs.RateLimit.Storage) == []
  end

  test "uses dedicated transport quota for ws token", %{conn: conn} do
    token = "user-session-token"

    conn =
      conn
      |> Map.put(:request_path, "/api/auth/ws-token")
      |> put_req_header("cookie", "#{@user_cookie}=#{token}")
      |> RateLimit.call([])

    refute conn.halted

    assert_transport_counter_present(token)
    assert_transport_ip_counter_present()
    refute_general_session_counter_present(token)
    refute_general_ip_counter_present()
  end

  test "allows general REST bursts up to the session fairness quota", %{conn: conn} do
    token = "user-session-token"

    for _ <- 1..180 do
      conn =
        conn
        |> Map.put(:request_path, "/api/documents")
        |> put_req_header("cookie", "#{@user_cookie}=#{token}")
        |> RateLimit.call([])

      refute conn.halted
    end

    conn =
      conn
      |> Map.put(:request_path, "/api/documents")
      |> put_req_header("cookie", "#{@user_cookie}=#{token}")
      |> RateLimit.call([])

    assert conn.halted
    assert conn.status == 429
  end

  test "keeps the general IP safety net above shared-IP normal use", %{conn: conn} do
    for index <- 1..1200 do
      conn =
        conn
        |> Map.put(:request_path, "/api/documents")
        |> put_req_header("cookie", "#{@user_cookie}=shared-ip-session-#{index}")
        |> RateLimit.call([])

      refute conn.halted
    end

    conn =
      conn
      |> Map.put(:request_path, "/api/documents")
      |> put_req_header("cookie", "#{@user_cookie}=shared-ip-session-over-limit")
      |> RateLimit.call([])

    assert conn.halted
    assert conn.status == 429
  end

  test "allows shared-IP auth bursts up to the auth throttle quota", %{conn: conn} do
    for _ <- 1..60 do
      conn =
        conn
        |> Map.put(:request_path, "/api/auth/login")
        |> RateLimit.call([])

      refute conn.halted
    end

    conn =
      conn
      |> Map.put(:request_path, "/api/auth/login")
      |> RateLimit.call([])

    assert conn.halted
    assert conn.status == 429
  end

  test "uses dedicated plugin runtime audit quota", %{conn: conn} do
    token = "user-session-token"

    conn =
      conn
      |> Map.put(:method, "POST")
      |> Map.put(
        :request_path,
        "/api/workspaces/00000000-0000-4000-8000-000000000001/plugin-runtime-audit"
      )
      |> put_req_header("cookie", "#{@user_cookie}=#{token}")
      |> RateLimit.call([])

    refute conn.halted

    assert_plugin_runtime_audit_counter_present(token)
    assert_plugin_runtime_audit_ip_counter_present()
    refute_general_session_counter_present(token)
    refute_general_ip_counter_present()
  end

  test "uses dedicated plugin runtime control quota for descriptor refresh", %{conn: conn} do
    token = "user-session-token"

    conn =
      conn
      |> Map.put(:method, "GET")
      |> Map.put(
        :request_path,
        "/api/workspaces/00000000-0000-4000-8000-000000000001/plugin-runtime"
      )
      |> put_req_header("cookie", "#{@user_cookie}=#{token}")
      |> RateLimit.call([])

    refute conn.halted

    assert_plugin_runtime_control_counter_present(token)
    assert_plugin_runtime_control_ip_counter_present()
    refute_general_session_counter_present(token)
    refute_general_ip_counter_present()
  end

  test "uses dedicated plugin runtime control quota for consent-required refresh", %{conn: conn} do
    token = "user-session-token"

    conn =
      conn
      |> Map.put(:method, "GET")
      |> Map.put(
        :request_path,
        "/api/workspaces/00000000-0000-4000-8000-000000000001/plugin-runtime/consent-required"
      )
      |> put_req_header("cookie", "#{@user_cookie}=#{token}")
      |> RateLimit.call([])

    refute conn.halted

    assert_plugin_runtime_control_counter_present(token)
    assert_plugin_runtime_control_ip_counter_present()
    refute_general_session_counter_present(token)
    refute_general_ip_counter_present()
  end

  test "uses dedicated plugin runtime sandbox document quota for iframe delivery", %{
    conn: conn
  } do
    token = "user-session-token"

    conn =
      conn
      |> Map.put(:method, "GET")
      |> Map.put(
        :request_path,
        "/api/plugin-runtime/sandbox-documents/00000000-0000-4000-8000-000000000001"
      )
      |> put_req_header("cookie", "#{@user_cookie}=#{token}")
      |> RateLimit.call([])

    refute conn.halted

    assert_plugin_runtime_sandbox_document_counter_present(token)
    assert_plugin_runtime_sandbox_document_ip_counter_present()
    refute_general_session_counter_present(token)
    refute_general_ip_counter_present()
  end

  test "applies auth throttling to share password challenge requests", %{conn: conn} do
    get_conn =
      conn
      |> Map.put(:method, "GET")
      |> Map.put(:request_path, "/api/shares/test-share/challenge")
      |> RateLimit.call([])

    refute get_conn.halted

    assert Enum.any?(:ets.tab2list(RefMDWeb.Plugs.RateLimit.Storage), fn
             {{{:auth, {127, 0, 0, 1}}, _window}, _count} -> true
             _ -> false
           end)

    :ets.delete_all_objects(RefMDWeb.Plugs.RateLimit.Storage)

    conn =
      conn
      |> Map.put(:method, "POST")
      |> Map.put(:request_path, "/api/shares/test-share/challenge")
      |> RateLimit.call([])

    refute conn.halted

    assert Enum.any?(:ets.tab2list(RefMDWeb.Plugs.RateLimit.Storage), fn
             {{{:auth, {127, 0, 0, 1}}, _window}, _count} -> true
             _ -> false
           end)
  end

  test "shares target auth throttling between raw and mounted share password challenges", %{
    conn: conn
  } do
    %{share: share, share_slug: share_slug, mount: mount} = insert_mounted_share_target!()

    raw_conn =
      conn
      |> Map.put(:method, "GET")
      |> Map.put(:request_path, "/api/shares/#{share_slug}/challenge")
      |> RateLimit.call([])

    refute raw_conn.halted
    assert target_auth_counter_count(share.id) == 1

    mount_conn =
      conn
      |> Map.put(:method, "GET")
      |> Map.put(:request_path, "/api/mounts/#{mount.id}/challenge")
      |> RateLimit.call([])

    refute mount_conn.halted
    assert target_auth_counter_count(share.id) == 2
  end

  defp assert_session_counter_present(token) do
    hashed = :crypto.hash(:sha256, token)

    assert Enum.any?(:ets.tab2list(RefMDWeb.Plugs.RateLimit.Storage), fn
             {{{:session, ^hashed}, _window}, _count} -> true
             _ -> false
           end)
  end

  defp assert_transport_counter_present(token) do
    hashed = :crypto.hash(:sha256, token)

    assert Enum.any?(:ets.tab2list(RefMDWeb.Plugs.RateLimit.Storage), fn
             {{{:transport_session, {:session, ^hashed}}, _window}, _count} -> true
             _ -> false
           end)
  end

  defp assert_transport_ip_counter_present do
    assert Enum.any?(:ets.tab2list(RefMDWeb.Plugs.RateLimit.Storage), fn
             {{{:transport_ip, {127, 0, 0, 1}}, _window}, _count} -> true
             _ -> false
           end)
  end

  defp assert_plugin_runtime_audit_counter_present(token) do
    hashed = :crypto.hash(:sha256, token)

    assert Enum.any?(:ets.tab2list(RefMDWeb.Plugs.RateLimit.Storage), fn
             {{{:plugin_runtime_audit_session, {:session, ^hashed}}, _window}, _count} -> true
             _ -> false
           end)
  end

  defp assert_plugin_runtime_audit_ip_counter_present do
    assert Enum.any?(:ets.tab2list(RefMDWeb.Plugs.RateLimit.Storage), fn
             {{{:plugin_runtime_audit_ip, {127, 0, 0, 1}}, _window}, _count} -> true
             _ -> false
           end)
  end

  defp assert_plugin_runtime_control_counter_present(token) do
    hashed = :crypto.hash(:sha256, token)

    assert Enum.any?(:ets.tab2list(RefMDWeb.Plugs.RateLimit.Storage), fn
             {{{:plugin_runtime_control_session, {:session, ^hashed}}, _window}, _count} ->
               true

             _ ->
               false
           end)
  end

  defp assert_plugin_runtime_control_ip_counter_present do
    assert Enum.any?(:ets.tab2list(RefMDWeb.Plugs.RateLimit.Storage), fn
             {{{:plugin_runtime_control_ip, {127, 0, 0, 1}}, _window}, _count} -> true
             _ -> false
           end)
  end

  defp assert_plugin_runtime_sandbox_document_counter_present(token) do
    hashed = :crypto.hash(:sha256, token)

    assert Enum.any?(:ets.tab2list(RefMDWeb.Plugs.RateLimit.Storage), fn
             {{{:plugin_runtime_sandbox_document_session, {:session, ^hashed}}, _window}, _count} ->
               true

             _ ->
               false
           end)
  end

  defp assert_plugin_runtime_sandbox_document_ip_counter_present do
    assert Enum.any?(:ets.tab2list(RefMDWeb.Plugs.RateLimit.Storage), fn
             {{{:plugin_runtime_sandbox_document_ip, {127, 0, 0, 1}}, _window}, _count} ->
               true

             _ ->
               false
           end)
  end

  defp target_auth_counter_count(share_id) do
    Enum.find_value(:ets.tab2list(RefMDWeb.Plugs.RateLimit.Storage), 0, fn
      {{{:auth_target, ^share_id}, _window}, count} -> count
      _ -> false
    end)
  end

  defp insert_mounted_share_target! do
    owner_id = create_user!("owner-rate-limit@example.com")
    mount_user_id = create_user!("mount-rate-limit@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Rate Limit Workspace")
    {:ok, mount_workspace} = Workspaces.create_default_workspace(mount_user_id, "Mount Workspace")
    document = create_document!(workspace.id, owner_id)
    share_slug_bytes = :crypto.strong_rand_bytes(16)
    share_slug = Base.url_encode64(share_slug_bytes, padding: false)
    token_hash = Blake3.hash_base64url(share_slug_bytes)

    share =
      %Share{}
      |> Share.changeset(%{
        id: Ecto.UUID.generate(),
        document_id: document.id,
        scope: "document",
        token_hash: token_hash,
        token_prefix: String.slice(share_slug, 0, 4),
        authorization_public_key_material:
          share_capability_public_key_material(open_admission_key(), token_hash),
        share_capability_secret_commitment: Hash.blake3_base64url("share-capability-secret"),
        password_capability_secret_commitment: "none",
        capability_context_hash: Hash.blake3_base64url("capability-context"),
        created_event_hash: Hash.blake3_base64url("created-event"),
        authenticated_workspace_pin_bootstrap_hash: Hash.blake3_base64url("pin-bootstrap"),
        authenticated_workspace_pin_bootstrap_checkpoint: %{},
        permission: "view",
        password_protected: true,
        max_views: 100,
        expires_event_sequence: 1,
        view_count: 0,
        created_by: owner_id
      })
      |> Repo.insert!()

    mount =
      %ShareMount{}
      |> ShareMount.changeset(%{
        share_id: share.id,
        target_document_id: document.id,
        target_kind: "document",
        user_id: mount_user_id,
        workspace_id: mount_workspace.id,
        position: 0
      })
      |> Repo.insert!()

    %{share: share, share_slug: share_slug, mount: mount}
  end

  defp create_user!(email) do
    user_id = Ecto.UUID.generate()
    unique_email = String.replace(email, "@", "+#{user_id}@")

    Repo.insert!(%User{
      id: user_id,
      email: unique_email,
      name: unique_email
    })

    user_id
  end

  defp create_document!(workspace_id, owner_id) do
    {:ok, document} =
      Documents.create_document(%{
        "id" => Ecto.UUID.generate(),
        "workspace_id" => workspace_id,
        "doc_type" => "document",
        "title" => "Rate limited document",
        "encrypted_title" => <<1, 2, 3>>,
        "encrypted_title_nonce" => :crypto.strong_rand_bytes(24),
        "encrypted_title_key_version" => 1,
        "created_by" => owner_id
      })

    document
  end

  defp refute_session_counter_present(token) do
    hashed = :crypto.hash(:sha256, token)

    refute Enum.any?(:ets.tab2list(RefMDWeb.Plugs.RateLimit.Storage), fn
             {{{:session, ^hashed}, _window}, _count} -> true
             _ -> false
           end)
  end

  defp refute_general_session_counter_present(token) do
    hashed = :crypto.hash(:sha256, token)

    refute Enum.any?(:ets.tab2list(RefMDWeb.Plugs.RateLimit.Storage), fn
             {{{:session, ^hashed}, _window}, _count} -> true
             _ -> false
           end)
  end

  defp refute_general_ip_counter_present do
    refute Enum.any?(:ets.tab2list(RefMDWeb.Plugs.RateLimit.Storage), fn
             {{{:ip, {127, 0, 0, 1}}, _window}, _count} -> true
             _ -> false
           end)
  end
end
