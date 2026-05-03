defmodule RefMDWeb.RateLimitTest do
  use RefMDWeb.ConnCase, async: false

  alias RefMDWeb.Plugs.RateLimit

  @user_cookie "_refmd_session"
  @share_cookie "_refmd_share_session"

  setup do
    :ets.delete_all_objects(RefMDWeb.Plugs.RateLimit.Storage)
    :ok
  end

  test "uses the user session cookie for share mount lookups", %{conn: conn} do
    user_token = "user-session-token"
    share_token = "share-session-token"

    conn =
      conn
      |> Map.put(:request_path, "/api/shares/test-share/mounts")
      |> put_req_header(
        "cookie",
        "#{@user_cookie}=#{user_token}; #{@share_cookie}=#{share_token}"
      )
      |> RateLimit.call([])

    refute conn.halted

    assert_session_counter_present(user_token)
    refute_session_counter_present(share_token)
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
