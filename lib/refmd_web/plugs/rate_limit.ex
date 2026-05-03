defmodule RefMDWeb.Plugs.RateLimit do
  @moduledoc """
  Multi-layer rate limiting plug using ETS counters.

  REST requests use the general IP/session/auth limits. Transport-auth endpoints
  use a separate quota so reconnect and PoP recovery do not exhaust the general
  REST budget during normal multi-tab recovery.

  Returns 429 Too Many Requests with JSON body and Retry-After header.
  """

  @behaviour Plug
  import Plug.Conn

  @ip_limit 300
  @session_limit 120
  @transport_auth_ip_limit 1200
  @transport_auth_session_limit 600
  @auth_limit 20
  @period_ms 60_000
  @user_session_cookie "_refmd_session"
  @share_session_cookie "_refmd_share_session"
  @share_session_scope_header "x-refmd-session-scope"
  @e2e_rate_limit_bypass_header "x-refmd-e2e-rate-limit-bypass"

  @auth_throttle_paths [
    "/api/auth/login",
    "/api/auth/salt",
    "/api/auth/register",
    "/api/auth/recovery/challenge",
    "/api/auth/recovery/session",
    "/api/auth/password-reset/request",
    "/api/auth/password-reset/verify"
  ]

  @transport_auth_paths [
    "/api/auth/pop-challenge",
    "/api/auth/ws-token"
  ]

  @spec init(keyword()) :: keyword()
  def init(opts), do: opts

  @spec call(Plug.Conn.t(), keyword()) :: Plug.Conn.t()
  def call(conn, _opts) do
    if e2e_rate_limit_bypass?(conn) do
      conn
    else
      enforce_rate_limit(conn)
    end
  end

  defp enforce_rate_limit(conn) do
    now = System.system_time(:millisecond)

    results = throttle_results(conn, now)

    case Enum.find(results, &match?({:blocked, _}, &1)) do
      {:blocked, expires_at} ->
        retry_after = max(ceil((expires_at - now) / 1000), 1)

        conn
        |> put_resp_header("retry-after", Integer.to_string(retry_after))
        |> put_resp_content_type("application/json")
        |> send_resp(
          429,
          Jason.encode!(%{error: "rate_limit_exceeded", retry_after: retry_after})
        )
        |> halt()

      nil ->
        conn
    end
  end

  defp e2e_rate_limit_bypass?(conn) do
    System.get_env("REFMD_E2E_RATE_LIMIT_BYPASS") == "1" and
      local_request?(conn.remote_ip) and
      get_req_header(conn, @e2e_rate_limit_bypass_header) == ["1"]
  end

  defp local_request?({127, 0, 0, 1}), do: true
  defp local_request?({0, 0, 0, 0, 0, 0, 0, 1}), do: true
  defp local_request?(_), do: false

  defp session_key(conn) do
    case extract_session_token(conn) do
      nil -> {:ip_session, conn.remote_ip}
      token -> {:session, :crypto.hash(:sha256, token)}
    end
  end

  defp throttle_results(conn, now) do
    if transport_auth_request?(conn) do
      [
        check_throttle({:transport_ip, conn.remote_ip}, @transport_auth_ip_limit, now),
        check_throttle(
          {:transport_session, session_key(conn)},
          @transport_auth_session_limit,
          now
        )
      ]
    else
      [check_throttle({:ip, conn.remote_ip}, @ip_limit, now)] ++
        [check_throttle(session_key(conn), @session_limit, now)] ++
        if(auth_throttle_request?(conn),
          do: [check_throttle({:auth, conn.remote_ip}, @auth_limit, now)],
          else: []
        )
    end
  end

  defp extract_session_token(conn) do
    conn
    |> get_req_header("cookie")
    |> parse_session_cookie()
    |> select_session_token(conn)
  end

  defp parse_session_cookie([cookie_header | _]) do
    cookie_header
    |> String.split(";")
    |> Enum.map(&String.trim/1)
    |> Enum.reduce(%{}, fn part, acc ->
      case String.split(part, "=", parts: 2) do
        [key, value] -> Map.put(acc, key, value)
        _ -> acc
      end
    end)
  end

  defp parse_session_cookie(_), do: %{}

  defp select_session_token(cookies, conn) do
    if share_session_request?(conn) do
      Map.get(cookies, @share_session_cookie)
    else
      Map.get(cookies, @user_session_cookie)
    end
  end

  defp share_session_request?(conn) do
    share_owned_request_path?(conn.request_path) or
      get_req_header(conn, @share_session_scope_header) |> List.first() == "share"
  end

  defp share_owned_request_path?(path) do
    String.match?(path, ~r<^/api/shares/[^/]+/bootstrap$>) or
      String.match?(path, ~r<^/api/shares/[^/]+/challenge$>) or
      String.match?(path, ~r<^/api/shares/d/[^/]+$>) or
      String.match?(path, ~r<^/api/shares/f/[^/]+$>)
  end

  defp auth_throttle_request?(conn) do
    conn.request_path in @auth_throttle_paths or
      String.match?(conn.request_path, ~r<^/api/shares/[^/]+/challenge$>)
  end

  defp transport_auth_request?(conn), do: conn.request_path in @transport_auth_paths

  defp check_throttle(key, limit, now) do
    table = RefMDWeb.Plugs.RateLimit.Storage
    window_start = div(now, @period_ms)
    counter_key = {key, window_start}
    expires_at = (window_start + 1) * @period_ms

    count =
      case :ets.update_counter(table, counter_key, {2, 1}, {counter_key, 0}) do
        n when is_integer(n) -> n
      end

    if count > limit do
      {:blocked, expires_at}
    else
      :ok
    end
  end
end
