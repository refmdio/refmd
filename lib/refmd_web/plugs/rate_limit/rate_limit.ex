defmodule RefMDWeb.Plugs.RateLimit do
  @moduledoc """
  Multi-layer rate limiting plug using ETS counters.

  REST requests use the general IP/session/auth limits. Transport-auth endpoints
  use a separate quota so reconnect and RRP recovery do not exhaust the general
  REST budget during normal multi-tab recovery.

  Returns 429 Too Many Requests with JSON body and Retry-After header.
  """

  @behaviour Plug
  import Plug.Conn

  alias RefMD.Sharing

  @ip_limit 1200
  @session_limit 180
  @transport_auth_ip_limit 1200
  @transport_auth_session_limit 600
  @plugin_runtime_control_ip_limit 2400
  @plugin_runtime_control_session_limit 1200
  @plugin_runtime_audit_ip_limit 2400
  @plugin_runtime_audit_session_limit 1200
  @plugin_runtime_sandbox_document_ip_limit 2400
  @plugin_runtime_sandbox_document_session_limit 1200
  @auth_limit 60
  @auth_target_limit 20
  @period_ms 60_000
  @user_session_cookie "__Host-refmd-session"
  @share_session_cookie "__Host-refmd-share-session"
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
    "/api/auth/rrp-challenge",
    "/api/auth/ws-token"
  ]

  def init(opts), do: opts

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

  defp session_key(conn) do
    case extract_session_token(conn) do
      nil -> {:ip_session, conn.remote_ip}
      token -> {:session, :crypto.hash(:sha256, token)}
    end
  end

  defp e2e_rate_limit_bypass?(conn) do
    e2e_rate_limit_bypass_enabled?() and
      local_request?(conn.remote_ip) and
      get_req_header(conn, @e2e_rate_limit_bypass_header) == ["1"]
  end

  defp e2e_rate_limit_bypass_enabled? do
    Application.get_env(:refmd, :e2e_rate_limit_bypass, false) or
      System.get_env("REFMD_E2E_RATE_LIMIT_BYPASS") == "1"
  end

  defp local_request?({127, 0, 0, 1}), do: true
  defp local_request?({0, 0, 0, 0, 0, 0, 0, 1}), do: true
  defp local_request?(_), do: false

  defp throttle_results(conn, now) do
    cond do
      transport_auth_request?(conn) ->
        [
          check_throttle({:transport_ip, conn.remote_ip}, @transport_auth_ip_limit, now),
          check_throttle(
            {:transport_session, session_key(conn)},
            @transport_auth_session_limit,
            now
          )
        ]

      plugin_runtime_audit_request?(conn) ->
        [
          check_throttle(
            {:plugin_runtime_audit_ip, conn.remote_ip},
            @plugin_runtime_audit_ip_limit,
            now
          ),
          check_throttle(
            {:plugin_runtime_audit_session, session_key(conn)},
            @plugin_runtime_audit_session_limit,
            now
          )
        ]

      plugin_runtime_sandbox_document_request?(conn) ->
        [
          check_throttle(
            {:plugin_runtime_sandbox_document_ip, conn.remote_ip},
            @plugin_runtime_sandbox_document_ip_limit,
            now
          ),
          check_throttle(
            {:plugin_runtime_sandbox_document_session, session_key(conn)},
            @plugin_runtime_sandbox_document_session_limit,
            now
          )
        ]

      plugin_runtime_control_request?(conn) ->
        [
          check_throttle(
            {:plugin_runtime_control_ip, conn.remote_ip},
            @plugin_runtime_control_ip_limit,
            now
          ),
          check_throttle(
            {:plugin_runtime_control_session, session_key(conn)},
            @plugin_runtime_control_session_limit,
            now
          )
        ]

      true ->
        [check_throttle({:ip, conn.remote_ip}, @ip_limit, now)] ++
          [check_throttle(session_key(conn), @session_limit, now)] ++
          auth_throttle_results(conn, now)
    end
  end

  defp auth_throttle_results(conn, now) do
    if auth_throttle_request?(conn) do
      [check_throttle({:auth, conn.remote_ip}, @auth_limit, now)] ++
        target_auth_throttle_results(conn.request_path, now)
    else
      []
    end
  end

  defp target_auth_throttle_results(path, now) do
    case share_challenge_rate_limit_share_id(path) do
      share_id when is_binary(share_id) ->
        [check_throttle({:auth_target, share_id}, @auth_target_limit, now)]

      _ ->
        []
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
      String.match?(conn.request_path, ~r<^/api/shares/[^/]+/challenge$>) or
      String.match?(conn.request_path, ~r<^/api/mounts/[^/]+/challenge$>)
  end

  defp share_challenge_rate_limit_share_id(path) do
    case Regex.run(~r<^/api/shares/([^/]+)/challenge$>, path) do
      [_, share_slug] ->
        Sharing.password_challenge_rate_limit_share_id(share_slug)

      _ ->
        case Regex.run(~r<^/api/mounts/([^/]+)/challenge$>, path) do
          [_, mount_id] -> Sharing.mount_challenge_rate_limit_share_id(mount_id)
          _ -> nil
        end
    end
  end

  defp transport_auth_request?(conn), do: conn.request_path in @transport_auth_paths

  defp plugin_runtime_audit_request?(conn) do
    String.match?(
      conn.request_path,
      ~r<^/api/workspaces/[^/]+/plugin-runtime-audit$>
    )
  end

  defp plugin_runtime_control_request?(conn) do
    conn.method == "GET" and
      String.match?(
        conn.request_path,
        ~r<^/api/workspaces/[^/]+/plugin-runtime(?:/consent-required)?$>
      )
  end

  defp plugin_runtime_sandbox_document_request?(conn) do
    conn.method == "GET" and
      String.match?(
        conn.request_path,
        ~r<^/api/plugin-runtime/sandbox-documents/[^/]+$>
      )
  end

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
