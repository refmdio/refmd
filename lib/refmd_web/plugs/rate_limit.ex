defmodule RefMDWeb.Plugs.RateLimit do
  @moduledoc """
  Multi-layer rate limiting plug using ETS counters.

  Three independent throttle layers, ALL incremented for every request:
  1. IP safety net (300/60s) — prevents cookie rotation bypass
  2. Session fairness (120/60s) — per-session quota with IP fallback
  3. Auth brute force (20/60s) — IP-based on public auth endpoints only

  Returns 429 Too Many Requests with JSON body and Retry-After header.
  """

  @behaviour Plug
  import Plug.Conn

  @ip_limit 300
  @session_limit 120
  @auth_limit 20
  @period_ms 60_000

  @auth_throttle_paths [
    "/api/auth/login",
    "/api/auth/salt",
    "/api/auth/register",
    "/api/auth/recovery/challenge",
    "/api/auth/recovery/session",
    "/api/auth/password-reset/request",
    "/api/auth/password-reset/verify"
  ]

  @spec init(keyword()) :: keyword()
  def init(opts), do: opts

  @spec call(Plug.Conn.t(), keyword()) :: Plug.Conn.t()
  def call(conn, _opts) do
    now = System.system_time(:millisecond)

    results = [
      check_throttle({:ip, conn.remote_ip}, @ip_limit, now),
      check_throttle(session_key(conn), @session_limit, now)
      | if(conn.request_path in @auth_throttle_paths,
          do: [check_throttle({:auth, conn.remote_ip}, @auth_limit, now)],
          else: []
        )
    ]

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

  defp extract_session_token(conn) do
    conn
    |> get_req_header("cookie")
    |> parse_session_cookie()
  end

  defp parse_session_cookie([cookie_header | _]) do
    cookie_header
    |> String.split(";")
    |> Enum.find_value(fn part ->
      case String.trim(part) |> String.split("=", parts: 2) do
        ["_refmd_session", value] -> value
        _ -> nil
      end
    end)
  end

  defp parse_session_cookie(_), do: nil

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
