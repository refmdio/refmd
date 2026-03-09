defmodule RefMDWeb.Plugs.RequireAuth do
  @moduledoc """
  Plug that validates session token from cookie and assigns current user/session.
  """

  import Plug.Conn
  alias RefMD.Accounts

  def init(opts), do: opts

  @touch_interval_seconds 5 * 60

  def call(conn, _opts) do
    with token when is_binary(token) <- get_session_token(conn),
         {:ok, session} <- Accounts.get_valid_session_by_token_base64(token) do
      maybe_touch_session(session)

      conn
      |> assign(:current_user_id, session.user_id)
      |> assign(:current_session, session)
      |> assign(:device_verified, session.device_id != nil)
    else
      _ ->
        conn
        |> put_status(:unauthorized)
        |> Phoenix.Controller.json(%{error: "unauthorized"})
        |> halt()
    end
  end

  defp get_session_token(conn) do
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

  defp maybe_touch_session(session) do
    elapsed = DateTime.diff(DateTime.utc_now(), session.last_seen_at, :second)

    if elapsed >= @touch_interval_seconds do
      Accounts.touch_session(session.id)
    end
  end
end
