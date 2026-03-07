defmodule RefMDWeb.Plugs.RequireAuth do
  @moduledoc """
  Plug that validates session token from cookie and assigns current user/session.
  """

  import Plug.Conn
  alias RefMD.Accounts

  def init(opts), do: opts

  def call(conn, _opts) do
    with token when is_binary(token) <- get_session_token(conn),
         {:ok, session} <- Accounts.get_valid_session_by_token(token) do
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
end
