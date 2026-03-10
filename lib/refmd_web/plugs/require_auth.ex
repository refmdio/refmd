defmodule RefMDWeb.Plugs.RequireAuth do
  @moduledoc """
  Plug that validates session token from cookie and assigns current user/session.
  """

  import Plug.Conn
  alias RefMD.Accounts

  @spec init(keyword()) :: keyword()
  def init(opts), do: opts

  @spec call(Plug.Conn.t(), keyword()) :: Plug.Conn.t()
  def call(conn, _opts) do
    with token when is_binary(token) <- get_session_token(conn),
         {:ok, session} <- Accounts.get_valid_session_by_token_base64(token) do
      Accounts.touch_session(session.id)

      device_verified = device_verified?(session)

      conn
      |> assign(:current_user_id, session.user_id)
      |> assign(:current_session, session)
      |> assign(:device_verified, device_verified)
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

  defp device_verified?(%{device_id: nil}), do: false

  defp device_verified?(%{device_id: device_id, user_id: user_id}) do
    case Accounts.get_device(device_id) do
      %{user_id: ^user_id, revoked_at: nil} -> true
      _ -> false
    end
  end
end
