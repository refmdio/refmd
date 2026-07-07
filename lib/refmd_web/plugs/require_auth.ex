defmodule RefMDWeb.Plugs.RequireAuth do
  @moduledoc """
  Plug that validates session token from cookie and assigns current user/session.
  """

  import Plug.Conn
  alias RefMD.Auth
  alias RefMD.Devices
  alias RefMD.Sharing

  @user_session_cookie "_refmd_session"
  @share_session_cookie "_refmd_share_session"
  @share_session_scope_header "x-refmd-session-scope"

  def init(opts), do: opts

  def call(conn, opts) do
    with token when is_binary(token) <- get_session_token(conn, opts),
         {:ok, auth_assigns} <- resolve_session_assigns(token, opts) do
      Enum.reduce(auth_assigns, conn, fn {key, value}, acc -> assign(acc, key, value) end)
    else
      _ ->
        conn
        |> put_status(:unauthorized)
        |> Phoenix.Controller.json(%{error: "unauthorized"})
        |> halt()
    end
  end

  defp get_session_token(conn, opts) do
    conn
    |> get_req_header("cookie")
    |> parse_session_cookie()
    |> select_session_token(conn, opts)
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

  defp select_session_token(cookies, conn, opts) do
    if prefer_share_session?(conn, opts) do
      Map.get(cookies, @share_session_cookie)
    else
      Map.get(cookies, @user_session_cookie)
    end
  end

  defp prefer_share_session?(conn, opts) do
    Keyword.get(opts, :allow_share_participant, false) and
      get_req_header(conn, @share_session_scope_header) |> List.first() == "share"
  end

  defp resolve_session_assigns(token, opts) do
    case Auth.get_valid_session_by_token_base64(token) do
      {:ok, session} ->
        Auth.touch_session(session.id)

        {:ok,
         [
           current_user_id: session.user_id,
           current_session: session,
           device_verified: device_verified?(session),
           session_kind: :user
         ]}

      _ ->
        if Keyword.get(opts, :allow_share_participant, false) do
          do_resolve_share_session_assigns(token)
        else
          {:error, :invalid_session}
        end
    end
  end

  defp do_resolve_share_session_assigns(token) do
    with {:ok, session} <- Sharing.get_valid_participant_session_by_token_base64(token) do
      {:ok,
       [
         current_user_id: session.principal_id,
         current_session: session,
         current_share_id: session.share_id,
         share_participant_principal_id: session.principal_id,
         share_participant_grant: session.grant,
         device_verified: share_device_verified?(session),
         session_kind: :share_participant
       ]}
    end
  end

  defp device_verified?(%{device_id: nil}), do: false

  defp device_verified?(%{device_id: device_id, user_id: user_id}) do
    match?(%{user_id: ^user_id, revoked_at: nil}, Devices.get_device(device_id))
  end

  defp share_device_verified?(%{device_id: nil}), do: false

  defp share_device_verified?(%{device_id: device_id, principal_id: principal_id}) do
    Sharing.participant_owns_device?(principal_id, device_id)
  end
end
