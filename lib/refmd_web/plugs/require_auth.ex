defmodule RefMDWeb.Plugs.RequireAuth do
  @moduledoc """
  Plug that validates session token from cookie and assigns current user/session.
  """

  import Plug.Conn
  alias RefMD.Auth
  alias RefMD.Auth.DBSC
  alias RefMD.Devices
  alias RefMD.Sharing

  @user_session_cookie "__Host-refmd-session"
  @share_session_cookie "__Host-refmd-share-session"
  @mount_session_cookie "__Host-refmd-mount-session"
  @share_session_scope_header "x-refmd-session-scope"
  @dbsc_exempt_paths MapSet.new([
                       "/api/auth/dbsc/register",
                       "/api/auth/dbsc/refresh",
                       "/api/auth/dbsc/share/register",
                       "/api/auth/dbsc/share/refresh"
                     ])

  def init(opts), do: opts

  def call(conn, opts) do
    cookies = parse_session_cookies(conn)

    with token when is_binary(token) <- select_session_token(cookies, conn, opts),
         {:ok, auth_assigns} <- resolve_session_assigns(token, opts),
         :ok <- require_dbsc_bound_cookie(conn, cookies, Map.new(auth_assigns)) do
      Enum.reduce(auth_assigns, conn, fn {key, value}, acc -> assign(acc, key, value) end)
    else
      {:error, {:dbsc_required, binding}} ->
        conn
        |> RefMDWeb.Http.DBSC.put_challenge_header(binding)
        |> put_status(:unauthorized)
        |> Phoenix.Controller.json(%{error: "dbsc_required"})
        |> halt()

      _ ->
        conn
        |> put_status(:unauthorized)
        |> Phoenix.Controller.json(%{error: "unauthorized"})
        |> halt()
    end
  end

  defp parse_session_cookies(conn) do
    conn
    |> get_req_header("cookie")
    |> parse_session_cookie()
  end

  defp require_dbsc_bound_cookie(%{request_path: path}, cookies, auth_assigns)
       when is_binary(path) do
    if MapSet.member?(@dbsc_exempt_paths, path) do
      :ok
    else
      do_require_dbsc_bound_cookie(cookies, auth_assigns)
    end
  end

  defp do_require_dbsc_bound_cookie(cookies, %{
         current_session: %{id: session_id},
         session_kind: session_kind
       }) do
    session_kind = dbsc_session_kind(session_kind)

    case DBSC.bound_cookie_status(
           session_kind,
           session_id,
           Map.get(cookies, dbsc_cookie(session_kind))
         ) do
      :not_registered -> :ok
      {:ok, _binding} -> :ok
      {:error, binding} -> {:error, {:dbsc_required, binding}}
    end
  end

  defp do_require_dbsc_bound_cookie(_cookies, _auth_assigns), do: :ok

  defp dbsc_session_kind(:share_participant), do: "share_participant"
  defp dbsc_session_kind(_), do: "user"

  defp dbsc_cookie("share_participant"), do: @share_session_cookie
  defp dbsc_cookie("mount"), do: @mount_session_cookie
  defp dbsc_cookie(_), do: @user_session_cookie

  defp select_session_token(cookies, conn, opts) do
    cond do
      Keyword.get(opts, :prefer_share_participant, false) ->
        Map.get(cookies, @share_session_cookie)

      prefer_share_session?(conn, opts) ->
        Map.get(cookies, @share_session_cookie)

      true ->
        Map.get(cookies, @user_session_cookie)
    end
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
