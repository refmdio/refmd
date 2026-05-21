defmodule RefMDWeb.Http.SessionCookies do
  @moduledoc false

  @user_session_cookie "_refmd_session"
  @share_session_cookie "_refmd_share_session"
  @mount_session_cookie "_refmd_mount_session"

  @spec set_session_cookie(Plug.Conn.t(), binary(), boolean()) :: Plug.Conn.t()
  def set_session_cookie(conn, token, remember_me) do
    put_session_cookie(conn, @user_session_cookie, token, remember_me)
  end

  @spec set_share_session_cookie(Plug.Conn.t(), binary(), boolean()) :: Plug.Conn.t()
  def set_share_session_cookie(conn, token, remember_me) do
    put_session_cookie(conn, @share_session_cookie, token, remember_me)
  end

  @spec set_mount_session_cookie(Plug.Conn.t(), binary(), boolean()) :: Plug.Conn.t()
  def set_mount_session_cookie(conn, token, remember_me) do
    put_session_cookie(conn, @mount_session_cookie, token, remember_me)
  end

  @spec delete_session_cookie(Plug.Conn.t()) :: Plug.Conn.t()
  def delete_session_cookie(conn) do
    Plug.Conn.delete_resp_cookie(conn, @user_session_cookie, path: "/api")
  end

  @spec delete_share_session_cookie(Plug.Conn.t()) :: Plug.Conn.t()
  def delete_share_session_cookie(conn) do
    Plug.Conn.delete_resp_cookie(conn, @share_session_cookie, path: "/api")
  end

  @spec delete_mount_session_cookie(Plug.Conn.t()) :: Plug.Conn.t()
  def delete_mount_session_cookie(conn) do
    Plug.Conn.delete_resp_cookie(conn, @mount_session_cookie, path: "/api")
  end

  defp put_session_cookie(conn, cookie_name, token, remember_me) do
    token_base64 = Base.url_encode64(token, padding: false)
    max_age = if remember_me, do: 30 * 24 * 60 * 60, else: 24 * 60 * 60

    same_site =
      case Application.get_env(:refmd, :samesite_mode, "lax") do
        "none" -> "None"
        _ -> "Lax"
      end

    opts = [
      path: "/api",
      http_only: true,
      secure:
        Application.get_env(:refmd, :cookie_secure, conn.scheme == :https) or
          same_site == "None",
      same_site: same_site
    ]

    Plug.Conn.put_resp_cookie(conn, cookie_name, token_base64, [{:max_age, max_age} | opts])
  end
end
