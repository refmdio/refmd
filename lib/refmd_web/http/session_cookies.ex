defmodule RefMDWeb.Http.SessionCookies do
  @moduledoc false

  alias RefMD.Auth.DBSC

  @user_session_cookie "__Host-refmd-session"
  @share_session_cookie "__Host-refmd-share-session"
  @mount_session_cookie "__Host-refmd-mount-session"

  def set_session_cookie(conn, token, remember_me) do
    put_session_cookie(conn, @user_session_cookie, token, remember_me)
  end

  def set_share_session_cookie(conn, token, remember_me) do
    put_session_cookie(conn, @share_session_cookie, token, remember_me)
  end

  def set_mount_session_cookie(conn, token, remember_me) do
    put_session_cookie(conn, @mount_session_cookie, token, remember_me)
  end

  def set_bound_session_cookie(conn, "share_participant", token) do
    put_session_cookie(conn, @share_session_cookie, token, DBSC.credential_ttl_seconds())
  end

  def set_bound_session_cookie(conn, "mount", token) do
    put_session_cookie(conn, @mount_session_cookie, token, DBSC.credential_ttl_seconds())
  end

  def set_bound_session_cookie(conn, _session_kind, token) do
    put_session_cookie(conn, @user_session_cookie, token, DBSC.credential_ttl_seconds())
  end

  def session_cookie_name("share_participant"), do: @share_session_cookie
  def session_cookie_name("mount"), do: @mount_session_cookie
  def session_cookie_name(_), do: @user_session_cookie

  def delete_session_cookie(conn) do
    Plug.Conn.delete_resp_cookie(conn, @user_session_cookie, path: "/")
  end

  def delete_share_session_cookie(conn) do
    Plug.Conn.delete_resp_cookie(conn, @share_session_cookie, path: "/")
  end

  def delete_mount_session_cookie(conn) do
    Plug.Conn.delete_resp_cookie(conn, @mount_session_cookie, path: "/")
  end

  defp put_session_cookie(conn, cookie_name, token, remember_me) when is_boolean(remember_me) do
    max_age = if remember_me, do: 30 * 24 * 60 * 60, else: 24 * 60 * 60

    put_session_cookie(conn, cookie_name, token, max_age)
  end

  defp put_session_cookie(conn, cookie_name, token, max_age) when is_integer(max_age) do
    token_base64 = Base.url_encode64(token, padding: false)

    same_site =
      case Application.get_env(:refmd, :samesite_mode, "lax") do
        "none" -> "None"
        _ -> "Lax"
      end

    opts = [
      path: "/",
      http_only: true,
      secure: true,
      same_site: same_site
    ]

    Plug.Conn.put_resp_cookie(conn, cookie_name, token_base64, [{:max_age, max_age} | opts])
  end
end
