defmodule RefMDWeb.Plugs.RequireGenesisSession do
  @moduledoc false

  import Phoenix.Controller
  import Plug.Conn

  alias RefMD.Auth.Genesis
  alias RefMDWeb.Http.SessionCookies

  def init(opts), do: opts

  def call(conn, _opts) do
    conn = fetch_cookies(conn)

    with nil <- conn.req_cookies[SessionCookies.session_cookie_name("user")],
         value when is_binary(value) <- conn.req_cookies[SessionCookies.genesis_cookie_name()],
         {:ok, token} <- Genesis.decode_cookie(value),
         {:ok, genesis, session} <- Genesis.get_pending_by_token(token) do
      conn
      |> assign(:pending_account_genesis, genesis)
      |> assign(:pending_genesis_session, session)
      |> assign(:pending_genesis_token, token)
    else
      _ ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "invalid_genesis_session"})
        |> halt()
    end
  end
end
