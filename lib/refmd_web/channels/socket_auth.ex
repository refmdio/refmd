defmodule RefMDWeb.SocketAuth do
  @moduledoc """
  Extracts the auth session token from the WebSocket upgrade request cookies.
  Used as a custom connect_info MFA in the endpoint socket configuration.
  """

  @spec extract_session_token(Plug.Conn.t()) :: String.t() | nil
  def extract_session_token(conn) do
    conn = Plug.Conn.fetch_cookies(conn)
    conn.cookies["_refmd_session"]
  end

  @spec extract_origin(Plug.Conn.t()) :: String.t() | nil
  def extract_origin(conn) do
    case Plug.Conn.get_req_header(conn, "origin") do
      [origin | _] -> origin
      [] -> nil
    end
  end

  @spec check_origin(URI.t()) :: boolean()
  def check_origin(%URI{} = origin) do
    allowed = Application.get_env(:refmd, :cors_origins, [])

    case allowed do
      [] ->
        samesite = Application.get_env(:refmd, :samesite_mode, "lax")
        samesite != "none"

      origins ->
        URI.to_string(%{origin | path: nil, query: nil, fragment: nil}) in origins
    end
  end

  @spec verify_origin_policy(String.t() | nil) :: :ok | {:error, :origin_required}
  def verify_origin_policy(nil) do
    samesite = Application.get_env(:refmd, :samesite_mode, "lax")

    if samesite == "none" do
      {:error, :origin_required}
    else
      :ok
    end
  end

  def verify_origin_policy(_origin), do: :ok
end
