defmodule RefMDWeb.Plugs.VerifyOrigin do
  @moduledoc """
  CSRF protection via Origin header verification for PoP-exempt mutating endpoints.

  In SameSite=Lax deployments, the cookie attribute itself prevents CSRF.
  In SameSite=None deployments, this plug enforces Origin verification
  on POST/PATCH/DELETE requests.

  PoP-required endpoints are already protected by device signature verification
  (PoP acts as a CSRF token equivalent).
  """

  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    samesite_mode = Application.get_env(:refmd, :samesite_mode, "lax")

    cond do
      samesite_mode != "none" ->
        conn

      conn.method in ["GET", "HEAD", "OPTIONS"] ->
        conn

      true ->
        verify_origin_header(conn)
    end
  end

  defp verify_origin_header(conn) do
    allowed_origins = Application.get_env(:refmd, :cors_origins, [])

    case get_req_header(conn, "origin") do
      [origin] ->
        if origin in allowed_origins do
          conn
        else
          reject_origin(conn, "origin_not_allowed")
        end

      [] ->
        reject_origin(conn, "origin_required")

      _multiple ->
        reject_origin(conn, "invalid_origin")
    end
  end

  defp reject_origin(conn, error) do
    conn
    |> put_status(:forbidden)
    |> Phoenix.Controller.json(%{error: error})
    |> halt()
  end
end
