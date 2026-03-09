defmodule RefMDWeb.Plugs.VerifyOrigin do
  @moduledoc """
  CSRF protection via Origin header verification for PoP-exempt mutating endpoints.

  In SameSite=Lax deployments, the cookie attribute itself prevents CSRF.
  In SameSite=None deployments, this plug enforces Origin verification
  on POST/PATCH/DELETE requests as required by the design (web-security.md).

  PoP-required endpoints are already protected by device signature verification
  (PoP acts as a CSRF token equivalent).
  """

  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    if Application.get_env(:refmd, :samesite_mode, "lax") != "none" do
      # SameSite=Lax: cookie attribute prevents CSRF; no Origin check needed
      conn
    else
      # SameSite=None: enforce Origin verification on POST/PATCH/DELETE only (web-security.md).
      # GET/HEAD/OPTIONS are exempt — browsers may omit Origin on same-origin GETs.
      # SSE endpoints are routed through a separate pipeline without this plug.
      if conn.method in ["GET", "HEAD", "OPTIONS"] do
        conn
      else
        allowed_origins = Application.get_env(:refmd, :cors_origins, [])

        case get_req_header(conn, "origin") do
          [origin] ->
            if origin in allowed_origins do
              conn
            else
              conn
              |> put_status(:forbidden)
              |> Phoenix.Controller.json(%{error: "origin_not_allowed"})
              |> halt()
            end

          [] ->
            conn
            |> put_status(:forbidden)
            |> Phoenix.Controller.json(%{error: "origin_required"})
            |> halt()

          _multiple ->
            conn
            |> put_status(:forbidden)
            |> Phoenix.Controller.json(%{error: "invalid_origin"})
            |> halt()
        end
      end
    end
  end
end
