defmodule RefMDWeb.Plugs.CSP do
  @moduledoc """
  Sets Content-Security-Policy and security headers.

  In development (ENABLE_SWAGGER=true), a relaxed policy is applied.
  Otherwise the strict production policy is used.

  A per-request nonce is generated and stored in conn.private[:csp_nonce]
  for inclusion in HTML templates as `<link>` / `<style>` nonce attributes.
  The current production CSP does not require nonces (style-src-elem uses
  'unsafe-inline'); the nonce is preserved for forward compatibility.

  connect-src includes WebSocket origins derived from the configured
  endpoint URL to support Phoenix Channel connections.
  """

  import Plug.Conn

  @spec init(keyword()) :: keyword()
  def init(opts), do: opts

  @spec call(Plug.Conn.t(), keyword()) :: Plug.Conn.t()
  def call(conn, _opts) do
    nonce = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    conn
    |> put_private(:csp_nonce, nonce)
    |> put_resp_header("content-security-policy", csp_value())
    |> put_resp_header("x-content-type-options", "nosniff")
    |> put_resp_header("x-frame-options", "DENY")
    |> put_resp_header(
      "strict-transport-security",
      "max-age=31536000; includeSubDomains"
    )
    |> put_resp_header("referrer-policy", "strict-origin-when-cross-origin")
    |> put_resp_header("permissions-policy", "geolocation=(), microphone=(), camera=()")
  end

  defp csp_value do
    if swagger_enabled?() do
      swagger_csp()
    else
      production_csp()
    end
  end

  defp production_csp do
    ws_origins = websocket_origins()

    directives = [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "style-src-elem 'self' 'unsafe-inline'",
      "style-src-attr 'unsafe-inline'",
      "img-src 'self' blob: data:",
      "media-src 'self' blob:",
      "font-src 'self'",
      "connect-src 'self' #{ws_origins}",
      "worker-src 'self'",
      "frame-src 'self' blob:",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "object-src 'none'"
    ]

    Enum.join(directives, "; ")
  end

  defp swagger_csp do
    directives = [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data:",
      "frame-ancestors 'none'"
    ]

    Enum.join(directives, "; ")
  end

  defp websocket_origins do
    url = Application.get_env(:refmd, RefMDWeb.Endpoint)[:url] || []
    host = Keyword.get(url, :host, "localhost")
    port = Keyword.get(url, :port, 443)
    http_scheme = Keyword.get(url, :scheme, "https")
    ws_scheme = if http_scheme == "https", do: "wss", else: "ws"

    "#{ws_scheme}://#{host}:#{port} #{http_scheme}://#{host}:#{port}"
  end

  defp swagger_enabled? do
    System.get_env("ENABLE_SWAGGER") == "true"
  end
end
