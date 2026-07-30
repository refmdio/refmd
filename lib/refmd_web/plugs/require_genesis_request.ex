defmodule RefMDWeb.Plugs.RequireGenesisRequest do
  @moduledoc false

  import Phoenix.Controller
  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    with [origin] <- get_req_header(conn, "origin"),
         true <- same_origin?(conn, origin),
         ["same-origin"] <- get_req_header(conn, "sec-fetch-site"),
         [content_type] <- get_req_header(conn, "content-type"),
         true <- json_content_type?(content_type) do
      conn
    else
      _ -> reject(conn)
    end
  end

  defp same_origin?(conn, origin) do
    configured = Application.get_env(:refmd, :cors_origins, [])
    origin == request_origin(conn) or origin in configured
  end

  defp request_origin(conn) do
    scheme = conn.scheme |> Atom.to_string()
    default_port = if conn.scheme == :https, do: 443, else: 80
    port = if conn.port == default_port, do: "", else: ":#{conn.port}"
    "#{scheme}://#{conn.host}#{port}"
  end

  defp json_content_type?(value) do
    value
    |> String.split(";", parts: 2)
    |> hd()
    |> String.trim()
    |> Kernel.==("application/json")
  end

  defp reject(conn) do
    conn
    |> put_status(:forbidden)
    |> json(%{error: "genesis_same_origin_required"})
    |> halt()
  end
end
