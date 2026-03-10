defmodule RefMDWeb.Plugs.ClientIP do
  @moduledoc """
  Extracts client IP from reverse proxy headers.

  Priority:
  1. X-Forwarded-For (first value)
  2. X-Real-IP
  3. conn.remote_ip (direct socket connection)
  """

  import Plug.Conn

  @spec init(keyword()) :: keyword()
  def init(opts), do: opts

  @spec call(Plug.Conn.t(), keyword()) :: Plug.Conn.t()
  def call(conn, _opts) do
    case get_client_ip(conn) do
      {:ok, ip} -> %{conn | remote_ip: ip}
      :error -> conn
    end
  end

  defp get_client_ip(conn) do
    case get_forwarded_for(conn) do
      {:ok, _} = result -> result
      :error -> get_real_ip(conn)
    end
  end

  defp get_forwarded_for(conn) do
    case get_req_header(conn, "x-forwarded-for") do
      [value | _] ->
        value
        |> String.split(",")
        |> List.first()
        |> String.trim()
        |> parse_ip()

      [] ->
        :error
    end
  end

  defp get_real_ip(conn) do
    case get_req_header(conn, "x-real-ip") do
      [value | _] -> parse_ip(String.trim(value))
      [] -> :error
    end
  end

  defp parse_ip(ip_string) do
    case :inet.parse_address(String.to_charlist(ip_string)) do
      {:ok, ip} -> {:ok, ip}
      {:error, _} -> :error
    end
  end
end
