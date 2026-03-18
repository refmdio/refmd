defmodule RefMDWeb.Plugs.ClientIP do
  @moduledoc """
  Extracts client IP from reverse proxy headers.

  Only trusts proxy headers when the direct connection comes from a configured
  trusted proxy IP/CIDR. Configure via:

      config :refmd, trusted_proxies: ["127.0.0.1/8", "::1/128", "10.0.0.0/8"]

  When not configured or the connecting peer is not trusted, conn.remote_ip
  is used as-is (direct connection).
  """

  import Plug.Conn

  @spec init(keyword()) :: keyword()
  def init(opts), do: opts

  @spec call(Plug.Conn.t(), keyword()) :: Plug.Conn.t()
  def call(conn, _opts) do
    if peer_is_trusted?(conn.remote_ip) do
      case get_client_ip(conn) do
        {:ok, ip} -> %{conn | remote_ip: ip}
        :error -> conn
      end
    else
      conn
    end
  end

  defp peer_is_trusted?(peer_ip) do
    case Application.get_env(:refmd, :trusted_proxies) do
      nil -> false
      proxies when is_list(proxies) -> Enum.any?(proxies, &ip_in_range?(peer_ip, &1))
    end
  end

  defp ip_in_range?(ip, cidr) when is_binary(cidr) do
    case parse_cidr(cidr) do
      {:ok, network, prefix_len} -> ip_matches?(ip, network, prefix_len)
      :error -> false
    end
  end

  defp parse_cidr(cidr) do
    case String.split(cidr, "/") do
      [ip_str, prefix_str] ->
        with {:ok, ip} <- :inet.parse_address(String.to_charlist(ip_str)),
             {prefix_len, ""} <- Integer.parse(prefix_str) do
          {:ok, ip, prefix_len}
        else
          _ -> :error
        end

      [ip_str] ->
        case :inet.parse_address(String.to_charlist(ip_str)) do
          {:ok, ip} when tuple_size(ip) == 4 -> {:ok, ip, 32}
          {:ok, ip} when tuple_size(ip) == 8 -> {:ok, ip, 128}
          _ -> :error
        end
    end
  end

  defp ip_matches?(ip, network, prefix_len) when tuple_size(ip) == tuple_size(network) do
    ip_bits = ip_to_integer(ip)
    net_bits = ip_to_integer(network)
    total_bits = tuple_size(ip) * if tuple_size(ip) == 4, do: 8, else: 16
    shift = total_bits - prefix_len
    Bitwise.bsr(ip_bits, shift) == Bitwise.bsr(net_bits, shift)
  end

  defp ip_matches?(_, _, _), do: false

  defp ip_to_integer({a, b, c, d}) do
    Bitwise.bsl(a, 24) + Bitwise.bsl(b, 16) + Bitwise.bsl(c, 8) + d
  end

  defp ip_to_integer({a, b, c, d, e, f, g, h}) do
    Bitwise.bsl(a, 112) + Bitwise.bsl(b, 96) + Bitwise.bsl(c, 80) + Bitwise.bsl(d, 64) +
      Bitwise.bsl(e, 48) + Bitwise.bsl(f, 32) + Bitwise.bsl(g, 16) + h
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
        ips =
          value
          |> String.split(",")
          |> Enum.map(&String.trim/1)
          |> Enum.reverse()

        find_client_ip(ips)

      [] ->
        :error
    end
  end

  defp find_client_ip([]) do
    :error
  end

  defp find_client_ip([ip_str | rest]) do
    case parse_ip(ip_str) do
      {:ok, ip} ->
        if peer_is_trusted?(ip) do
          find_client_ip(rest)
        else
          {:ok, ip}
        end

      :error ->
        find_client_ip(rest)
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
