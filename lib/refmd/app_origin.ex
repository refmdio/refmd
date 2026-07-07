defmodule RefMD.AppOrigin do
  @moduledoc false

  def configured_origins do
    :refmd
    |> Application.get_env(RefMDWeb.Endpoint, [])
    |> Keyword.get(:url, [])
    |> origin_from_url_config()
    |> List.wrap()
  end

  def conn_origin(%Plug.Conn{} = conn) do
    canonical_origin(Atom.to_string(conn.scheme), conn.host, conn.port)
  end

  def app_origin?(origin, extra_origins \\ []) when is_binary(origin) do
    case canonical_origin_string(origin) do
      {:ok, canonical_origin} -> canonical_origin in canonical_origins(extra_origins)
      :error -> false
    end
  end

  def uri_origin(%URI{scheme: scheme, host: host, port: port})
      when is_binary(scheme) and is_binary(host) do
    canonical_origin(scheme, host, port)
  end

  defp origin_from_url_config(url_config) when is_list(url_config) do
    case Keyword.fetch(url_config, :host) do
      {:ok, host} when is_binary(host) and host != "" ->
        scheme = url_config |> Keyword.get(:scheme, "http") |> to_string()
        canonical_origin(scheme, host, Keyword.get(url_config, :port))

      _ ->
        nil
    end
  end

  defp origin_from_url_config(_url_config), do: nil

  defp canonical_origins(extra_origins) do
    configured_origins() ++
      (extra_origins
       |> Enum.filter(&is_binary/1)
       |> Enum.flat_map(fn origin ->
         case canonical_origin_string(origin) do
           {:ok, canonical_origin} -> [canonical_origin]
           :error -> []
         end
       end))
  end

  defp canonical_origin_string(origin) when is_binary(origin) do
    case URI.parse(origin) do
      %URI{scheme: scheme, host: host, port: port}
      when is_binary(scheme) and is_binary(host) ->
        {:ok, canonical_origin(scheme, host, port)}

      _ ->
        :error
    end
  end

  defp canonical_origin(scheme, host, port) do
    normalized_scheme = String.downcase(scheme)
    normalized_host = host |> String.downcase() |> String.trim_trailing(".")

    case {normalized_scheme, port} do
      {"https", port} when port in [nil, 443] -> "https://#{normalized_host}"
      {"http", port} when port in [nil, 80] -> "http://#{normalized_host}"
      {scheme, port} when is_integer(port) -> "#{scheme}://#{normalized_host}:#{port}"
      {scheme, _port} -> "#{scheme}://#{normalized_host}"
    end
  end
end
