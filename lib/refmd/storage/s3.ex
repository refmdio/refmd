defmodule RefMD.Storage.S3 do
  @moduledoc false

  @behaviour RefMD.Storage

  @empty_sha256 :crypto.hash(:sha256, "") |> Base.encode16(case: :lower)
  @service "s3"
  @algorithm "AWS4-HMAC-SHA256"
  @max_keys 100

  @impl true
  def put(path, bytes, _opts) when is_binary(path) and is_binary(bytes) do
    with :ok <- validate_storage_path(path),
         {:ok, config} <- config(),
         {:ok, status, _headers, _body} <-
           request(config, :put, path, [], bytes, [
             {"content-type", "application/octet-stream"},
             {"content-length", Integer.to_string(byte_size(bytes))},
             {"if-none-match", "*"}
           ]) do
      case status do
        status when status in [200, 201] -> :ok
        412 -> {:error, :storage_conflict}
        409 -> {:error, :storage_conflict}
        _ -> {:error, :storage_unavailable}
      end
    end
  end

  @impl true
  def get(path) when is_binary(path) do
    with :ok <- validate_storage_path(path),
         {:ok, config} <- config(),
         {:ok, status, _headers, body} <- request(config, :get, path, [], "", []) do
      case status do
        200 -> {:ok, body}
        404 -> {:error, :not_found}
        _ -> {:error, :storage_unavailable}
      end
    end
  end

  @impl true
  def delete(path) when is_binary(path) do
    with :ok <- validate_storage_path(path),
         {:ok, config} <- config(),
         {:ok, status, _headers, _body} <- request(config, :delete, path, [], "", []) do
      case status do
        status when status in [200, 202, 204, 404] -> :ok
        _ -> {:error, :storage_unavailable}
      end
    end
  end

  @impl true
  def exists?(path) when is_binary(path) do
    with :ok <- validate_storage_path(path),
         {:ok, config} <- config(),
         {:ok, status, _headers, _body} <- request(config, :head, path, [], "", []) do
      case status do
        200 -> {:ok, true}
        404 -> {:ok, false}
        _ -> {:error, :storage_unavailable}
      end
    end
  end

  @impl true
  def list("plugin-packages/" = prefix, cursor) do
    query =
      [
        {"list-type", "2"},
        {"prefix", prefix},
        {"max-keys", Integer.to_string(@max_keys)}
      ] ++ continuation_query(cursor)

    with {:ok, config} <- config(),
         {:ok, status, _headers, body} <- request(config, :get, "", query, "", []) do
      case status do
        200 -> parse_list_response(body)
        _ -> {:error, :storage_unavailable}
      end
    end
  end

  def list(_prefix, _cursor), do: {:error, :invalid_prefix}

  defp config do
    opts =
      :refmd
      |> Application.get_env(:storage, [])
      |> Keyword.get(:s3, [])

    with {:ok, bucket} <- required_string(opts, :bucket),
         {:ok, region} <- required_string(opts, :region),
         {:ok, access_key_id} <- required_string(opts, :access_key_id),
         {:ok, secret_access_key} <- required_string(opts, :secret_access_key) do
      {:ok,
       %{
         bucket: bucket,
         region: region,
         access_key_id: access_key_id,
         secret_access_key: secret_access_key,
         session_token: optional_string(opts, :session_token),
         endpoint: optional_string(opts, :endpoint),
         path_style: Keyword.get(opts, :path_style, false),
         request_fun: Keyword.get(opts, :request_fun, &http_request/4),
         now_fun: Keyword.get(opts, :now_fun, &:calendar.universal_time/0)
       }}
    end
  end

  defp required_string(opts, key) do
    case Keyword.get(opts, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, :storage_misconfigured}
    end
  end

  defp optional_string(opts, key) do
    case Keyword.get(opts, key) do
      value when is_binary(value) and value != "" -> value
      _ -> nil
    end
  end

  defp validate_storage_path(path) do
    if path != "" and not String.starts_with?(path, "/") and
         not String.contains?(path, ["\\", <<0>>, "../", "/..", "//"]) do
      :ok
    else
      {:error, :invalid_path}
    end
  end

  defp request(config, method, path, query, body, extra_headers) do
    {url, host, canonical_uri} = request_target(config, path, query)
    payload_hash = sha256_hex(body)
    amz_date = amz_date(config.now_fun.())
    date = String.slice(amz_date, 0, 8)

    headers =
      [
        {"host", host},
        {"x-amz-content-sha256", payload_hash},
        {"x-amz-date", amz_date}
      ] ++ token_header(config.session_token) ++ extra_headers

    authorization =
      authorization_header(
        config,
        method,
        canonical_uri,
        query,
        headers,
        payload_hash,
        amz_date,
        date
      )

    headers = [{"authorization", authorization} | headers]

    config.request_fun.(method, url, headers, body)
  end

  defp request_target(config, path, query) do
    endpoint = endpoint(config)
    key_path = encoded_key_path(path)

    {host, object_path} =
      if config.path_style do
        {endpoint.host, "/" <> uri_encode(config.bucket) <> key_path}
      else
        {config.bucket <> "." <> endpoint.host, key_path}
      end

    port = endpoint.port || default_port(endpoint.scheme)
    host_header = host_header(host, port, endpoint.scheme)
    query_string = canonical_query(query)
    url_query = if query_string == "", do: "", else: "?" <> query_string
    url = endpoint.scheme <> "://" <> host_header <> object_path <> url_query

    {url, host_header, object_path}
  end

  defp endpoint(%{endpoint: nil, region: region}) do
    %{scheme: "https", host: "s3." <> region <> ".amazonaws.com", port: nil}
  end

  defp endpoint(%{endpoint: endpoint_url}) do
    uri = URI.parse(endpoint_url)
    %{scheme: uri.scheme || "https", host: uri.host, port: uri.port}
  end

  defp default_port("http"), do: 80
  defp default_port(_scheme), do: 443

  defp host_header(host, port, "http") when port in [nil, 80], do: host
  defp host_header(host, port, "https") when port in [nil, 443], do: host
  defp host_header(host, port, _scheme), do: host <> ":" <> Integer.to_string(port)

  defp encoded_key_path(""), do: "/"

  defp encoded_key_path(path) do
    "/" <>
      (path
       |> String.split("/", trim: true)
       |> Enum.map_join("/", &uri_encode/1))
  end

  defp continuation_query(nil), do: []
  defp continuation_query(cursor) when is_binary(cursor), do: [{"continuation-token", cursor}]
  defp continuation_query(_cursor), do: []

  defp token_header(nil), do: []
  defp token_header(token), do: [{"x-amz-security-token", token}]

  defp authorization_header(
         config,
         method,
         canonical_uri,
         query,
         headers,
         payload_hash,
         amz_date,
         date
       ) do
    credential_scope = Enum.join([date, config.region, @service, "aws4_request"], "/")
    signed_headers = signed_headers(headers)

    canonical_request =
      [
        method |> Atom.to_string() |> String.upcase(),
        canonical_uri,
        canonical_query(query),
        canonical_headers(headers),
        signed_headers,
        payload_hash
      ]
      |> Enum.join("\n")

    string_to_sign =
      [
        @algorithm,
        amz_date,
        credential_scope,
        sha256_hex(canonical_request)
      ]
      |> Enum.join("\n")

    signature =
      config.secret_access_key
      |> signing_key(date, config.region)
      |> hmac(string_to_sign)
      |> Base.encode16(case: :lower)

    @algorithm <>
      " Credential=" <>
      config.access_key_id <>
      "/" <>
      credential_scope <>
      ", SignedHeaders=" <>
      signed_headers <>
      ", Signature=" <> signature
  end

  defp canonical_headers(headers) do
    headers
    |> normalize_headers()
    |> Enum.map_join(fn {name, value} -> name <> ":" <> value <> "\n" end)
  end

  defp signed_headers(headers) do
    headers
    |> normalize_headers()
    |> Enum.map_join(";", &elem(&1, 0))
  end

  defp normalize_headers(headers) do
    headers
    |> Enum.map(fn {name, value} ->
      {String.downcase(name),
       value |> to_string() |> String.trim() |> String.replace(~r/\s+/, " ")}
    end)
    |> Enum.sort_by(&elem(&1, 0))
  end

  defp canonical_query(query) do
    query
    |> Enum.map(fn {key, value} -> {uri_encode(key), uri_encode(value)} end)
    |> Enum.sort()
    |> Enum.map_join("&", fn {key, value} -> key <> "=" <> value end)
  end

  defp uri_encode(value) do
    value
    |> to_string()
    |> URI.encode(&unreserved?/1)
  end

  defp unreserved?(character) do
    character in ?A..?Z or character in ?a..?z or character in ?0..?9 or
      character in [?-, ?_, ?., ?~]
  end

  defp signing_key(secret_access_key, date, region) do
    ("AWS4" <> secret_access_key)
    |> hmac(date)
    |> hmac(region)
    |> hmac(@service)
    |> hmac("aws4_request")
  end

  defp hmac(key, data), do: :crypto.mac(:hmac, :sha256, key, data)

  defp sha256_hex(body) when is_binary(body),
    do: :crypto.hash(:sha256, body) |> Base.encode16(case: :lower)

  defp amz_date({{year, month, day}, {hour, minute, second}}) do
    [
      pad(year, 4),
      pad(month, 2),
      pad(day, 2),
      "T",
      pad(hour, 2),
      pad(minute, 2),
      pad(second, 2),
      "Z"
    ]
    |> IO.iodata_to_binary()
  end

  defp pad(value, size), do: value |> Integer.to_string() |> String.pad_leading(size, "0")

  defp http_request(method, url, headers, body) do
    with :ok <- ensure_http_clients_started() do
      {http_method, request} = http_request_tuple(method, url, headers, body)

      http_method
      |> :httpc.request(request, http_options(url), body_format: :binary)
      |> normalize_http_response()
    end
  end

  defp http_request_tuple(:put, url, headers, body) do
    {:put,
     {String.to_charlist(url), charlist_headers(headers), ~c"application/octet-stream", body}}
  end

  defp http_request_tuple(method, url, headers, _body) when method in [:get, :head, :delete] do
    {method, {String.to_charlist(url), charlist_headers(headers)}}
  end

  defp http_options(url) do
    case URI.parse(url) do
      %URI{scheme: "https"} ->
        [
          ssl: [
            verify: :verify_peer,
            cacerts: :public_key.cacerts_get(),
            customize_hostname_check: [
              match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
            ]
          ]
        ]

      _ ->
        []
    end
  end

  defp charlist_headers(headers) do
    Enum.map(headers, fn {name, value} ->
      {String.to_charlist(name), String.to_charlist(value)}
    end)
  end

  defp normalize_http_response({:ok, {{_version, status, _reason}, headers, body}}) do
    {:ok, status, normalize_response_headers(headers), body || ""}
  end

  defp normalize_http_response({:error, _reason}), do: {:error, :storage_unavailable}

  defp normalize_response_headers(headers) do
    Enum.map(headers, fn {name, value} -> {to_string(name), to_string(value)} end)
  end

  defp ensure_http_clients_started do
    with :ok <- ensure_started(:ssl) do
      ensure_started(:inets)
    end
  end

  defp ensure_started(app) do
    case Application.ensure_all_started(app) do
      {:ok, _apps} -> :ok
      {:error, {:already_started, ^app}} -> :ok
      {:error, _reason} -> {:error, :storage_unavailable}
    end
  end

  defp parse_list_response(body) do
    {document, _} = body |> String.to_charlist() |> :xmerl_scan.string(quiet: true)

    {:ok,
     %{
       entries: xml_texts(document, ~c"//Contents/Key/text()"),
       cursor: next_cursor(xml_texts(document, ~c"//NextContinuationToken/text()"))
     }}
  rescue
    _ -> {:error, :storage_unavailable}
  end

  defp xml_texts(document, xpath) do
    xpath
    |> :xmerl_xpath.string(document)
    |> Enum.map(&xml_text/1)
    |> Enum.reject(&(&1 == ""))
  end

  defp xml_text({:xmlText, _parents, _pos, _attrs, value, :text}), do: to_string(value)
  defp xml_text(_node), do: ""

  defp next_cursor([token | _]), do: token
  defp next_cursor(_), do: nil

  def empty_payload_hash, do: @empty_sha256
end
