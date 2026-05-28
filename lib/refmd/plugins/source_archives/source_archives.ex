defmodule RefMD.Plugins.SourceArchives do
  @moduledoc false

  alias RefMD.Plugins.Artifact

  @remote_fetch_timeout_ms 10_000
  @remote_archive_max_bytes 5_000_000
  @remote_fetch_chunk_bytes 8_192
  @remote_fetch_redirect_hop_limit 5

  @spec fetch_archive(String.t(), keyword()) :: {:ok, Path.t(), String.t()} | {:error, atom()}
  def fetch_archive(source_url, opts) when is_binary(source_url) and is_list(opts) do
    with {:requested, :ok} <- {:requested, audit_fetch_requested(source_url, opts)},
         {:clients, :ok} <- {:clients, ensure_http_clients_started()},
         {:canonical_url, {:ok, canonical_url}} <-
           {:canonical_url, Artifact.canonical_remote_source_url(source_url)},
         {:archive, {:ok, archive_path}} <-
           {:archive, fetch_resolved_archive(canonical_url, opts)} do
      {:ok, archive_path, canonical_url}
    else
      {:requested, {:error, reason}} ->
        {:error, reason}

      {:archive, {:error, _reason} = error} ->
        error

      {_stage, {:error, reason} = error} when is_atom(reason) ->
        audit_fetch_failed_or_error(source_url, opts, reason, error)
    end
  end

  defp fetch_resolved_archive(canonical_url, opts) do
    target_resolver =
      Keyword.get(opts, :target_resolver, &Artifact.verified_remote_source_target/1)

    case target_resolver.(canonical_url) do
      {:ok, target} ->
        with {:ok, body} <- request_remote_archive(target, opts, 0) do
          write_remote_archive(body)
        end

      {:error, reason} = error when is_atom(reason) ->
        audit_fetch_failed_or_error(canonical_url, opts, reason, error)

      {:error, _reason} = error ->
        error
    end
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
      {:error, _reason} -> {:error, :plugin_source_fetch_unavailable}
    end
  end

  defp request_remote_archive(target, opts, redirect_hops) do
    fetcher = Keyword.get(opts, :fetcher, &default_remote_archive_fetch/1)
    canonical_url = URI.to_string(target.uri)

    fetcher.(target)
    |> handle_remote_archive_response(target, canonical_url, opts, redirect_hops)
  end

  defp handle_remote_archive_response(
         {:ok, 200, headers, body},
         _target,
         canonical_url,
         opts,
         _redirect_hops
       )
       when is_binary(body) do
    case validate_remote_archive_response(headers, body) do
      {:ok, body} ->
        with :ok <- audit_fetch_completed(canonical_url, opts) do
          {:ok, body}
        end

      {:error, reason} = error ->
        audit_fetch_failed_or_error(canonical_url, opts, reason, error)
    end
  end

  defp handle_remote_archive_response(
         {:ok, status, headers, _body},
         target,
         canonical_url,
         opts,
         redirect_hops
       )
       when status in 300..399 do
    with :ok <- audit_fetch_completed(canonical_url, opts) do
      follow_remote_redirect(target, headers, opts, redirect_hops)
    end
  end

  defp handle_remote_archive_response(
         {:ok, _status, _headers, _body},
         _target,
         canonical_url,
         opts,
         _redirect_hops
       ) do
    audit_fetch_failed_or_error(
      canonical_url,
      opts,
      :plugin_source_fetch_failed,
      {:error, :plugin_source_fetch_failed}
    )
  end

  defp handle_remote_archive_response(
         {:error, reason},
         _target,
         canonical_url,
         opts,
         _redirect_hops
       )
       when is_atom(reason) do
    audit_fetch_failed_or_error(canonical_url, opts, reason, {:error, reason})
  end

  defp handle_remote_archive_response(
         {:error, _reason},
         _target,
         canonical_url,
         opts,
         _redirect_hops
       ) do
    audit_fetch_failed_or_error(
      canonical_url,
      opts,
      :plugin_source_fetch_failed,
      {:error, :plugin_source_fetch_failed}
    )
  end

  defp follow_remote_redirect(target, _headers, opts, redirect_hops)
       when redirect_hops >= @remote_fetch_redirect_hop_limit do
    audit_fetch_failed_or_error(
      URI.to_string(target.uri),
      opts,
      :plugin_source_redirect_limit_exceeded,
      {:error, :plugin_source_redirect_limit_exceeded}
    )
  end

  defp follow_remote_redirect(target, headers, opts, redirect_hops) do
    target_resolver =
      Keyword.get(opts, :target_resolver, &Artifact.verified_remote_source_target/1)

    with {:ok, location} <- remote_redirect_location(headers),
         {:ok, redirect_url} <- remote_redirect_source_url(target.uri, location),
         :ok <- audit_fetch_requested(redirect_url, opts),
         {:ok, canonical_url} <- Artifact.canonical_remote_source_url(redirect_url),
         {:ok, redirect_target} <- target_resolver.(canonical_url) do
      request_remote_archive(redirect_target, opts, redirect_hops + 1)
    else
      {:error, reason} = error when is_atom(reason) ->
        redirect_url = redirect_audit_url(target.uri, headers)
        audit_fetch_failed_or_error(redirect_url, opts, reason, error)

      {:error, _reason} = error ->
        error
    end
  end

  defp audit_fetch_requested(canonical_url, opts) do
    record_fetch_requested = Keyword.get(opts, :record_fetch_requested, &audit_noop/1)

    canonical_url
    |> audit_attrs(opts)
    |> record_fetch_requested.()
    |> audit_result()
  end

  defp audit_fetch_completed(canonical_url, opts) do
    record_fetch_completed = Keyword.get(opts, :record_fetch_completed, &audit_noop/1)

    canonical_url
    |> audit_attrs(opts)
    |> record_fetch_completed.()
    |> audit_result()
  end

  defp audit_fetch_failed_or_error(canonical_url, opts, reason, original_error)
       when is_atom(reason) do
    record_fetch_failed = Keyword.get(opts, :record_fetch_failed, &audit_noop/2)

    case record_fetch_failed.(audit_attrs(canonical_url, opts), reason) do
      {:ok, _} -> original_error
      {:error, audit_error} -> {:error, audit_error}
    end
  end

  defp audit_attrs(canonical_url, opts) do
    opts
    |> Keyword.get(:audit_attrs, %{})
    |> Map.put(:source_url, canonical_url)
  end

  defp audit_result({:ok, _}), do: :ok
  defp audit_result({:error, reason}), do: {:error, reason}

  defp audit_noop(_attrs), do: {:ok, %{}}
  defp audit_noop(_attrs, _reason), do: {:ok, %{}}

  defp remote_redirect_source_url(current_uri, location) do
    {:ok, current_uri |> URI.merge(location) |> URI.to_string()}
  rescue
    _exception in [ArgumentError, FunctionClauseError, Protocol.UndefinedError] ->
      {:error, :plugin_source_invalid}
  end

  defp redirect_audit_url(current_uri, headers) do
    with {:ok, location} <- remote_redirect_location(headers),
         {:ok, redirect_url} <- remote_redirect_source_url(current_uri, location) do
      redirect_url
    else
      _ -> URI.to_string(current_uri)
    end
  end

  defp remote_redirect_location(headers) do
    case remote_header(headers, "location") do
      location when is_binary(location) and location != "" -> {:ok, location}
      _ -> {:error, :plugin_source_redirect_not_allowed}
    end
  end

  defp remote_header(headers, name) do
    expected = String.downcase(name)

    Enum.find_value(headers, fn
      {header_name, value} when is_binary(header_name) and is_binary(value) ->
        if String.downcase(String.trim(header_name)) == expected do
          String.trim(value)
        end

      _ ->
        nil
    end)
  end

  defp default_remote_archive_fetch(%{uri: uri, host: host, address: address}) do
    port = uri.port || 443

    with {:ok, socket} <- connect_remote_source(address, port, host),
         :ok <- send_remote_source_request(socket, uri, host),
         result <- recv_remote_source_response(socket) do
      :ssl.close(socket)
      result
    else
      {:error, _reason} = error -> error
    end
  end

  defp connect_remote_source(address, port, host) do
    :ssl.connect(
      address,
      port,
      [
        :binary,
        active: false,
        verify: :verify_peer,
        cacerts: :public_key.cacerts_get(),
        server_name_indication: String.to_charlist(host),
        customize_hostname_check: [
          match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
        ]
      ],
      @remote_fetch_timeout_ms
    )
  end

  defp send_remote_source_request(socket, uri, host) do
    path = remote_request_path(uri)

    request = [
      "GET ",
      path,
      " HTTP/1.1\r\n",
      "Host: ",
      host,
      "\r\n",
      "User-Agent: RefMD-Plugin-Acquisition\r\n",
      "Accept: application/zip, application/octet-stream\r\n",
      "Connection: close\r\n\r\n"
    ]

    :ssl.send(socket, request)
  end

  defp remote_request_path(%URI{path: path, query: query}) do
    path = if is_nil(path) or path == "", do: "/", else: path
    if is_binary(query) and query != "", do: path <> "?" <> query, else: path
  end

  defp recv_remote_source_response(socket) do
    with {:ok, response} <- recv_remote_source_bytes(socket, <<>>) do
      parse_remote_source_response(response)
    end
  end

  defp recv_remote_source_bytes(socket, acc) when byte_size(acc) <= @remote_archive_max_bytes do
    case :ssl.recv(socket, @remote_fetch_chunk_bytes, @remote_fetch_timeout_ms) do
      {:ok, bytes} when byte_size(bytes) > 0 ->
        recv_remote_source_bytes(socket, acc <> bytes)

      {:error, :closed} ->
        {:ok, acc}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp recv_remote_source_bytes(_socket, _acc), do: {:error, :plugin_source_response_too_large}

  defp parse_remote_source_response(response) do
    case :binary.split(response, "\r\n\r\n") do
      [head, body] ->
        with {:ok, status, headers} <- parse_remote_source_head(head) do
          {:ok, status, headers, body}
        end

      _ ->
        {:error, :plugin_source_fetch_failed}
    end
  end

  defp parse_remote_source_head(head) do
    lines = String.split(head, "\r\n")

    with [status_line | header_lines] <- lines,
         [_, status, _] <- String.split(status_line, " ", parts: 3),
         {status, ""} <- Integer.parse(status) do
      {:ok, status, parse_remote_source_headers(header_lines)}
    else
      _ -> {:error, :plugin_source_fetch_failed}
    end
  end

  defp parse_remote_source_headers(lines) do
    Enum.flat_map(lines, fn line ->
      case String.split(line, ":", parts: 2) do
        [name, value] -> [{String.trim(name), String.trim(value)}]
        _ -> []
      end
    end)
  end

  defp validate_remote_archive_response(headers, body) do
    with :ok <- validate_remote_content_length(headers),
         :ok <- validate_remote_body_size(body) do
      {:ok, body}
    end
  end

  defp validate_remote_content_length(headers) do
    case content_length_header(headers) do
      nil ->
        :ok

      size when size <= @remote_archive_max_bytes ->
        :ok

      _size ->
        {:error, :plugin_source_response_too_large}
    end
  end

  defp validate_remote_body_size(body) when byte_size(body) <= @remote_archive_max_bytes, do: :ok
  defp validate_remote_body_size(_body), do: {:error, :plugin_source_response_too_large}

  defp content_length_header(headers) do
    Enum.find_value(headers, &content_length_header_value/1)
  end

  defp content_length_header_value({name, value}) do
    case String.downcase(to_string(name)) do
      "content-length" -> parse_content_length(value)
      _other -> nil
    end
  end

  defp parse_content_length(value) do
    case Integer.parse(to_string(value)) do
      {size, ""} -> size
      _invalid -> nil
    end
  end

  defp write_remote_archive(body) when is_binary(body), do: write_remote_archive(body, 3)

  defp write_remote_archive(_body, 0), do: {:error, :plugin_source_fetch_failed}

  defp write_remote_archive(body, attempts) when is_binary(body) do
    path =
      Path.join(
        System.tmp_dir!(),
        "refmd-plugin-archive-#{random_archive_token()}.zip"
      )

    case File.open(path, [:write, :binary, :exclusive], fn file -> IO.binwrite(file, body) end) do
      {:ok, :ok} -> {:ok, path}
      {:error, :eexist} -> write_remote_archive(body, attempts - 1)
      {:error, _reason} -> {:error, :plugin_source_fetch_failed}
    end
  end

  defp random_archive_token do
    16
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end
end
