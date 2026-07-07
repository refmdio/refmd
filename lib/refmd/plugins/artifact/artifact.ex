defmodule RefMD.Plugins.Artifact do
  @moduledoc false

  alias RefMD.Plugins.JavaScriptSource

  import Bitwise

  alias RefMD.Crypto.{Hash, JCS}

  @required_files MapSet.new(["manifest.json", "main.js"])
  @root_files MapSet.new(["manifest.json", "main.js", "styles.css"])
  @source_url_hash_sentinel "NO_SOURCE_URL"
  @remote_source_kind "remote_https_url"
  @local_source_kind "local_upload"
  @max_archive_bytes 5_000_000
  @max_uncompressed_archive_bytes 5_000_000
  @metadata_endpoint_hosts MapSet.new(["metadata", "metadata.google.internal"])
  @forbidden_resource_extensions MapSet.new(~w(.js .mjs .cjs .jsx .ts .tsx))
  @resource_media_by_extension %{
    ".apng" => {"image", "image/apng"},
    ".avif" => {"image", "image/avif"},
    ".gif" => {"image", "image/gif"},
    ".jpg" => {"image", "image/jpeg"},
    ".jpeg" => {"image", "image/jpeg"},
    ".json" => {"json", "application/json"},
    ".md" => {"text", "text/markdown"},
    ".otf" => {"font", "font/otf"},
    ".png" => {"image", "image/png"},
    ".txt" => {"text", "text/plain"},
    ".wasm" => {"wasm", "application/wasm"},
    ".webp" => {"image", "image/webp"},
    ".woff" => {"font", "font/woff"},
    ".woff2" => {"font", "font/woff2"}
  }
  @resource_kinds MapSet.new(~w(image font text json data wasm))
  @forbidden_host_api_tokens [
    "getApp",
    "workspaceManager",
    "WorkspaceLeaf",
    "renderPluginContent",
    "renderTrustedBuiltinContent",
    "TrustedHostWorkspace",
    "registerDomEvent",
    "registerView",
    "registerEditorExtension",
    "addSidebarPanel",
    "addStatusBarItem"
  ]
  @server_synced_storage_write_permissions MapSet.new([
                                             "storage:write:workspace",
                                             "storage:write:document"
                                           ])
  @storage_surfaces MapSet.new(["userLocal", "cache", "document", "workspace"])
  @ui_permissions MapSet.new([
                    "ui:command",
                    "ui:menu_item",
                    "ui:statusbar",
                    "ui:sidebar",
                    "ui:workspace_tile",
                    "ui:auxiliary_pane",
                    "ui:document_tree:*",
                    "ui:settings_iframe",
                    "ui:settings_declarative",
                    "ui:declarative_modal",
                    "ui:editor"
                  ])
  @literal_permissions MapSet.new([
                         "document:write",
                         "credential:use",
                         "network:fetch",
                         "editor:selection:read",
                         "editor:context:read"
                       ])
  @renderer_slot_type_pattern ~r/^[a-z][a-z0-9._-]{0,63}$/
  @forbidden_renderer_slot_types MapSet.new(["markdown", "md", "document", "full-document"])
  @network_endpoint_methods ~w(GET POST PUT PATCH DELETE HEAD)
  @network_endpoint_routes ~w(proxy)
  @network_endpoint_body_schemas ~w(none json text)
  @forbidden_network_headers ~w(authorization cookie proxy-authorization)
  @forbidden_network_endpoint_fields ~w(proxy proxyUrl proxyURL proxy_url proxyCredential proxy_credential proxyId proxy_id)
  @network_header_name_pattern ~r/^[a-z0-9!#$%&'*+.^_`|~-]+$/

  def candidate_attrs_from_archive_path(path, source_kind, source_url, attrs)
      when is_binary(path) and is_map(attrs) do
    with {:ok, source} <- source_metadata(source_kind, source_url),
         {:ok, archive} <- read_bounded_archive(path),
         {:ok, files} <- archive_files(path),
         {:ok, parts} <- validated_parts(files),
         {:ok, manifest} <- parse_manifest(parts.manifest_json),
         :ok <- validate_manifest_scope(manifest),
         :ok <- validate_manifest_permission_grant(manifest),
         :ok <- validate_manifest_network_endpoints(manifest),
         {:ok, resources} <- validated_resources(files, manifest),
         {:ok, plugin_id} <- required_manifest_string(manifest, ["id", "plugin_id"]),
         {:ok, version} <- required_manifest_string(manifest, ["version"]) do
      resource_manifest = resource_manifest(resources)
      resource_manifest_hash = semantic_hash(resource_manifest)
      package_entries = package_entries(parts, resources)

      candidate =
        attrs
        |> Map.merge(%{
          plugin_id: plugin_id,
          version: version,
          owner_scope_kind: owner_scope_kind(attrs, manifest),
          source_kind: source.kind,
          source_url: source.url,
          source_url_hash: source.url_hash,
          archive_hash: Hash.blake3_base64url(archive),
          manifest_json: manifest,
          manifest_json_bytes: parts.manifest_json,
          main_js: parts.main_js,
          styles_css: parts.styles_css,
          manifest_hash: Hash.blake3_base64url(parts.manifest_json),
          main_js_hash: Hash.blake3_base64url(parts.main_js),
          styles_css_hash: Hash.blake3_base64url(parts.styles_css),
          resource_manifest: resource_manifest,
          resource_manifest_hash: resource_manifest_hash,
          package_entries: package_entries,
          bundle_hash:
            bundle_hash(
              parts.main_js,
              parts.styles_css,
              parts.manifest_json,
              resource_manifest_hash
            ),
          permissions_hash: semantic_hash(Map.get(manifest, "permissions", [])),
          endpoint_hash: semantic_hash(get_in(manifest, ["network", "endpoints"]) || []),
          renderer_slots_hash: semantic_hash(Map.get(manifest, "rendererSlots", [])),
          document_scope_hash: semantic_hash(Map.get(manifest, "documentScopes", [])),
          validation_status: "valid",
          validation_errors: []
        })

      {:ok, candidate}
    end
  end

  def source_url_hash(source_kind, source_url) do
    with {:ok, source} <- source_metadata(source_kind, source_url) do
      {:ok, source.url_hash}
    end
  end

  def canonical_remote_source_url(source_url) when is_binary(source_url),
    do: canonical_remote_url(source_url)

  def verify_remote_source_targets(canonical_url) when is_binary(canonical_url) do
    with {:ok, _target} <- verified_remote_source_target(canonical_url) do
      :ok
    end
  end

  def verified_remote_source_target(canonical_url) when is_binary(canonical_url) do
    verified_remote_source_target(canonical_url, &resolve_host_addresses/1)
  end

  def verified_remote_source_target(canonical_url, resolver)
      when is_binary(canonical_url) and is_function(resolver, 1) do
    uri = URI.parse(canonical_url)

    with {:ok, host} <- normalize_remote_host(uri),
         :ok <- reject_private_host(host),
         {:ok, addresses} <- resolver.(host) do
      case Enum.any?(addresses, &private_ip_address?/1) do
        true -> {:error, :plugin_source_private_target}
        false -> verified_remote_address(uri, host, addresses)
      end
    end
  end

  defp verified_remote_address(uri, host, addresses) do
    case addresses do
      [address | _] -> {:ok, %{uri: uri, host: host, address: address}}
      [] -> {:error, :plugin_source_dns_failed}
    end
  end

  def bundle_hash(main_js, styles_css, manifest_json)
      when is_binary(main_js) and is_binary(styles_css) and is_binary(manifest_json) do
    bundle_hash(main_js, styles_css, manifest_json, semantic_hash([]))
  end

  def bundle_hash(main_js, styles_css, manifest_json, resource_manifest_hash)
      when is_binary(main_js) and is_binary(styles_css) and is_binary(manifest_json) and
             is_binary(resource_manifest_hash) do
    bundle_hash_from_hashes(
      Hash.blake3_base64url(manifest_json),
      Hash.blake3_base64url(main_js),
      Hash.blake3_base64url(styles_css),
      resource_manifest_hash
    )
  end

  def bundle_hash_from_hashes(
        manifest_hash,
        main_js_hash,
        styles_css_hash,
        resource_manifest_hash
      )
      when is_binary(manifest_hash) and is_binary(main_js_hash) and is_binary(styles_css_hash) and
             is_binary(resource_manifest_hash) do
    %{
      "manifest_hash" => manifest_hash,
      "main_js_hash" => main_js_hash,
      "styles_css_hash" => styles_css_hash,
      "resource_manifest_hash" => resource_manifest_hash
    }
    |> JCS.canonical_bytes!()
    |> Hash.blake3_base64url()
  end

  def validate_manifest_permission_grant(manifest) when is_map(manifest) do
    with {:ok, permissions} <- validated_manifest_permissions(manifest),
         :ok <- validate_manifest_renderer_slots(manifest) do
      if Enum.any?(permissions, &plaintext_read_permission?/1) and
           Enum.any?(permissions, &server_synced_storage_write_permission?/1) do
        {:error, :plugin_manifest_dangerous_permission_combination}
      else
        :ok
      end
    end
  end

  def validate_manifest_permission_grant(_manifest), do: {:error, :plugin_manifest_invalid}

  defp validate_manifest_network_endpoints(%{"network" => %{"endpoints" => endpoints}})
       when is_list(endpoints) do
    with :ok <- validate_unique_endpoint_ids(endpoints) do
      validate_manifest_network_endpoint_list(endpoints)
    end
  end

  defp validate_manifest_network_endpoints(%{"network" => %{"endpoints" => _endpoints}}),
    do: {:error, :plugin_manifest_invalid_network_endpoint}

  defp validate_manifest_network_endpoints(%{"network" => network}) when is_map(network), do: :ok

  defp validate_manifest_network_endpoints(%{"network" => _network}),
    do: {:error, :plugin_manifest_invalid_network_endpoint}

  defp validate_manifest_network_endpoints(_manifest), do: :ok

  defp validate_manifest_network_endpoint_list(endpoints) do
    Enum.reduce_while(endpoints, :ok, fn endpoint, :ok ->
      case validate_manifest_network_endpoint(endpoint) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp validate_unique_endpoint_ids(endpoints) do
    endpoint_ids =
      endpoints
      |> Enum.map(fn
        %{"id" => id} when is_binary(id) and id != "" -> id
        _endpoint -> nil
      end)

    if Enum.any?(endpoint_ids, &is_nil/1) or Enum.uniq(endpoint_ids) != endpoint_ids,
      do: {:error, :plugin_manifest_invalid_network_endpoint},
      else: :ok
  end

  defp validate_manifest_network_endpoint(%{"id" => id, "url" => url} = endpoint)
       when is_binary(id) and id != "" and is_binary(url) and url != "" do
    [
      reject_plugin_controlled_endpoint_fields(endpoint),
      validate_endpoint_url(url),
      validate_endpoint_methods(Map.get(endpoint, "methods")),
      validate_endpoint_routes(Map.get(endpoint, "routes")),
      validate_endpoint_headers(endpoint),
      validate_endpoint_body_schema(Map.get(endpoint, "bodySchema")),
      validate_endpoint_credential_audience(Map.get(endpoint, "credentialAudience")),
      validate_endpoint_byte_limit(Map.get(endpoint, "maxRequestBytes")),
      validate_endpoint_byte_limit(Map.get(endpoint, "maxResponseBytes"))
    ]
    |> validate_endpoint_steps()
  end

  defp validate_manifest_network_endpoint(_endpoint),
    do: {:error, :plugin_manifest_invalid_network_endpoint}

  defp reject_plugin_controlled_endpoint_fields(endpoint) do
    cond do
      Enum.any?(Map.keys(endpoint), &(&1 in @forbidden_network_endpoint_fields)) ->
        {:error, :plugin_manifest_invalid_network_endpoint}

      Map.get(endpoint, "mode") == "no-cors" ->
        {:error, :plugin_manifest_invalid_network_endpoint}

      true ->
        :ok
    end
  end

  defp validate_endpoint_steps(steps) do
    Enum.reduce_while(steps, :ok, fn
      :ok, :ok -> {:cont, :ok}
      error, :ok -> {:halt, error}
    end)
  end

  defp validate_endpoint_url(url) do
    case canonical_network_endpoint_url(url) do
      {:ok, _canonical_url} -> :ok
      error -> error
    end
  end

  defp canonical_network_endpoint_url(url) do
    uri = URI.parse(url)

    with :ok <- reject_endpoint_url_control_characters(url),
         :ok <- validate_endpoint_https_scheme(uri),
         {:ok, raw_host} <- raw_network_endpoint_host(url),
         {:ok, host} <- normalize_network_endpoint_host(uri),
         :ok <- validate_endpoint_host_canonical(raw_host, host),
         :ok <- reject_network_endpoint_url_parts(uri),
         :ok <- reject_ambiguous_network_endpoint_path(url),
         :ok <- reject_app_origin_network_endpoint(uri),
         :ok <- reject_private_network_endpoint_host(host) do
      path = if is_nil(uri.path) or uri.path == "", do: "/", else: uri.path
      canonical = URI.to_string(%{uri | scheme: "https", host: host, port: nil, path: path})

      if canonical == normalized_network_endpoint_input(url),
        do: {:ok, canonical},
        else: {:error, :plugin_manifest_invalid_network_endpoint}
    end
  end

  defp reject_endpoint_url_control_characters(url) do
    if control_character?(url),
      do: {:error, :plugin_manifest_invalid_network_endpoint},
      else: :ok
  end

  defp validate_endpoint_https_scheme(%URI{scheme: "https"}), do: :ok

  defp validate_endpoint_https_scheme(_uri),
    do: {:error, :plugin_manifest_invalid_network_endpoint}

  defp raw_network_endpoint_host(url) do
    case Regex.run(~r/^https:\/\/(?:[^@\/?#]*@)?(\[[^\]]+\]|[^:\/?#]+)(?::\d+)?(?:[\/?#]|$)/, url) do
      [_match, host] -> {:ok, String.trim(host, "[]")}
      _no_match -> {:error, :plugin_manifest_invalid_network_endpoint}
    end
  end

  defp normalize_network_endpoint_host(%URI{host: host}) when is_binary(host) and host != "",
    do: {:ok, String.downcase(host)}

  defp normalize_network_endpoint_host(_uri),
    do: {:error, :plugin_manifest_invalid_network_endpoint}

  defp validate_endpoint_host_canonical(raw_host, host) do
    if raw_host == host,
      do: :ok,
      else: {:error, :plugin_manifest_invalid_network_endpoint}
  end

  defp reject_network_endpoint_url_parts(%URI{userinfo: nil, fragment: nil, port: 443}), do: :ok

  defp reject_network_endpoint_url_parts(_uri),
    do: {:error, :plugin_manifest_invalid_network_endpoint}

  defp reject_ambiguous_network_endpoint_path(url) do
    raw_lower = String.downcase(url)

    cond do
      Regex.match?(~r/%(?![0-9A-Fa-f]{2})/, url) ->
        {:error, :plugin_manifest_invalid_network_endpoint}

      Regex.match?(~r/%2f|%5c|%2e/, raw_lower) ->
        {:error, :plugin_manifest_invalid_network_endpoint}

      Regex.match?(~r/(?:^|\/)\.{1,2}(?:\/|$)/, url) ->
        {:error, :plugin_manifest_invalid_network_endpoint}

      true ->
        :ok
    end
  end

  defp reject_private_network_endpoint_host(host) do
    if private_host?(host),
      do: {:error, :plugin_manifest_invalid_network_endpoint},
      else: :ok
  end

  defp reject_app_origin_network_endpoint(uri) do
    if uri |> RefMD.AppOrigin.uri_origin() |> RefMD.AppOrigin.app_origin?(),
      do: {:error, :plugin_manifest_invalid_network_endpoint},
      else: :ok
  end

  defp normalized_network_endpoint_input(url) do
    if Regex.match?(~r/^https:\/\/[^\/?#]+$/, url),
      do: url <> "/",
      else: url
  end

  defp validate_endpoint_methods(methods) when is_list(methods) and methods != [] do
    if valid_unique_endpoint_values?(methods, @network_endpoint_methods),
      do: :ok,
      else: {:error, :plugin_manifest_invalid_network_endpoint}
  end

  defp validate_endpoint_methods(_methods),
    do: {:error, :plugin_manifest_invalid_network_endpoint}

  defp validate_endpoint_routes(routes) when is_list(routes) and routes != [] do
    if valid_unique_endpoint_values?(routes, @network_endpoint_routes),
      do: :ok,
      else: {:error, :plugin_manifest_invalid_network_endpoint}
  end

  defp validate_endpoint_routes(_routes),
    do: {:error, :plugin_manifest_invalid_network_endpoint}

  defp valid_unique_endpoint_values?(values, allowed) do
    Enum.all?(values, &(is_binary(&1) and &1 in allowed)) and
      Enum.uniq(values) == values
  end

  defp validate_endpoint_headers(endpoint) do
    case {Map.fetch(endpoint, "headers"), Map.fetch(endpoint, "allowedHeaders")} do
      {:error, :error} ->
        :ok

      {{:ok, headers}, :error} ->
        validate_endpoint_header_list(headers)

      {:error, {:ok, headers}} ->
        validate_endpoint_header_list(headers)

      {{:ok, _headers}, {:ok, _allowed_headers}} ->
        {:error, :plugin_manifest_invalid_network_endpoint}
    end
  end

  defp validate_endpoint_header_list(headers) when is_list(headers) do
    if Enum.all?(headers, &valid_endpoint_header?/1) and Enum.uniq(headers) == headers,
      do: :ok,
      else: {:error, :plugin_manifest_invalid_network_endpoint}
  end

  defp validate_endpoint_header_list(_headers),
    do: {:error, :plugin_manifest_invalid_network_endpoint}

  defp valid_endpoint_header?(header) when is_binary(header) and header != "" do
    Regex.match?(@network_header_name_pattern, header) and
      header not in @forbidden_network_headers
  end

  defp valid_endpoint_header?(_header), do: false

  defp validate_endpoint_body_schema(nil), do: :ok

  defp validate_endpoint_body_schema(schema) when is_binary(schema) do
    if schema in @network_endpoint_body_schemas,
      do: :ok,
      else: {:error, :plugin_manifest_invalid_network_endpoint}
  end

  defp validate_endpoint_body_schema(_schema),
    do: {:error, :plugin_manifest_invalid_network_endpoint}

  defp validate_endpoint_credential_audience(nil), do: :ok

  defp validate_endpoint_credential_audience(audience)
       when is_binary(audience) and audience != "", do: :ok

  defp validate_endpoint_credential_audience(_audience),
    do: {:error, :plugin_manifest_invalid_network_endpoint}

  defp validate_endpoint_byte_limit(nil), do: :ok
  defp validate_endpoint_byte_limit(limit) when is_integer(limit) and limit > 0, do: :ok

  defp validate_endpoint_byte_limit(_limit),
    do: {:error, :plugin_manifest_invalid_network_endpoint}

  def approval_subject(candidate, attrs) when is_map(candidate) and is_map(attrs) do
    candidate
    |> approval_subject_base(attrs)
    |> Map.merge(owner_subject_fields(candidate))
    |> Map.merge(application_subject_fields(candidate))
  end

  defp approval_subject_base(candidate, attrs) do
    %{
      "plugin_id" => fetch!(candidate, :plugin_id),
      "package_id" => fetch!(candidate, :package_id),
      "version" => fetch!(candidate, :version),
      "source_kind" => fetch!(candidate, :source_kind),
      "source_url_hash" => fetch!(candidate, :source_url_hash),
      "archive_hash" => fetch!(candidate, :archive_hash),
      "bundle_hash" => fetch!(candidate, :bundle_hash),
      "manifest_hash" => fetch!(candidate, :manifest_hash),
      "main_js_hash" => fetch!(candidate, :main_js_hash),
      "styles_css_hash" => fetch!(candidate, :styles_css_hash),
      "resource_manifest_hash" => fetch!(candidate, :resource_manifest_hash),
      "permissions_hash" => fetch!(candidate, :permissions_hash),
      "endpoint_hash" => fetch!(candidate, :endpoint_hash),
      "renderer_slots_hash" => fetch!(candidate, :renderer_slots_hash),
      "document_scope_hash" => fetch!(candidate, :document_scope_hash),
      "approver_user_id" => fetch!(attrs, :approver_user_id),
      "approver_device_id" => fetch!(attrs, :approver_device_id),
      "approval_epoch" => fetch!(attrs, :approval_epoch),
      "previous_approval_event_hash" => fetch!(attrs, :previous_approval_event_hash),
      "created_at_ms" => fetch!(attrs, :created_at_ms)
    }
  end

  defp owner_subject_fields(candidate) do
    case fetch!(candidate, :owner_scope_kind) do
      "workspace" ->
        %{
          "owner_scope_kind" => "workspace",
          "owner_workspace_id" => fetch_non_nil!(candidate, :owner_workspace_id)
        }

      "user" ->
        %{
          "owner_scope_kind" => "user",
          "owner_user_id" => fetch_non_nil!(candidate, :owner_user_id)
        }

      _ ->
        raise KeyError, key: :owner_scope_kind, term: candidate
    end
  end

  defp application_subject_fields(candidate) do
    case Map.get(candidate, :workspace_id) || Map.get(candidate, "workspace_id") do
      workspace_id when is_binary(workspace_id) ->
        %{
          "application_scope_kind" => "workspace",
          "workspace_id" => workspace_id
        }

      _ ->
        %{}
    end
  end

  defp fetch_non_nil!(map, key) do
    case Map.get(map, key) || Map.get(map, Atom.to_string(key)) do
      value when is_binary(value) -> value
      _ -> raise KeyError, key: key, term: map
    end
  end

  def approval_subject_hash(candidate, attrs) do
    candidate
    |> approval_subject(attrs)
    |> JCS.canonical_bytes!()
    |> Hash.blake3_base64url()
  end

  defp archive_files(path) do
    with :ok <- preflight_archive(path) do
      case :zip.extract(String.to_charlist(path), [:memory]) do
        {:ok, entries} -> normalize_archive_entries(entries)
        {:error, _reason} -> {:error, :plugin_archive_invalid}
      end
    end
  end

  defp preflight_archive(path) do
    case :zip.table(String.to_charlist(path)) do
      {:ok, entries} -> validate_archive_table_entries(entries)
      {:error, _reason} -> {:error, :plugin_archive_invalid}
    end
  end

  defp read_bounded_archive(path) do
    case File.read(path) do
      {:ok, archive} when byte_size(archive) <= @max_archive_bytes ->
        {:ok, archive}

      {:ok, _archive} ->
        {:error, :plugin_archive_too_large}

      {:error, _reason} ->
        {:error, :plugin_archive_invalid}
    end
  end

  defp normalize_archive_entries(entries) do
    entries
    |> Enum.reduce_while({:ok, %{}, 0}, fn {name, bytes}, {:ok, acc, total_size} ->
      filename = List.to_string(name)
      bytes = IO.iodata_to_binary(bytes)
      next_total_size = total_size + byte_size(bytes)

      cond do
        invalid_archive_path?(filename) ->
          {:halt, {:error, :plugin_archive_path_invalid}}

        not allowed_archive_file?(filename) ->
          {:halt, {:error, :plugin_archive_unknown_file}}

        Map.has_key?(acc, filename) ->
          {:halt, {:error, :plugin_archive_duplicate_file}}

        next_total_size > @max_uncompressed_archive_bytes ->
          {:halt, {:error, :plugin_archive_decompressed_too_large}}

        true ->
          {:cont, {:ok, Map.put(acc, filename, bytes), next_total_size}}
      end
    end)
    |> case do
      {:ok, files, _total_size} -> {:ok, files}
      error -> error
    end
  end

  defp validate_archive_table_entries(entries) do
    entries
    |> Enum.reduce_while({:ok, MapSet.new(), 0}, fn
      {:zip_comment, _comment}, {:ok, seen, total_size} ->
        {:cont, {:ok, seen, total_size}}

      {:zip_file, name, file_info, _comment, _offset, _compressed_size},
      {:ok, seen, total_size} ->
        case validate_archive_table_file(name, file_info, seen, total_size) do
          {:ok, next_seen, next_total_size} -> {:cont, {:ok, next_seen, next_total_size}}
          error -> {:halt, error}
        end

      _entry, _acc ->
        {:halt, {:error, :plugin_archive_invalid}}
    end)
    |> case do
      {:ok, _seen, _total_size} -> :ok
      error -> error
    end
  end

  defp validate_archive_table_file(name, file_info, seen, total_size) do
    filename = List.to_string(name)
    size = archive_table_uncompressed_size(file_info)
    next_total_size = total_size + max(size, 0)

    cond do
      invalid_archive_path?(filename) ->
        {:error, :plugin_archive_path_invalid}

      not allowed_archive_file?(filename) ->
        {:error, :plugin_archive_unknown_file}

      MapSet.member?(seen, filename) ->
        {:error, :plugin_archive_duplicate_file}

      not archive_table_regular_file?(file_info) or size < 0 ->
        {:error, :plugin_archive_invalid}

      next_total_size > @max_uncompressed_archive_bytes ->
        {:error, :plugin_archive_decompressed_too_large}

      true ->
        {:ok, MapSet.put(seen, filename), next_total_size}
    end
  end

  defp archive_table_uncompressed_size(
         {:file_info, size, _type, _access, _atime, _mtime, _ctime, _mode, _links, _major_device,
          _minor_device, _inode, _uid, _gid}
       )
       when is_integer(size),
       do: size

  defp archive_table_uncompressed_size(_file_info), do: -1

  defp archive_table_regular_file?(
         {:file_info, _size, :regular, _access, _atime, _mtime, _ctime, _mode, _links,
          _major_device, _minor_device, _inode, _uid, _gid}
       ),
       do: true

  defp archive_table_regular_file?(_file_info), do: false

  defp validated_parts(files) do
    present = Map.keys(files) |> MapSet.new()
    main_js = files["main.js"]
    styles_css = Map.get(files, "styles.css", "")

    cond do
      not MapSet.subset?(@required_files, present) ->
        {:error, :plugin_archive_required_file_missing}

      not String.valid?(main_js) or not String.valid?(styles_css) ->
        {:error, :plugin_archive_source_encoding_invalid}

      unsafe_main_source?(main_js) or unsafe_style_source?(styles_css) ->
        {:error, :plugin_archive_inline_source_unsafe}

      runtime_dependency?(main_js) ->
        {:error, :plugin_archive_runtime_dependency}

      true ->
        {:ok,
         %{
           manifest_json: files["manifest.json"],
           main_js: main_js,
           styles_css: styles_css
         }}
    end
  end

  defp allowed_archive_file?(filename) do
    MapSet.member?(@root_files, filename) or String.starts_with?(filename, "resources/")
  end

  defp validate_manifest_scope(%{"scope" => %{} = scope}) do
    supported = Map.get(scope, "supportedOwnerScopes")
    default_scope = Map.get(scope, "defaultOwnerScope")
    workspace_application = Map.get(scope, "workspaceApplication")

    cond do
      not is_list(supported) or supported == [] ->
        {:error, :plugin_manifest_invalid_scope}

      not Enum.all?(supported, &(&1 in ["user", "workspace"])) ->
        {:error, :plugin_manifest_invalid_scope}

      default_scope not in supported ->
        {:error, :plugin_manifest_invalid_scope}

      workspace_application not in ["none", "optional", "required"] ->
        {:error, :plugin_manifest_invalid_scope}

      true ->
        :ok
    end
  end

  defp validate_manifest_scope(_manifest), do: {:error, :plugin_manifest_invalid_scope}

  defp owner_scope_kind(attrs, manifest) do
    requested = Map.get(attrs, :owner_scope_kind) || Map.get(attrs, "owner_scope_kind")
    supported = get_in(manifest, ["scope", "supportedOwnerScopes"]) || []

    cond do
      requested in supported ->
        requested

      manifest_routed_without_workspace?(attrs) and "user" in supported ->
        "user"

      true ->
        get_in(manifest, ["scope", "defaultOwnerScope"])
    end
  end

  defp manifest_routed_without_workspace?(attrs) do
    manifest_routed? = Map.get(attrs, :manifest_routed) || Map.get(attrs, "manifest_routed")
    workspace_id = Map.get(attrs, :workspace_id) || Map.get(attrs, "workspace_id")

    routing_workspace_id =
      Map.get(attrs, :routing_workspace_id) || Map.get(attrs, "routing_workspace_id")

    manifest_routed? == true and not is_binary(workspace_id) and
      not is_binary(routing_workspace_id)
  end

  defp validated_resources(files, manifest) do
    resource_files = Map.drop(files, ["manifest.json", "main.js", "styles.css"])

    with {:ok, declarations} <- declared_resources(manifest),
         :ok <- validate_declared_resource_set(resource_files, declarations) do
      resources =
        declarations
        |> Enum.sort_by(& &1.path)
        |> Enum.map(fn declaration ->
          bytes = Map.fetch!(resource_files, declaration.path)

          {:ok, resource} = verified_resource_declaration(declaration, bytes)

          resource
          |> Map.put(:bytes, bytes)
          |> Map.put(:byte_length, byte_size(bytes))
          |> Map.put(:hash, Hash.blake3_base64url(bytes))
        end)

      {:ok, resources}
    end
  end

  defp declared_resources(%{"resources" => resources}) when is_list(resources) do
    resources
    |> Enum.reduce_while({:ok, []}, fn resource, {:ok, declarations} ->
      case declared_resource(resource) do
        {:ok, declaration} -> {:cont, {:ok, [declaration | declarations]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, declarations} -> {:ok, Enum.reverse(declarations)}
      {:error, reason} -> {:error, reason}
    end
  end

  defp declared_resources(%{"resources" => _resources}),
    do: {:error, :plugin_manifest_invalid_resource}

  defp declared_resources(_manifest), do: {:ok, []}

  defp declared_resource(%{
         "path" => "resources/" <> _ = path,
         "kind" => kind,
         "media_type" => media_type
       })
       when is_binary(kind) and is_binary(media_type),
       do: {:ok, %{path: path, kind: kind, media_type: media_type}}

  defp declared_resource(%{
         "path" => "resources/" <> _ = path,
         "kind" => kind,
         "mediaType" => media_type
       })
       when is_binary(kind) and is_binary(media_type),
       do: {:ok, %{path: path, kind: kind, media_type: media_type}}

  defp declared_resource(_resource), do: {:error, :plugin_manifest_invalid_resource}

  defp validate_declared_resource_set(resource_files, declarations) do
    declared_paths = MapSet.new(declarations, & &1.path)
    actual_paths = Map.keys(resource_files) |> MapSet.new()

    cond do
      Enum.any?(declarations, &(not valid_resource_logical_path?(&1.path))) ->
        {:error, :plugin_manifest_invalid_resource}

      MapSet.size(declared_paths) != length(declarations) ->
        {:error, :plugin_manifest_invalid_resource}

      not MapSet.equal?(declared_paths, actual_paths) ->
        {:error, :plugin_archive_resource_manifest_mismatch}

      Enum.any?(actual_paths, &forbidden_resource_path?/1) ->
        {:error, :plugin_archive_runtime_dependency}

      true ->
        validate_declared_resources(resource_files, declarations)
    end
  end

  defp validate_declared_resources(resource_files, declarations) do
    Enum.reduce_while(declarations, :ok, fn declaration, :ok ->
      declaration
      |> verified_resource_declaration(Map.fetch!(resource_files, declaration.path))
      |> resource_validation_step()
    end)
  end

  defp resource_validation_step({:ok, _resource}), do: {:cont, :ok}
  defp resource_validation_step({:error, reason}), do: {:halt, {:error, reason}}

  defp verified_resource_declaration(%{path: path, kind: kind, media_type: media_type}, bytes) do
    with :ok <- validate_resource_kind(kind),
         :ok <- validate_source_map(path, bytes),
         {:ok, expected_kind, expected_media_type} <- detected_resource_type(path),
         :ok <-
           validate_resource_declaration(kind, media_type, expected_kind, expected_media_type) do
      {:ok, %{path: path, kind: expected_kind, media_type: expected_media_type}}
    end
  end

  defp validate_resource_kind(kind) do
    if MapSet.member?(@resource_kinds, kind) do
      :ok
    else
      {:error, :plugin_manifest_invalid_resource}
    end
  end

  defp validate_resource_declaration(
         "data",
         "application/octet-stream",
         "data",
         "application/octet-stream"
       ),
       do: :ok

  defp validate_resource_declaration(kind, media_type, kind, media_type), do: :ok

  defp validate_resource_declaration(_kind, _media_type, _expected_kind, _expected_media_type),
    do: {:error, :plugin_manifest_invalid_resource}

  defp detected_resource_type(path) do
    extension = resource_extension(path)

    case Map.fetch(@resource_media_by_extension, extension) do
      {:ok, {kind, media_type}} -> {:ok, kind, media_type}
      :error -> {:ok, "data", "application/octet-stream"}
    end
  end

  defp forbidden_resource_path?(path) do
    MapSet.member?(@forbidden_resource_extensions, resource_extension(path))
  end

  defp validate_source_map(path, bytes) do
    if resource_extension(path) == ".map" do
      case Jason.decode(bytes) do
        {:ok, %{"sourcesContent" => sources_content}} when is_list(sources_content) ->
          {:error, :plugin_archive_runtime_dependency}

        {:ok, _map} ->
          :ok

        {:error, _reason} ->
          {:error, :plugin_archive_runtime_dependency}
      end
    else
      :ok
    end
  end

  defp resource_extension(path) do
    path
    |> Path.extname()
    |> String.downcase()
  end

  defp resource_manifest(resources) do
    Enum.map(resources, fn resource ->
      %{
        "path" => resource.path,
        "kind" => resource.kind,
        "media_type" => resource.media_type,
        "byte_length" => resource.byte_length,
        "hash" => resource.hash,
        "executable" => resource.kind == "wasm"
      }
    end)
  end

  defp package_entries(parts, resources) do
    [
      %{
        entry_kind: "manifest",
        logical_path: "manifest.json",
        media_type: "application/json",
        bytes: parts.manifest_json
      },
      %{
        entry_kind: "main_js",
        logical_path: "main.js",
        media_type: "application/javascript",
        bytes: parts.main_js
      }
    ] ++
      styles_entry(parts.styles_css) ++
      Enum.map(resources, fn resource ->
        %{
          entry_kind: "resource",
          logical_path: resource.path,
          resource_kind: resource.kind,
          media_type: resource.media_type,
          bytes: resource.bytes
        }
      end)
  end

  defp styles_entry(""), do: []

  defp styles_entry(styles_css) do
    [
      %{
        entry_kind: "styles_css",
        logical_path: "styles.css",
        media_type: "text/css",
        bytes: styles_css
      }
    ]
  end

  defp invalid_archive_path?(filename) do
    filename == "" or String.starts_with?(filename, "/") or String.contains?(filename, "\\") or
      String.contains?(filename, "../") or String.contains?(filename, "/..") or
      String.contains?(filename, "//") or dot_path_segment?(filename) or
      control_character?(filename)
  end

  defp valid_resource_logical_path?("resources/" <> rest) when rest != "" do
    not dot_path_segment?(rest) and not String.contains?(rest, "//") and
      not control_character?(rest)
  end

  defp valid_resource_logical_path?(_path), do: false

  defp dot_path_segment?(path) do
    path
    |> String.split("/")
    |> Enum.any?(&(&1 in [".", ".."]))
  end

  defp runtime_dependency?(main_js) do
    normalized = normalize_js_dependency_scan(main_js)

    compact =
      normalized
      |> then(&Regex.replace(~r/\s+/u, &1, ""))
      |> normalize_js_string_concatenations()

    computed_compact =
      main_js
      |> then(&Regex.replace(~r/\s+/u, &1, ""))
      |> normalize_js_string_concatenations()

    String.contains?(normalized, [
      "import ",
      "import(",
      " from \"",
      " from '",
      "importScripts",
      "navigator.serviceWorker",
      "new Worker",
      "new SharedWorker",
      "new Blob",
      "URL.createObjectURL"
    ]) or
      String.contains?(compact, [
        "import(",
        "import\"",
        "import'",
        "from\"",
        "from'",
        "importScripts(",
        "navigator.serviceWorker",
        "navigator[\"serviceWorker\"]",
        "navigator['serviceWorker']",
        "navigator[`serviceWorker`]",
        "newWorker(",
        "newSharedWorker(",
        "newBlob(",
        "URL.createObjectURL",
        "URL[\"createObjectURL\"]",
        "URL['createObjectURL']",
        "URL[`createObjectURL`]"
      ]) or computed_runtime_dependency?(computed_compact) or
      String.contains?(normalized, @forbidden_host_api_tokens) or
      computed_host_api_access?(computed_compact)
  end

  defp normalize_js_dependency_scan(source) do
    JavaScriptSource.mask_non_code(source)
  end

  defp normalize_js_string_concatenations(source) do
    normalized = Regex.replace(~r/(["'])([A-Za-z]+)\1\+(["'])([A-Za-z]+)\3/u, source, ~S("\2\4"))

    if normalized == source do
      normalized
    else
      normalize_js_string_concatenations(normalized)
    end
  end

  defp computed_runtime_dependency?(compact) do
    Enum.any?(
      [
        ~r/(?:navigator|globalThis|window|self)\[[`"']serviceWorker[`"']\]/u,
        ~r/(?:globalThis|window|self)\[[`"']importScripts[`"']\]\(/u,
        ~r/new\(*?(?:globalThis|window|self)\[[`"'](?:Worker|SharedWorker|Blob)[`"']\]\)*\(/u,
        ~r/(?:URL|\(*?(?:globalThis|window|self)\[[`"']URL[`"']\]\)*?)\[[`"']createObjectURL[`"']\]\(/u
      ],
      &Regex.match?(&1, compact)
    )
  end

  defp computed_host_api_access?(compact) do
    token_pattern =
      @forbidden_host_api_tokens
      |> Enum.map_join("|", &Regex.escape/1)

    Regex.match?(
      ~r/(?:globalThis|window|self)\[[`"'](?:#{token_pattern})[`"']\]/u,
      compact
    )
  end

  defp unsafe_main_source?(source) do
    JavaScriptSource.unsafe_control_character?(source)
  end

  defp unsafe_style_source?(source) do
    Regex.match?(~r/<\/style/iu, source) or
      Regex.match?(~r/[\x{0001}-\x{0008}\x{000B}\x{000C}\x{000E}-\x{001F}\x{007F}]/u, source)
  end

  defp parse_manifest(raw) do
    {:ok, JCS.parse_json_strict!(raw)}
  rescue
    ArgumentError -> {:error, :plugin_manifest_invalid}
  end

  defp validated_manifest_permissions(%{"permissions" => permissions})
       when is_list(permissions) do
    case Enum.all?(permissions, &valid_manifest_permission?/1) do
      true -> {:ok, Enum.filter(permissions, &is_binary/1)}
      false -> {:error, :plugin_manifest_invalid_permission}
    end
  end

  defp validated_manifest_permissions(%{"permissions" => _permissions}),
    do: {:error, :plugin_manifest_invalid_permission}

  defp validated_manifest_permissions(_manifest), do: {:ok, []}

  defp valid_manifest_permission?(permission) when is_binary(permission) and permission != "" do
    MapSet.member?(@literal_permissions, permission) or
      MapSet.member?(@ui_permissions, permission) or
      scoped_document_read_permission?(permission) or
      storage_permission?(permission) or
      renderer_plaintext_permission?(permission)
  end

  defp valid_manifest_permission?(_permission), do: false

  defp scoped_document_read_permission?("document:read:" <> scope),
    do: scope in ["active", "selected", "workspace"]

  defp scoped_document_read_permission?(_permission), do: false

  defp storage_permission?("storage:" <> rest) do
    case String.split(rest, ":", parts: 2) do
      [operation, surface] when operation in ["read", "write"] ->
        MapSet.member?(@storage_surfaces, surface)

      _ ->
        false
    end
  end

  defp storage_permission?(_permission), do: false

  defp renderer_plaintext_permission?("plaintext:render:" <> rest) do
    case String.split(rest, ":", parts: 2) do
      ["block", type] -> valid_renderer_slot_type?(type)
      ["inline", "code"] -> true
      _ -> false
    end
  end

  defp renderer_plaintext_permission?(_permission), do: false

  defp validate_manifest_renderer_slots(%{"rendererSlots" => slots}) when is_list(slots) do
    if Enum.all?(slots, &valid_manifest_renderer_slot?/1) do
      :ok
    else
      {:error, :plugin_manifest_invalid_renderer_slot}
    end
  end

  defp validate_manifest_renderer_slots(%{"rendererSlots" => _slots}),
    do: {:error, :plugin_manifest_invalid_renderer_slot}

  defp validate_manifest_renderer_slots(_manifest), do: :ok

  defp valid_manifest_renderer_slot?(%{"kind" => "block", "type" => type}) when is_binary(type) do
    valid_renderer_slot_type?(type)
  end

  defp valid_manifest_renderer_slot?(%{"kind" => "inline", "type" => "code"}), do: true

  defp valid_manifest_renderer_slot?(_slot), do: false

  defp valid_renderer_slot_type?(type) when is_binary(type) do
    Regex.match?(@renderer_slot_type_pattern, type) and
      not MapSet.member?(@forbidden_renderer_slot_types, type)
  end

  defp plaintext_read_permission?("document:read:" <> scope)
       when scope in ["active", "selected", "workspace"],
       do: true

  defp plaintext_read_permission?("plaintext:render:" <> _scope), do: true
  defp plaintext_read_permission?("editor:selection:read"), do: true
  defp plaintext_read_permission?("editor:context:read"), do: true
  defp plaintext_read_permission?(_permission), do: false

  defp server_synced_storage_write_permission?(permission),
    do: MapSet.member?(@server_synced_storage_write_permissions, permission)

  defp required_manifest_string(manifest, keys) do
    case Enum.find_value(keys, &Map.get(manifest, &1)) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, :plugin_manifest_required_field_missing}
    end
  end

  defp semantic_hash(value), do: Hash.blake3_base64url(JCS.canonical_value_bytes!(value))

  defp source_metadata(source_kind, source_url)
       when source_kind in [:local_upload, @local_source_kind] do
    if is_nil(source_url) do
      {:ok, %{kind: @local_source_kind, url: nil, url_hash: @source_url_hash_sentinel}}
    else
      {:error, :plugin_source_url_not_allowed}
    end
  end

  defp source_metadata(source_kind, source_url)
       when source_kind in [:remote_https_url, @remote_source_kind] and is_binary(source_url) do
    with {:ok, canonical_url} <- canonical_remote_url(source_url) do
      {:ok,
       %{
         kind: @remote_source_kind,
         url: canonical_url,
         url_hash: Hash.blake3_base64url(canonical_url)
       }}
    end
  end

  defp source_metadata(_, _), do: {:error, :plugin_source_invalid}

  defp canonical_remote_url(url) do
    uri = URI.parse(url)

    with :ok <- reject_control_characters(url),
         :ok <- validate_https_scheme(uri),
         {:ok, host} <- normalize_remote_host(uri),
         :ok <- reject_remote_url_parts(uri),
         :ok <- reject_private_host(host) do
      path = if is_nil(uri.path) or uri.path == "", do: "/", else: uri.path
      {:ok, URI.to_string(%{uri | scheme: "https", host: host, path: path, fragment: nil})}
    end
  end

  defp reject_control_characters(value) when is_binary(value) do
    if control_character?(value),
      do: {:error, :plugin_source_invalid},
      else: :ok
  end

  defp control_character?(value) when is_binary(value) do
    String.match?(value, ~r/[\x00-\x1F\x7F]/)
  end

  defp validate_https_scheme(%URI{scheme: "https"}), do: :ok
  defp validate_https_scheme(_uri), do: {:error, :plugin_source_https_required}

  defp normalize_remote_host(%URI{host: host}) when is_binary(host) and host != "",
    do: {:ok, String.downcase(host)}

  defp normalize_remote_host(_uri), do: {:error, :plugin_source_invalid}

  defp reject_remote_url_parts(%URI{userinfo: nil, fragment: nil}), do: :ok
  defp reject_remote_url_parts(_uri), do: {:error, :plugin_source_invalid}

  defp reject_private_host(host) do
    if private_host?(host),
      do: {:error, :plugin_source_private_target},
      else: :ok
  end

  defp private_host?(host) do
    normalized = String.trim_trailing(host, ".")

    MapSet.member?(@metadata_endpoint_hosts, normalized) or normalized in ["localhost"] or
      String.ends_with?(normalized, ".localhost") or String.ends_with?(normalized, ".local") or
      ip_literal?(normalized)
  end

  defp ip_literal?(host),
    do: match?({:ok, _address}, :inet.parse_address(String.to_charlist(host)))

  defp resolve_host_addresses(host) do
    addresses =
      [:inet, :inet6]
      |> Enum.flat_map(fn family ->
        case :inet.getaddrs(String.to_charlist(host), family) do
          {:ok, resolved} -> resolved
          {:error, _reason} -> []
        end
      end)

    case addresses do
      [] -> {:error, :plugin_source_dns_failed}
      addresses -> {:ok, addresses}
    end
  end

  defp private_ip_address?({10, _, _, _}), do: true
  defp private_ip_address?({127, _, _, _}), do: true
  defp private_ip_address?({169, 254, _, _}), do: true
  defp private_ip_address?({100, second, _, _}) when second in 64..127, do: true
  defp private_ip_address?({100, 100, 100, 200}), do: true
  defp private_ip_address?({172, second, _, _}) when second in 16..31, do: true
  defp private_ip_address?({192, 168, _, _}), do: true
  defp private_ip_address?({0, 0, 0, 0}), do: true
  defp private_ip_address?({first, _, _, _}) when first in 224..239, do: true
  defp private_ip_address?({0, 0, 0, 0, 0, 0, 0, 0}), do: true
  defp private_ip_address?({0, 0, 0, 0, 0, 0, 0, 1}), do: true

  defp private_ip_address?({0, 0, 0, 0, 0, 0xFFFF, high, low}),
    do: private_ip_address?({high >>> 8, high &&& 0xFF, low >>> 8, low &&& 0xFF})

  defp private_ip_address?({first, _, _, _, _, _, _, _}) when first in 0xFE80..0xFEBF, do: true
  defp private_ip_address?({first, _, _, _, _, _, _, _}) when first in 0xFC00..0xFDFF, do: true
  defp private_ip_address?({first, _, _, _, _, _, _, _}) when first in 0xFF00..0xFFFF, do: true
  defp private_ip_address?(_address), do: false

  defp fetch!(map, key) do
    Map.get(map, key) || Map.fetch!(map, Atom.to_string(key))
  end
end
