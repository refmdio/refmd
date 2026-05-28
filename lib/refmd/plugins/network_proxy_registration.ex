defmodule RefMD.Plugins.NetworkProxyRegistration do
  @moduledoc false

  @allowed_scopes ~w(user workspace)
  @id_regex ~r/\A[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}\z/

  @type scope :: String.t()
  @type t :: %{
          required(String.t()) => String.t() | boolean() | [String.t()] | map()
        }

  @spec normalize(term(), scope()) :: {:ok, t() | nil} | {:error, atom()}
  def normalize(nil, _expected_scope), do: {:ok, nil}

  def normalize(%{} = value, expected_scope) when expected_scope in @allowed_scopes do
    with {:ok, id} <- required_string(value, "id"),
         :ok <- validate_id(id),
         {:ok, label} <- required_string(value, "label"),
         {:ok, base_url} <- required_string(value, "base_url"),
         :ok <- validate_base_url(base_url),
         {:ok, scope} <- required_string(value, "scope"),
         :ok <- validate_scope(scope, expected_scope),
         {:ok, enabled} <- optional_boolean(value, "enabled"),
         {:ok, operator_label} <- optional_string(value, "operator_label", label),
         {:ok, allowed_workspace_ids} <- optional_string_list(value, "allowed_workspace_ids"),
         {:ok, allowed_user_ids} <- optional_string_list(value, "allowed_user_ids"),
         {:ok, verification_material} <- optional_verification_material(value),
         {:ok, revoked} <- optional_boolean(value, "revoked", false),
         {:ok, policy} <- optional_policy(value) do
      {:ok,
       %{
         "id" => id,
         "label" => label,
         "base_url" => normalize_base_url(base_url),
         "scope" => scope,
         "enabled" => enabled,
         "operator_label" => operator_label,
         "allowed_workspace_ids" => allowed_workspace_ids,
         "allowed_user_ids" => allowed_user_ids,
         "verification_material" => verification_material,
         "revoked" => revoked,
         "policy" => policy
       }}
    end
  end

  def normalize(_value, _expected_scope), do: {:error, :invalid_proxy_registration}

  defp required_string(value, key) do
    case Map.get(value, key) || Map.get(value, String.to_existing_atom(key)) do
      field when is_binary(field) ->
        trimmed = String.trim(field)
        if trimmed == "", do: {:error, :invalid_proxy_registration}, else: {:ok, trimmed}

      _ ->
        {:error, :invalid_proxy_registration}
    end
  rescue
    ArgumentError -> {:error, :invalid_proxy_registration}
  end

  defp optional_boolean(value, key) do
    optional_boolean(value, key, true)
  end

  defp optional_boolean(value, key, default) do
    case Map.get(value, key, Map.get(value, safe_atom(key), default)) do
      field when is_boolean(field) -> {:ok, field}
      nil -> {:ok, default}
      _ -> {:error, :invalid_proxy_registration}
    end
  end

  defp optional_string(value, key, default) do
    case Map.get(value, key, Map.get(value, safe_atom(key), default)) do
      field when is_binary(field) ->
        trimmed = String.trim(field)
        if trimmed == "", do: {:error, :invalid_proxy_registration}, else: {:ok, trimmed}

      nil ->
        {:ok, default}

      _ ->
        {:error, :invalid_proxy_registration}
    end
  end

  defp optional_string_list(value, key) do
    case Map.get(value, key, Map.get(value, safe_atom(key), [])) do
      fields when is_list(fields) ->
        normalized =
          fields
          |> Enum.map(fn
            field when is_binary(field) -> String.trim(field)
            _ -> :invalid
          end)

        if Enum.any?(normalized, &(&1 in ["", :invalid])),
          do: {:error, :invalid_proxy_registration},
          else: {:ok, Enum.uniq(normalized)}

      nil ->
        {:ok, []}

      _ ->
        {:error, :invalid_proxy_registration}
    end
  end

  defp optional_verification_material(value) do
    with {:ok, material} <- optional_map(value, "verification_material") do
      validate_verification_material(material)
    end
  end

  defp validate_verification_material(material) do
    allowed = ~w(response_signing_key response_signature_protocol response_key_id)

    if Enum.all?(material, &verification_material_entry?(&1, allowed)),
      do: {:ok, material},
      else: {:error, :invalid_proxy_registration}
  end

  defp verification_material_entry?({key, field}, allowed),
    do: key in allowed and is_binary(field)

  defp optional_policy(value) do
    with {:ok, policy} <- optional_map(value, "policy"),
         :ok <- validate_optional_positive_integer(policy, "max_request_size"),
         :ok <- validate_optional_positive_integer(policy, "max_response_size"),
         :ok <- validate_optional_policy_string_list(policy, "allowed_route_classes"),
         :ok <- validate_optional_policy_string_list(policy, "allowed_endpoint_ids"),
         :ok <- validate_optional_policy_string_list(policy, "denied_endpoint_ids") do
      allowed =
        ~w(max_request_size max_response_size allowed_route_classes allowed_endpoint_ids denied_endpoint_ids)

      if Enum.all?(Map.keys(policy), &(&1 in allowed)),
        do: {:ok, policy},
        else: {:error, :invalid_proxy_registration}
    end
  end

  defp optional_map(value, key) do
    case Map.get(value, key, Map.get(value, safe_atom(key), %{})) do
      field when is_map(field) -> {:ok, stringify_keys(field)}
      nil -> {:ok, %{}}
      _ -> {:error, :invalid_proxy_registration}
    end
  end

  defp validate_optional_positive_integer(policy, key) do
    case Map.get(policy, key) do
      nil -> :ok
      value when is_integer(value) and value >= 1 -> :ok
      _ -> {:error, :invalid_proxy_registration}
    end
  end

  defp validate_optional_policy_string_list(policy, key) do
    case Map.get(policy, key) do
      nil -> :ok
      value when is_list(value) -> validate_string_list(value)
      _ -> {:error, :invalid_proxy_registration}
    end
  end

  defp validate_string_list(values) do
    if Enum.all?(values, &(is_binary(&1) and String.trim(&1) != "")),
      do: :ok,
      else: {:error, :invalid_proxy_registration}
  end

  defp stringify_keys(map) do
    Map.new(map, fn
      {key, value} when is_atom(key) -> {Atom.to_string(key), value}
      {key, value} -> {key, value}
    end)
  end

  defp safe_atom(key) do
    String.to_existing_atom(key)
  rescue
    ArgumentError -> key
  end

  defp validate_id(id),
    do: if(Regex.match?(@id_regex, id), do: :ok, else: {:error, :invalid_proxy_registration})

  defp validate_scope(scope, expected_scope) do
    cond do
      scope != expected_scope -> {:error, :invalid_proxy_registration}
      scope in @allowed_scopes -> :ok
      true -> {:error, :invalid_proxy_registration}
    end
  end

  defp validate_base_url(url) do
    case URI.parse(url) do
      %URI{scheme: "https", host: host} = uri when is_binary(host) and host != "" ->
        if uri |> RefMD.AppOrigin.uri_origin() |> RefMD.AppOrigin.app_origin?() do
          {:error, :invalid_proxy_registration}
        else
          :ok
        end

      _ ->
        {:error, :invalid_proxy_registration}
    end
  end

  defp normalize_base_url(url) do
    uri = URI.parse(url)
    path = String.trim_trailing(uri.path || "", "/")
    host = uri.host |> String.downcase() |> String.trim_trailing(".")
    port = if uri.port == 443, do: nil, else: uri.port

    URI.to_string(%{
      uri
      | scheme: String.downcase(uri.scheme),
        host: host,
        port: port,
        path: path
    })
  end
end
