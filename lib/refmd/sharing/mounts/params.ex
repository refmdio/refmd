defmodule RefMD.Sharing.Mounts.Params do
  @moduledoc false

  @spec fetch_mount_target_token(map()) :: {:ok, String.t()} | {:error, term()}
  def fetch_mount_target_token(attrs) do
    case Map.get(attrs, :target_token) || Map.get(attrs, "target_token") do
      value when is_binary(value) and byte_size(value) > 0 -> {:ok, value}
      _ -> {:error, {:missing_field, :target_token}}
    end
  end

  @spec fetch_mount_position(map()) :: {:ok, non_neg_integer()} | {:error, term()}
  def fetch_mount_position(attrs) do
    case Map.get(attrs, :position) || Map.get(attrs, "position") do
      value when is_integer(value) and value >= 0 ->
        {:ok, value}

      value when is_binary(value) ->
        case Integer.parse(value) do
          {position, ""} when position >= 0 -> {:ok, position}
          _ -> {:error, {:invalid_value, :position}}
        end

      nil ->
        {:error, {:missing_field, :position}}

      _ ->
        {:error, {:invalid_value, :position}}
    end
  end

  @spec fetch_uuid(map(), atom()) :: {:ok, Ecto.UUID.t()} | {:error, term()}
  def fetch_uuid(attrs, key) do
    case Map.get(attrs, key) || Map.get(attrs, to_string(key)) do
      value when is_binary(value) ->
        parse_uuid_value(value, key)

      _ ->
        {:error, {:missing_field, key}}
    end
  end

  @spec fetch_optional_uuid(map(), atom()) :: {:ok, Ecto.UUID.t() | nil} | {:error, term()}
  def fetch_optional_uuid(attrs, key) do
    case Map.get(attrs, key) do
      nil -> Map.get(attrs, to_string(key))
      value -> value
    end
    |> case do
      nil -> {:ok, nil}
      value -> parse_uuid_value(value, key)
    end
  end

  @spec fetch_optional_binary(map(), atom()) :: {:ok, binary() | nil} | {:error, term()}
  def fetch_optional_binary(attrs, key) do
    case Map.get(attrs, key) do
      nil -> Map.get(attrs, to_string(key))
      value -> value
    end
    |> case do
      nil -> {:ok, nil}
      value when is_binary(value) -> {:ok, value}
      _ -> {:error, {:invalid_value, key}}
    end
  end

  @spec fetch_required_binary(map(), atom()) :: {:ok, binary()} | {:error, term()}
  def fetch_required_binary(attrs, key) do
    case Map.get(attrs, key) || Map.get(attrs, to_string(key)) do
      value when is_binary(value) and byte_size(value) > 0 -> {:ok, value}
      _ -> {:error, {:missing_field, key}}
    end
  end

  @spec fetch_enum(map(), atom(), [String.t()]) :: {:ok, String.t()} | {:error, term()}
  def fetch_enum(attrs, key, allowed) do
    case Map.get(attrs, key) || Map.get(attrs, to_string(key)) do
      value when is_binary(value) ->
        if value in allowed, do: {:ok, value}, else: {:error, {:invalid_value, key}}

      nil ->
        {:error, {:missing_field, key}}

      _ ->
        {:error, {:invalid_value, key}}
    end
  end

  @spec fetch_blake3_hash(map(), atom()) :: {:ok, String.t()} | {:error, term()}
  def fetch_blake3_hash(attrs, key) do
    case Map.get(attrs, key) || Map.get(attrs, to_string(key)) do
      value when is_binary(value) ->
        if Regex.match?(~r/^[A-Za-z0-9\-_]{43}$/, value),
          do: {:ok, value},
          else: {:error, {:invalid_value, key}}

      nil ->
        {:error, {:missing_field, key}}

      _ ->
        {:error, {:invalid_value, key}}
    end
  end

  @spec fetch_url_token(map(), atom()) :: {:ok, String.t(), binary()} | {:error, term()}
  def fetch_url_token(attrs, key) do
    token =
      case Map.get(attrs, key) do
        nil -> Map.get(attrs, to_string(key))
        value -> value
      end

    validate_url_token(token)
  end

  @spec validate_url_token(term()) :: {:ok, String.t(), binary()} | {:error, :invalid_token}
  def validate_url_token(token) when is_binary(token) do
    case Base.url_decode64(token, padding: false) do
      {:ok, bytes} when byte_size(bytes) == 16 -> {:ok, token, bytes}
      _ -> {:error, :invalid_token}
    end
  end

  def validate_url_token(_token), do: {:error, :invalid_token}

  defp parse_uuid_value(value, key) when is_binary(value) do
    case Ecto.UUID.cast(value) do
      {:ok, uuid} -> {:ok, uuid}
      :error -> {:error, {:invalid_uuid, key}}
    end
  end
end
