defmodule RefMD.Sharing.Input do
  @moduledoc false

  alias RefMD.Crypto.Signature
  alias RefMD.Documents.Document

  @max_safe_integer 9_007_199_254_740_991
  def fetch_uuid(attrs, key) do
    case dual_key_get(attrs, key) do
      value when is_binary(value) -> parse_uuid_value(value, key)
      _ -> {:error, {:missing_field, key}}
    end
  end

  def fetch_enum(attrs, key, allowed) do
    case dual_key_get(attrs, key) do
      value when is_binary(value) ->
        if value in allowed, do: {:ok, value}, else: {:error, {:invalid_value, key}}

      nil ->
        {:error, {:missing_field, key}}

      _ ->
        {:error, {:invalid_value, key}}
    end
  end

  def fetch_boolean(attrs, key) do
    case dual_key_get(attrs, key) do
      value when is_boolean(value) -> {:ok, value}
      nil -> {:error, {:missing_field, key}}
      _ -> {:error, {:invalid_value, key}}
    end
  end

  def fetch_binary(attrs, key) do
    case dual_key_get(attrs, key) do
      value when is_binary(value) -> {:ok, value}
      _ -> {:error, {:missing_field, key}}
    end
  end

  def fetch_optional_binary(attrs, key) do
    case dual_key_get(attrs, key) do
      nil -> {:ok, nil}
      value when is_binary(value) -> {:ok, value}
      _ -> {:error, {:invalid_value, key}}
    end
  end

  def fetch_authorization_public_key_material(attrs) do
    material = dual_key_get(attrs, :authorization_public_key_material)

    Signature.assert_public_key_material!(material)

    if material["owner_kind"] == "share_capability" do
      {:ok, material}
    else
      {:error, {:invalid_public_key, :authorization_public_key_material}}
    end
  rescue
    ArgumentError -> {:error, {:invalid_public_key, :authorization_public_key_material}}
  end

  def validate_authorization_public_key_material(
        %{"owner_kind" => "share_capability", "owner_id" => token_hash},
        token_hash
      ),
      do: :ok

  def validate_authorization_public_key_material(_material, _token_hash),
    do: {:error, {:invalid_public_key, :authorization_public_key_material}}

  def fetch_required_base64url_hash(attrs, key) do
    case dual_key_get(attrs, key) do
      value when is_binary(value) ->
        if String.match?(value, ~r/^[A-Za-z0-9\-_]{43}$/),
          do: {:ok, value},
          else: {:error, {:invalid_value, key}}

      nil ->
        {:error, {:missing_field, key}}

      _ ->
        {:error, {:invalid_value, key}}
    end
  end

  def fetch_password_capability_secret_commitment(attrs, password_protected) do
    value = dual_key_get(attrs, :password_capability_secret_commitment)

    normalize_password_capability_secret_commitment(value, password_protected)
  end

  defp normalize_password_capability_secret_commitment("none" = value, false), do: {:ok, value}

  defp normalize_password_capability_secret_commitment(nil, false), do: {:ok, "none"}

  defp normalize_password_capability_secret_commitment(nil, true),
    do: {:error, {:missing_field, :password_capability_secret_commitment}}

  defp normalize_password_capability_secret_commitment(value, true) when is_binary(value) do
    if String.match?(value, ~r/^[A-Za-z0-9\-_]{43}$/) do
      {:ok, value}
    else
      {:error, {:invalid_value, :password_capability_secret_commitment}}
    end
  end

  defp normalize_password_capability_secret_commitment(_, _),
    do: {:error, {:invalid_value, :password_capability_secret_commitment}}

  def fetch_optional_map(attrs, key) do
    case dual_key_get(attrs, key) do
      nil -> {:ok, nil}
      value when is_map(value) -> {:ok, value}
      _ -> {:error, {:invalid_value, key}}
    end
  end

  def fetch_required_map(attrs, key) do
    case dual_key_get(attrs, key) do
      value when is_map(value) -> {:ok, value}
      nil -> {:error, {:missing_field, key}}
      _ -> {:error, {:invalid_value, key}}
    end
  end

  def fetch_optional_datetime(attrs, key) do
    case dual_key_get(attrs, key) do
      nil ->
        {:ok, nil}

      value when is_binary(value) ->
        case DateTime.from_iso8601(value) do
          {:ok, datetime, _} -> {:ok, datetime}
          _ -> {:error, {:invalid_datetime, key}}
        end

      _ ->
        {:error, {:invalid_datetime, key}}
    end
  end

  def fetch_optional_positive_integer(attrs, key) do
    case dual_key_get(attrs, key) do
      nil -> {:ok, nil}
      value when is_integer(value) and value > 0 -> {:ok, value}
      _ -> {:error, {:invalid_integer, key}}
    end
  end

  def fetch_required_positive_integer(attrs, key) do
    case fetch_optional_positive_integer(attrs, key) do
      {:ok, nil} -> {:error, {:missing_field, key}}
      result -> result
    end
  end

  def fetch_folder_share_keys(attrs, "document", _password_protected) do
    case dual_key_get(attrs, :share_keys) do
      nil -> {:ok, []}
      _ -> {:error, {:invalid_value, :share_keys}}
    end
  end

  def fetch_folder_share_keys(attrs, "folder", password_protected) do
    case dual_key_get(attrs, :share_keys) do
      nil ->
        {:error, {:missing_field, :share_keys}}

      [] ->
        {:ok, []}

      share_keys when is_list(share_keys) ->
        parse_folder_share_key_entries(share_keys, password_protected)

      _ ->
        {:error, {:invalid_value, :share_keys}}
    end
  end

  def fetch_folder_share_exclusions(attrs, "document") do
    case dual_key_get(attrs, :exclusions) do
      nil -> {:ok, []}
      _ -> {:error, {:invalid_value, :exclusions}}
    end
  end

  def fetch_folder_share_exclusions(attrs, "folder") do
    case dual_key_get(attrs, :exclusions) do
      nil -> {:ok, []}
      exclusions when is_list(exclusions) -> parse_uuid_list(exclusions, :exclusions)
      _ -> {:error, {:invalid_value, :exclusions}}
    end
  end

  def validate_share_scope(%Document{doc_type: "document"}, "document"), do: :ok
  def validate_share_scope(%Document{doc_type: "folder"}, "folder"), do: :ok
  def validate_share_scope(%Document{}, _scope), do: {:error, {:invalid_value, :scope}}

  def validate_active_share_root(%Document{archived_at: nil}), do: :ok
  def validate_active_share_root(%Document{}), do: {:error, {:invalid_value, :document_id}}

  def fetch_token_prefix(attrs, share_slug) do
    expected = String.slice(share_slug, 0, 4)

    case dual_key_get(attrs, :token_prefix) do
      ^expected -> {:ok, expected}
      _ -> {:error, :invalid_token_prefix}
    end
  end

  def validate_password_share_fields(false, nil, nil), do: :ok

  def validate_password_share_fields(false, _salt, _kdf_params),
    do: {:error, {:invalid_value, :password_protected}}

  def validate_password_share_fields(true, salt, kdf_params) do
    cond do
      not is_binary(salt) or byte_size(salt) != 16 -> {:error, {:missing_field, :salt}}
      not is_map(kdf_params) -> {:error, {:missing_field, :kdf_params}}
      not valid_share_kdf_params?(kdf_params) -> {:error, :invalid_kdf_params}
      true -> :ok
    end
  end

  def fetch_password_auth_key(_attrs, false), do: {:ok, nil}

  def fetch_password_auth_key(attrs, true) do
    case dual_key_get(attrs, :auth_key) do
      value when is_binary(value) and byte_size(value) == 32 ->
        {:ok, value}

      value when is_binary(value) ->
        case Base.url_decode64(value, padding: false) do
          {:ok, decoded} when byte_size(decoded) == 32 -> {:ok, decoded}
          _ -> {:error, {:invalid_value, :auth_key}}
        end

      nil ->
        {:error, {:missing_field, :auth_key}}

      _ ->
        {:error, {:invalid_value, :auth_key}}
    end
  end

  defp dual_key_get(attrs, key) when is_atom(key) do
    case Map.fetch(attrs, key) do
      {:ok, value} -> value
      :error -> Map.get(attrs, Atom.to_string(key))
    end
  end

  def validate_encrypted_dek(encrypted_dek, _password_protected)
      when byte_size(encrypted_dek) == 48,
      do: :ok

  def validate_encrypted_dek(_encrypted_dek, _password_protected),
    do: {:error, :invalid_encrypted_dek}

  def validate_share_key_nonce(nil), do: :ok
  def validate_share_key_nonce(nonce) when byte_size(nonce) == 24, do: :ok
  def validate_share_key_nonce(_nonce), do: {:error, :invalid_nonce}

  def validate_share_key_nonce(nil, _password_protected), do: {:error, :invalid_nonce}
  def validate_share_key_nonce(nonce, _password_protected), do: validate_share_key_nonce(nonce)

  def fetch_url_token(attrs, key) do
    token =
      case Map.get(attrs, key) do
        nil -> Map.get(attrs, to_string(key))
        value -> value
      end

    validate_url_token(token)
  end

  def parse_uuid_list(values, field) do
    values
    |> Enum.reduce_while({:ok, []}, fn value, {:ok, acc} ->
      case Ecto.UUID.cast(value) do
        {:ok, uuid} -> {:cont, {:ok, [uuid | acc]}}
        :error -> {:halt, {:error, {:invalid_uuid, field}}}
      end
    end)
    |> reverse_parsed_list()
  end

  def max_safe_integer, do: @max_safe_integer

  defp parse_uuid_value(value, key) when is_binary(value) do
    case Ecto.UUID.cast(value) do
      {:ok, uuid} -> {:ok, uuid}
      :error -> {:error, {:invalid_uuid, key}}
    end
  end

  defp parse_folder_share_key_entries(share_keys, password_protected) do
    share_keys
    |> Enum.reduce_while({:ok, []}, fn entry, {:ok, acc} ->
      case parse_folder_share_key_entry(entry, password_protected) do
        {:ok, parsed} -> {:cont, {:ok, [parsed | acc]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> reverse_parsed_list()
  end

  defp parse_folder_share_key_entry(entry, password_protected) when is_map(entry) do
    with {:ok, share_id} <- fetch_uuid(entry, :share_id),
         {:ok, document_id} <- fetch_uuid(entry, :document_id),
         {:ok, encrypted_dek} <- fetch_binary(entry, :encrypted_dek),
         {:ok, nonce} <- fetch_optional_binary(entry, :nonce),
         :ok <- validate_encrypted_dek(encrypted_dek, password_protected),
         :ok <- validate_share_key_nonce(nonce, password_protected) do
      {:ok,
       %{
         share_id: share_id,
         document_id: document_id,
         encrypted_dek: encrypted_dek,
         nonce: nonce
       }}
    end
  end

  defp parse_folder_share_key_entry(_entry, _password_protected),
    do: {:error, {:invalid_value, :share_keys}}

  defp reverse_parsed_list({:ok, parsed}), do: {:ok, Enum.reverse(parsed)}
  defp reverse_parsed_list(error), do: error

  defp valid_share_kdf_params?(%{
         "algorithm" => "argon2id",
         "memory" => memory,
         "iterations" => iterations,
         "parallelism" => parallelism,
         "hash_length" => hash_length
       })
       when is_integer(memory) and is_integer(iterations) and is_integer(parallelism) and
              is_integer(hash_length) do
    integer_in_range?(memory, 16_384, 262_144) and
      integer_in_range?(iterations, 2, 10) and
      integer_in_range?(parallelism, 1, 8) and
      hash_length == 32
  end

  defp valid_share_kdf_params?(_), do: false

  defp integer_in_range?(value, min, max), do: value >= min and value <= max

  defp validate_url_token(token) when is_binary(token) do
    case Base.url_decode64(token, padding: false) do
      {:ok, bytes} when byte_size(bytes) == 16 -> {:ok, token, bytes}
      _ -> {:error, :invalid_token}
    end
  end

  defp validate_url_token(_token), do: {:error, :invalid_token}
end
