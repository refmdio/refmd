defmodule RefMD.Plugins.PluginStorageEntry do
  @moduledoc false

  import Ecto.Changeset

  @scopes ~w(document workspace)

  @spec changeset(struct(), map()) :: Ecto.Changeset.t()
  def changeset(entry, attrs) do
    entry
    |> cast(attrs, [
      :application_id,
      :package_id,
      :activation_id,
      :workspace_id,
      :plugin_id,
      :scope,
      :scope_id,
      :key,
      :ciphertext,
      :nonce,
      :key_version
    ])
    |> validate_required([
      :application_id,
      :package_id,
      :activation_id,
      :workspace_id,
      :plugin_id,
      :scope,
      :scope_id,
      :key,
      :ciphertext,
      :nonce,
      :key_version
    ])
    |> validate_inclusion(:scope, @scopes)
    |> validate_number(:key_version, greater_than: 0)
    |> validate_binary_present(:ciphertext)
    |> validate_binary_present(:nonce)
    |> validate_non_empty(:plugin_id)
    |> validate_non_empty(:scope_id)
    |> validate_non_empty(:key)
    |> unique_constraint(:key, name: :plugin_kv_application_scope_key_index)
    |> foreign_key_constraint(:application_id)
    |> foreign_key_constraint(:package_id)
    |> foreign_key_constraint(:activation_id)
    |> foreign_key_constraint(:workspace_id)
  end

  defp validate_binary_present(changeset, field) do
    validate_change(changeset, field, fn ^field, value ->
      if is_binary(value) and byte_size(value) > 0 do
        []
      else
        [{field, "must not be empty"}]
      end
    end)
  end

  defp validate_non_empty(changeset, field) do
    validate_change(changeset, field, fn ^field, value ->
      if is_binary(value) and String.trim(value) != "" do
        []
      else
        [{field, "must not be empty"}]
      end
    end)
  end
end
