defmodule RefMD.Plugins.PluginPackageEntry do
  use Ecto.Schema
  import Ecto.Changeset

  alias RefMD.Crypto.Hash

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id
  @owner_scope_kinds ~w(workspace user)
  @entry_kinds ~w(manifest main_js styles_css resource)
  @statuses ~w(candidate pinned rejected orphan_pending_delete)
  @storage_path_prefix "plugin-packages/"

  schema "plugin_package_entries" do
    belongs_to :owner_workspace, RefMD.Workspaces.Workspace
    belongs_to :owner_user, RefMD.Users.User
    belongs_to :candidate, RefMD.Plugins.PluginBundleCandidate
    belongs_to :bundle, RefMD.Plugins.PluginBundle
    belongs_to :package, RefMD.Plugins.PluginPackage

    field :owner_scope_kind, :string
    field :entry_kind, :string
    field :logical_path, :string
    field :resource_kind, :string
    field :media_type, :string
    field :byte_length, :integer
    field :hash, :string
    field :storage_path, :string
    field :status, :string
    field :pinned_at, :utc_datetime_usec
    field :deleted_at, :utc_datetime_usec

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at, updated_at: false)
  end

  @required_fields [
    :owner_scope_kind,
    :entry_kind,
    :logical_path,
    :media_type,
    :byte_length,
    :hash,
    :storage_path,
    :status
  ]

  def changeset(entry, attrs) do
    entry
    |> cast(
      attrs,
      @required_fields ++
        [
          :owner_workspace_id,
          :owner_user_id,
          :candidate_id,
          :bundle_id,
          :package_id,
          :resource_kind,
          :pinned_at,
          :deleted_at
        ]
    )
    |> validate_required(@required_fields)
    |> validate_inclusion(:owner_scope_kind, @owner_scope_kinds)
    |> validate_inclusion(:entry_kind, @entry_kinds)
    |> validate_inclusion(:status, @statuses)
    |> validate_number(:byte_length, greater_than_or_equal_to: 0)
    |> validate_owner_scope()
    |> validate_logical_path()
    |> validate_non_empty(:media_type)
    |> validate_non_empty(:storage_path)
    |> validate_storage_path()
    |> validate_hash(:hash)
    |> check_constraint(:storage_path, name: :plugin_package_entries_storage_path_id_check)
    |> unique_constraint(:storage_path)
    |> unique_constraint([:candidate_id, :logical_path])
    |> unique_constraint([:bundle_id, :logical_path])
    |> unique_constraint([:candidate_id, :entry_kind],
      name: :plugin_package_entries_candidate_singleton_kind_index
    )
    |> unique_constraint([:bundle_id, :entry_kind],
      name: :plugin_package_entries_bundle_singleton_kind_index
    )
    |> foreign_key_constraint(:owner_workspace_id)
    |> foreign_key_constraint(:owner_user_id)
    |> foreign_key_constraint(:candidate_id)
    |> foreign_key_constraint(:bundle_id)
    |> foreign_key_constraint(:package_id)
  end

  defp validate_owner_scope(changeset) do
    scope = get_field(changeset, :owner_scope_kind)
    workspace_id = get_field(changeset, :owner_workspace_id)
    user_id = get_field(changeset, :owner_user_id)

    case {scope, workspace_id, user_id} do
      {"workspace", workspace_id, nil} when is_binary(workspace_id) -> changeset
      {"user", nil, user_id} when is_binary(user_id) -> changeset
      _ -> add_error(changeset, :owner_scope_kind, "must match exactly one owner id")
    end
  end

  defp validate_logical_path(changeset) do
    entry_kind = get_field(changeset, :entry_kind)
    logical_path = get_field(changeset, :logical_path)

    case {entry_kind, logical_path} do
      {"manifest", "manifest.json"} ->
        changeset

      {"main_js", "main.js"} ->
        changeset

      {"styles_css", "styles.css"} ->
        changeset

      {"resource", "resources/" <> rest} when rest != "" ->
        validate_resource_logical_path(changeset, rest)

      _ ->
        add_error(changeset, :logical_path, "must match entry kind")
    end
  end

  defp validate_storage_path(changeset) do
    entry_id = get_field(changeset, :id)
    storage_path = get_field(changeset, :storage_path)

    if is_binary(entry_id) and storage_path == @storage_path_prefix <> entry_id do
      changeset
    else
      add_error(changeset, :storage_path, "must match package entry object key")
    end
  end

  defp validate_resource_logical_path(changeset, rest) do
    segments = String.split(rest, "/")

    if String.contains?(rest, "\\") or control_character?(rest) or
         Enum.any?(segments, &(&1 in ["", ".", ".."])) do
      add_error(changeset, :logical_path, "must be a canonical resource path")
    else
      changeset
    end
  end

  defp control_character?(value) when is_binary(value) do
    String.match?(value, ~r/[\x00-\x1F\x7F]/)
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

  defp validate_hash(changeset, field) do
    validate_change(changeset, field, fn ^field, value ->
      try do
        Hash.assert_blake3_base64url!(value)
        []
      rescue
        ArgumentError -> [{field, "must be a BLAKE3 base64url hash"}]
      end
    end)
  end
end
