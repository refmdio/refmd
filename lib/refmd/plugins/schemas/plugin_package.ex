defmodule RefMD.Plugins.PluginPackage do
  use Ecto.Schema
  import Ecto.Changeset

  alias RefMD.Crypto.Hash

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @owner_scope_kinds ~w(workspace user)

  schema "plugin_packages" do
    belongs_to :owner_workspace, RefMD.Workspaces.Workspace
    belongs_to :owner_user, RefMD.Users.User
    belongs_to :created_by_user, RefMD.Users.User
    belongs_to :created_by_device, RefMD.Devices.Device
    belongs_to :current_bundle, RefMD.Plugins.PluginBundle

    field :plugin_id, :string
    field :version, :string
    field :owner_scope_kind, :string
    field :bundle_hash, :string
    field :resource_manifest_hash, :string
    field :state_head_hash, :string

    has_many :applications, RefMD.Plugins.PluginApplication, foreign_key: :package_id
    has_many :entries, RefMD.Plugins.PluginPackageEntry, foreign_key: :package_id
    has_many :bundles, RefMD.Plugins.PluginBundle, foreign_key: :package_id

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
  end

  @type t :: %__MODULE__{}

  @required_fields [
    :plugin_id,
    :version,
    :owner_scope_kind,
    :bundle_hash,
    :resource_manifest_hash,
    :state_head_hash
  ]

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(package, attrs) do
    package
    |> cast(
      attrs,
      @required_fields ++
        [
          :owner_workspace_id,
          :owner_user_id,
          :created_by_user_id,
          :created_by_device_id,
          :current_bundle_id
        ]
    )
    |> validate_required(@required_fields)
    |> validate_inclusion(:owner_scope_kind, @owner_scope_kinds)
    |> validate_owner_scope()
    |> validate_non_empty(:plugin_id)
    |> validate_non_empty(:version)
    |> validate_hash(:bundle_hash)
    |> validate_hash(:resource_manifest_hash)
    |> validate_state_head_hash()
    |> foreign_key_constraint(:owner_workspace_id)
    |> foreign_key_constraint(:owner_user_id)
    |> foreign_key_constraint(:created_by_user_id)
    |> foreign_key_constraint(:created_by_device_id)
    |> foreign_key_constraint(:current_bundle_id)
    |> unique_constraint(
      [:owner_scope_kind, :owner_workspace_id, :plugin_id, :version, :bundle_hash],
      name: :plugin_packages_workspace_owner_package_index
    )
    |> unique_constraint(
      [:owner_scope_kind, :owner_user_id, :plugin_id, :version, :bundle_hash],
      name: :plugin_packages_user_owner_package_index
    )
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

  defp validate_state_head_hash(changeset) do
    validate_change(changeset, :state_head_hash, fn :state_head_hash, value ->
      if value == "GENESIS" do
        []
      else
        try do
          Hash.assert_blake3_base64url!(value)
          []
        rescue
          ArgumentError -> [state_head_hash: "must be GENESIS or a BLAKE3 base64url hash"]
        end
      end
    end)
  end
end
