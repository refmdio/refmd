defmodule RefMD.Plugins.PluginRecord do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @scopes ~w(document workspace)

  schema "plugin_records" do
    belongs_to :application, RefMD.Plugins.PluginApplication
    belongs_to :package, RefMD.Plugins.PluginPackage
    belongs_to :activation, RefMD.Plugins.PluginActivation
    belongs_to :workspace, RefMD.Workspaces.Workspace

    field :plugin_id, :string
    field :scope, :string
    field :scope_id, :string
    field :kind, :string
    field :encrypted_data, :binary
    field :nonce, :binary
    field :key_version, :integer

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(record, attrs) do
    record
    |> cast(attrs, [
      :id,
      :application_id,
      :package_id,
      :activation_id,
      :workspace_id,
      :plugin_id,
      :scope,
      :scope_id,
      :kind,
      :encrypted_data,
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
      :kind,
      :encrypted_data,
      :nonce,
      :key_version
    ])
    |> validate_inclusion(:scope, @scopes)
    |> validate_number(:key_version, greater_than: 0)
    |> validate_binary_present(:encrypted_data)
    |> validate_binary_present(:nonce)
    |> validate_non_empty(:plugin_id)
    |> validate_non_empty(:scope_id)
    |> validate_non_empty(:kind)
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
